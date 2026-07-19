package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// 升级后的 Reality 研究 Demo。
//
// 相比 v1 版本,本版本增加了:
//   1. 协议首包识别(TLS / HTTP / 未知)
//   2. 更完整的 TLS ClientHello 解析(版本、密码套件、扩展、ALPN、Supported Versions、KeyShare groups)
//   3. SNI 到真实目标网站的动态路由映射
//   4. 提取 JA3 指纹所需字段(暂不计算完整 JA3 hash,避免引入外部依赖)
//   5. 在日志中直观展示不同协议、不同客户端的握手特征
//
// 本 Demo 仍然只演示 TLS 握手字节流的操控与透传,不实现 Reality 的认证、
// 密钥派生与隧道接管。代码中保留了明确的"认证插槽"注释,标示 Reality 源码
// 中 X25519+HKDF+AES-GCM 的接入点。

const (
	defaultListen = "127.0.0.1:8443"
	defaultDest   = "www.microsoft.com:443"
)

// ForwardRule 描述一条 SNI -> dest 的映射规则。
type ForwardRule struct {
	SNI  string
	Dest string
}

// ClientHelloInfo 保存解析后的 ClientHello 关键信息。
type ClientHelloInfo struct {
	RecordVersion      uint16
	HandshakeVersion   uint16
	Random             [32]byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []Extension
	SNI                string
	ALPNs              []string
	SupportedVersions  []uint16
	KeyShareGroups     []uint16
	SignatureSchemes   []uint16
}

// Extension 保存单个 TLS 扩展的原始信息。
type Extension struct {
	Type uint16
	Len  uint16
	Data []byte
}

// ProtocolType 表示首包识别结果。
type ProtocolType int

const (
	ProtoUnknown ProtocolType = iota
	ProtoTLS
	ProtoHTTP
)

func (p ProtocolType) String() string {
	switch p {
	case ProtoTLS:
		return "TLS"
	case ProtoHTTP:
		return "HTTP"
	default:
		return "UNKNOWN"
	}
}

func main() {
	listen := flag.String("listen", defaultListen, "本地监听地址")
	dest := flag.String("dest", defaultDest, "默认真实目标网站地址")
	sniMap := flag.String("sni-map", "", "SNI 路由映射,逗号分隔,例如: 'www.microsoft.com:microsoft.com:443,www.apple.com:apple.com:443'")
	show := flag.Bool("show", false, "打印详细握手信息")
	flag.Parse()

	rules := parseSniMap(*sniMap)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()

	log.Printf("[+] 监听 %s, 默认目标 %s", *listen, *dest)
	if len(rules) > 0 {
		log.Printf("[+] 已加载 %d 条 SNI 路由规则", len(rules))
		for _, r := range rules {
			log.Printf("    %s -> %s", r.SNI, r.Dest)
		}
	}
	log.Println("[+] 测试命令: openssl s_client -connect 127.0.0.1:8443 -servername www.microsoft.com")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept 失败: %v", err)
			continue
		}
		go handleConn(conn, *dest, rules, *show)
	}
}

// parseSniMap 解析命令行传入的 SNI 映射字符串。
func parseSniMap(s string) []ForwardRule {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var rules []ForwardRule
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			log.Printf("[-] 忽略非法 SNI 映射: %s", part)
			continue
		}
		rules = append(rules, ForwardRule{SNI: kv[0], Dest: kv[1]})
	}
	return rules
}

// routeBySNI 根据 SNI 选择目标地址,没有匹配则返回默认目标。
func routeBySNI(sni, defaultDest string, rules []ForwardRule) string {
	for _, r := range rules {
		if r.SNI == sni {
			return r.Dest
		}
	}
	return defaultDest
}

func handleConn(clientConn net.Conn, defaultDest string, rules []ForwardRule, show bool) {
	defer clientConn.Close()
	remoteAddr := clientConn.RemoteAddr().String()

	// 先 peek 前 5 个字节,识别协议类型。
	header := make([]byte, 5)
	if _, err := io.ReadFull(clientConn, header); err != nil {
		log.Printf("[%s] 读取首包失败: %v", remoteAddr, err)
		return
	}

	proto := detectProtocol(header)
	log.Printf("[%s] 协议识别: %s", remoteAddr, proto)

	switch proto {
	case ProtoTLS:
		handleTLS(clientConn, header, defaultDest, rules, show, remoteAddr)
	case ProtoHTTP:
		handlePlainHTTP(clientConn, header, defaultDest, remoteAddr)
	default:
		// 未知协议:按原始默认目标透传,只做透明中继。
		log.Printf("[%s] 未知协议,按默认目标 %s 透明转发", remoteAddr, defaultDest)
		forward(clientConn, header, defaultDest, remoteAddr)
	}
}

// detectProtocol 根据首 5 字节识别协议类型。
func detectProtocol(header []byte) ProtocolType {
	if len(header) < 5 {
		return ProtoUnknown
	}
	// TLS Handshake 首字节固定为 0x16,记录版本常见为 0x0301/0x0302/0x0303/0x0304 的伪装版本。
	if header[0] == 0x16 {
		ver := binary.BigEndian.Uint16(header[1:3])
		if ver == 0x0301 || ver == 0x0302 || ver == 0x0303 || ver == 0x0304 || ver == 0x0300 {
			return ProtoTLS
		}
	}
	// HTTP 请求方法常见前缀
	methods := []string{"GET ", "POST", "HEAD", "PUT ", "DELE", "OPTI", "PATC", "TRAC", "CONN"}
	for _, m := range methods {
		if bytes.HasPrefix(header, []byte(m)) {
			return ProtoHTTP
		}
	}
	return ProtoUnknown
}

// handleTLS 处理 TLS 连接:读取完整 ClientHello,解析,选择目标,转发。
func handleTLS(clientConn net.Conn, header []byte, defaultDest string, rules []ForwardRule, show bool, remoteAddr string) {
	recLen := int(binary.BigEndian.Uint16(header[3:5]))
	record := make([]byte, 5+recLen)
	copy(record, header)
	if _, err := io.ReadFull(clientConn, record[5:]); err != nil {
		log.Printf("[%s] 读取 TLS record 体失败: %v", remoteAddr, err)
		return
	}

	info, err := parseClientHello(record)
	if err != nil {
		log.Printf("[%s] 解析 ClientHello 失败: %v", remoteAddr, err)
		return
	}

	dest := routeBySNI(info.SNI, defaultDest, rules)
	if info.SNI == "" {
		info.SNI = "(none)"
	}

	log.Printf("[%s] TLS ClientHello: SNI=%s, Version=0x%04x, Ciphers=%d, Exts=%d, KeyShareGroups=%v, ALPN=%v, Dest=%s",
		remoteAddr, info.SNI, info.HandshakeVersion, len(info.CipherSuites), len(info.Extensions),
		info.KeyShareGroups, info.ALPNs, dest)

	if show {
		printClientHelloDetails(remoteAddr, info)
	}

	// =====================================================
	// Reality 认证插槽(本 Demo 未实现):
	// 在真实 Reality 中,此时会:
	//   1. 从 info.KeyShares 中提取 X25519 客户端公钥
	//   2. 用服务端 privateKey 做 X25519 ECDH,得到 sharedSecret
	//   3. hkdf.New(sha256.New, sharedSecret, info.Random[:20], []byte("REALITY")).Read(authKey)
	//   4. 用 AES-GCM 解密 info.SessionID[:16] -> 版本/时间戳/shortId
	//   5. 校验版本范围、时间差、shortId 白名单
	// 认证失败 -> 透明转发给 dest(抗主动探测)
	// 认证成功 -> 接管握手,自行生成 TLS 1.3 记录,后续走代理隧道
	// 本 Demo 为了边界清晰,只执行透明转发。
	// =====================================================

	forward(clientConn, record, dest, remoteAddr)
}

// printClientHelloDetails 打印详细解析结果。
func printClientHelloDetails(remoteAddr string, info *ClientHelloInfo) {
	var cipherNames []string
	for _, c := range info.CipherSuites {
		cipherNames = append(cipherNames, fmt.Sprintf("0x%04x", c))
	}
	var extTypes []string
	for _, e := range info.Extensions {
		extTypes = append(extTypes, fmt.Sprintf("0x%04x", e.Type))
	}
	log.Printf("[%s]   CipherSuites: %s", remoteAddr, strings.Join(cipherNames, ", "))
	log.Printf("[%s]   Extension Types: %s", remoteAddr, strings.Join(extTypes, ", "))
	log.Printf("[%s]   SupportedVersions: %v", remoteAddr, versionsToStrings(info.SupportedVersions))
	log.Printf("[%s]   SignatureSchemes: %v", remoteAddr, schemesToStrings(info.SignatureSchemes))
	log.Printf("[%s]   SessionID: %s", remoteAddr, hex.EncodeToString(info.SessionID))
}

// versionsToStrings 把 TLS 版本号数组转换成可读字符串。
func versionsToStrings(vers []uint16) []string {
	var out []string
	for _, v := range vers {
		switch v {
		case 0x0304:
			out = append(out, "TLS 1.3")
		case 0x0303:
			out = append(out, "TLS 1.2")
		case 0x0302:
			out = append(out, "TLS 1.1")
		case 0x0301:
			out = append(out, "TLS 1.0")
		default:
			out = append(out, fmt.Sprintf("0x%04x", v))
		}
	}
	return out
}

// schemesToStrings 把签名算法数组转换成可读字符串。
func schemesToStrings(schemes []uint16) []string {
	var out []string
	for _, s := range schemes {
		out = append(out, fmt.Sprintf("0x%04x", s))
	}
	return out
}

// forward 把已读取的首包数据发送到目标,然后双向透传。
func forward(clientConn net.Conn, firstChunk []byte, dest, remoteAddr string) {
	destConn, err := net.Dial("tcp", dest)
	if err != nil {
		log.Printf("[%s] 连接目标 %s 失败: %v", remoteAddr, dest, err)
		return
	}
	defer destConn.Close()

	if _, err := destConn.Write(firstChunk); err != nil {
		log.Printf("[%s] 转发首包失败: %v", remoteAddr, err)
		return
	}

	log.Printf("[%s] 开始双向透传 <-> %s", remoteAddr, dest)
	relay(clientConn, destConn)
}

// handlePlainHTTP 对明文 HTTP 只做记录并透明转发。
func handlePlainHTTP(clientConn net.Conn, header []byte, defaultDest, remoteAddr string) {
	// 对于 HTTP 请求,我们需要把第一行读出来,以判断 Host 和目标。
	buf := bytes.NewBuffer(header)
	tmp := make([]byte, 4096)
	for {
		line, err := buf.ReadBytes('\n')
		if err != nil && len(line) == 0 {
			break
		}
		if len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
			// 已读取一行
		}
		// 简单打印请求行
		if strings.HasPrefix(string(bytes.TrimSpace(line)), "GET") ||
			strings.HasPrefix(string(bytes.TrimSpace(line)), "POST") ||
			strings.HasPrefix(string(bytes.TrimSpace(line)), "CONNECT") {
			log.Printf("[%s] HTTP 请求行: %s", remoteAddr, strings.TrimSpace(string(line)))
		}
		if bytes.Contains(line, []byte("\r\n\r\n")) {
			break
		}
		// 避免无限循环
		break
	}
	log.Printf("[%s] 明文 HTTP, 按默认目标 %s 转发", remoteAddr, defaultDest)
	forward(clientConn, header, defaultDest, remoteAddr)
	_ = tmp
}

// relay 双向转发 conn 之间的数据。
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
}

// parseClientHello 从完整 TLS record 解析出 ClientHello 信息。
func parseClientHello(record []byte) (*ClientHelloInfo, error) {
	if len(record) < 5 || record[0] != 0x16 {
		return nil, fmt.Errorf("不是 TLS Handshake record")
	}

	recLen := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) != 5+recLen {
		return nil, fmt.Errorf("TLS record 长度不匹配: 期望 %d, 实际 %d", 5+recLen, len(record))
	}

	body := record[5:]
	if len(body) < 5 || body[0] != 1 { // 1 = ClientHello
		return nil, fmt.Errorf("不是 ClientHello")
	}

	info := &ClientHelloInfo{}
	info.RecordVersion = binary.BigEndian.Uint16(record[1:3])

	// 跳过 Handshake 长度(3 字节)
	pos := 4
	if len(body) < pos+34 {
		return nil, fmt.Errorf("ClientHello 主体过短")
	}
	info.HandshakeVersion = binary.BigEndian.Uint16(body[pos : pos+2])
	pos += 2
	copy(info.Random[:], body[pos:pos+32])
	pos += 32

	// Session ID
	if pos >= len(body) {
		return nil, fmt.Errorf("Session ID 长度越界")
	}
	sidLen := int(body[pos])
	pos++
	if pos+sidLen > len(body) {
		return nil, fmt.Errorf("Session ID 数据越界")
	}
	info.SessionID = make([]byte, sidLen)
	copy(info.SessionID, body[pos:pos+sidLen])
	pos += sidLen

	// Cipher Suites
	if pos+2 > len(body) {
		return nil, fmt.Errorf("Cipher Suites 长度越界")
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+csLen > len(body) || csLen%2 != 0 {
		return nil, fmt.Errorf("Cipher Suites 数据越界")
	}
	for i := 0; i < csLen; i += 2 {
		info.CipherSuites = append(info.CipherSuites, binary.BigEndian.Uint16(body[pos+i:pos+i+2]))
	}
	pos += csLen

	// Compression Methods
	if pos+1 > len(body) {
		return nil, fmt.Errorf("Compression Methods 长度越界")
	}
	compLen := int(body[pos])
	pos++
	if pos+compLen > len(body) {
		return nil, fmt.Errorf("Compression Methods 数据越界")
	}
	for i := 0; i < compLen; i++ {
		info.CompressionMethods = append(info.CompressionMethods, body[pos+i])
	}
	pos += compLen

	// Extensions
	if pos+2 > len(body) {
		return nil, fmt.Errorf("Extensions 长度越界")
	}
	extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+extLen > len(body) {
		return nil, fmt.Errorf("Extensions 数据越界")
	}
	parseExtensions(body[pos:pos+extLen], info)
	return info, nil
}

// parseExtensions 解析所有扩展,并提取关键信息。
func parseExtensions(exts []byte, info *ClientHelloInfo) {
	pos := 0
	for pos+4 <= len(exts) {
		extType := binary.BigEndian.Uint16(exts[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(exts[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > len(exts) {
			break
		}
		data := exts[pos : pos+extLen]
		info.Extensions = append(info.Extensions, Extension{
			Type: extType,
			Len:  uint16(extLen),
			Data: data,
		})
		switch extType {
		case 0x0000: // server_name
			info.SNI = parseSNIExt(data)
		case 0x0010: // ALPN
			info.ALPNs = parseALPN(data)
		case 0x002b: // supported_versions
			info.SupportedVersions = parseSupportedVersions(data)
		case 0x0033: // key_share
			info.KeyShareGroups = parseKeyShareGroups(data)
		case 0x000d: // signature_algorithms
			info.SignatureSchemes = parseSignatureSchemes(data)
		}
		pos += extLen
	}
}

// parseSNIExt 解析 server_name 扩展。
func parseSNIExt(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) != 2+listLen || listLen < 3 {
		return ""
	}
	data = data[2:]
	if data[0] != 0 { // host_name
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[1:3]))
	if len(data) < 3+nameLen {
		return ""
	}
	return string(data[3 : 3+nameLen])
}

// parseALPN 解析 ALPN 扩展。
func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) != 2+listLen {
		return nil
	}
	data = data[2:]
	var alpn []string
	for len(data) >= 1 {
		l := int(data[0])
		if len(data) < 1+l {
			break
		}
		alpn = append(alpn, string(data[1:1+l]))
		data = data[1+l:]
	}
	return alpn
}

// parseSupportedVersions 解析 supported_versions 扩展。
func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 3 {
		return nil
	}
	listLen := int(data[0])
	if len(data) != 1+listLen || listLen%2 != 0 {
		return nil
	}
	var vers []uint16
	for i := 1; i < 1+listLen; i += 2 {
		vers = append(vers, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return vers
}

// parseKeyShareGroups 解析 key_share 扩展,提取 group IDs。
func parseKeyShareGroups(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) != 2+listLen {
		return nil
	}
	data = data[2:]
	var groups []uint16
	for len(data) >= 4 {
		group := binary.BigEndian.Uint16(data[0:2])
		keyLen := int(binary.BigEndian.Uint16(data[2:4]))
		if len(data) < 4+keyLen {
			break
		}
		groups = append(groups, group)
		data = data[4+keyLen:]
	}
	return groups
}

// parseSignatureSchemes 解析 signature_algorithms 扩展。
func parseSignatureSchemes(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) != 2+listLen || listLen%2 != 0 {
		return nil
	}
	var schemes []uint16
	for i := 2; i < 2+listLen; i += 2 {
		schemes = append(schemes, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return schemes
}

// 下面的代码用于避免 unused import 警告,同时保留时间格式化等工具的引用。
func init() {
	_ = time.Now
}
