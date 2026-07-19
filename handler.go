package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
)

// handleConn 根据首包协议类型分发处理。
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
		forwardRaw(clientConn, header, defaultDest)
	}
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

	forwardTLS(clientConn, record, dest, remoteAddr)
}

// handlePlainHTTP 对明文 HTTP 只做记录并透明转发。
func handlePlainHTTP(clientConn net.Conn, header []byte, defaultDest, remoteAddr string) {
	// 对于 HTTP 请求,我们需要把第一行读出来,以判断 Host 和目标。
	buf := bytes.NewBuffer(header)
	for {
		line, err := buf.ReadBytes('\n')
		if err != nil && len(line) == 0 {
			break
		}
		// 简单打印请求行
		trimmed := strings.TrimSpace(string(line))
		if strings.HasPrefix(trimmed, "GET") ||
			strings.HasPrefix(trimmed, "POST") ||
			strings.HasPrefix(trimmed, "CONNECT") {
			log.Printf("[%s] HTTP 请求行: %s", remoteAddr, trimmed)
		}
		if bytes.Contains(line, []byte("\r\n\r\n")) {
			break
		}
		// 避免无限循环
		break
	}
	log.Printf("[%s] 明文 HTTP, 按默认目标 %s 转发", remoteAddr, defaultDest)
	forwardRaw(clientConn, header, defaultDest)
}
