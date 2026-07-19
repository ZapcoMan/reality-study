package main

import (
	"encoding/binary"
	"fmt"
)

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
