package main

import (
	"bytes"
	"encoding/binary"
)

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
