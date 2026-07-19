package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
)

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
