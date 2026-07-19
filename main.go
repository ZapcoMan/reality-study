package main

import (
	"flag"
	"log"
	"net"
)

// 升级后的 Reality 研究 Demo(v2)。
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
