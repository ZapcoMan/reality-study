package main

import (
	"log"
	"strings"
)

// ForwardRule 描述一条 SNI -> dest 的映射规则。
type ForwardRule struct {
	SNI  string
	Dest string
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
