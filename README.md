# Reality 研究 Demo

TLS 握手操控与透明代理研究项目，用于学习 Reality 协议的核心机制。

## 功能特性

- **协议识别** — 通过首包 5 字节自动识别 TLS / HTTP / 未知协议
- **ClientHello 解析** — 完整解析 TLS 握手关键字段：
  - 协议版本、Cipher Suites、Session ID
  - SNI（Server Name Indication）
  - ALPN（Application-Layer Protocol Negotiation）
  - Supported Versions（TLS 1.0 ~ 1.3）
  - KeyShare Groups（X25519 等）
  - Signature Algorithms
- **SNI 动态路由** — 根据 SNI 字段将连接路由到不同的真实目标
- **JA3 指纹字段提取** — 已具备计算 JA3 指纹所需的全部字段（暂未计算完整 hash）
- **透明转发** — 双向 `io.Copy` 代理，保留 Reality 认证插槽

## 快速开始

### 构建

```bash
go build -o reality-study.exe
```

### 运行

```bash
# 基本运行（默认目标 www.microsoft.com:443）
.\reality-study.exe

# 指定监听地址和目标
.\reality-study.exe -listen 127.0.0.1:8443 -dest www.microsoft.com:443

# 配置 SNI 路由映射
.\reality-study.exe -sni-map "www.microsoft.com:microsoft.com:443,www.apple.com:apple.com:443"

# 显示详细的 ClientHello 信息
.\reality-study.exe -show

# 组合使用
.\reality-study.exe -listen 127.0.0.1:8443 -sni-map "www.microsoft.com:microsoft.com:443" -show
```

### OpenSSL（如已安装）

```bash
openssl s_client -connect 127.0.0.1:8443 -servername www.microsoft.com
```

#### curl（通用）

```bash
curl -k https://127.0.0.1:8443 -H "Host: www.microsoft.com"
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-listen` | `127.0.0.1:8443` | 本地监听地址 |
| `-dest` | `www.microsoft.com:443` | 默认真实目标网站地址 |
| `-sni-map` | 空 | SNI 路由映射，格式：`sni1:dest1,sni2:dest2` |
| `-show` | `false` | 打印详细的 ClientHello 解析信息 |

## 架构说明

### 协议识别流程

```
客户端连接
    │
    ▼
读取首 5 字节
    │
    ├── 0x16 + 0x030x → TLS → handleTLS()
    ├── GET/POST/...  → HTTP → handlePlainHTTP()
    └── 其他           → 未知 → forwardRaw()
```

### TLS 处理流程

```
handleTLS()
    │
    ├── 读取完整 TLS Record
    ├── parseClientHello() 解析握手信息
    ├── routeBySNI() 根据 SNI 选择目标
    │
    ├── [Reality 认证插槽 - 未实现]
    │   ├── X25519 ECDH → sharedSecret
    │   ├── HKDF 派生 authKey
    │   ├── AES-GCM 解密 SessionID
    │   └── 验证版本/时间戳/shortId
    │
    └── forwardTLS() → 双向透明转发
```

### Reality 认证插槽

代码中 `handleTLS` 函数内保留了完整的 Reality 认证接入点注释。在真实 Reality 实现中：

1. **认证失败** → 透明转发给目标（抗主动探测）
2. **认证成功** → 接管握手，自行生成 TLS 记录，后续走代理隧道

本 Demo 仅实现透明转发，用于研究 TLS 握手字节流的操控机制。

## 项目结构

```
reality-study/
├── main.go          # 主程序入口，包含所有逻辑
├── go.mod           # Go 模块定义
└── README.md        # 本说明文件
```

## 依赖

本项目仅使用 Go 标准库，无第三方依赖：

- `net` — TCP 连接监听与转发
- `encoding/binary` — TLS 字节流解析
- `bytes` — 缓冲区操作
- `encoding/hex` — SessionID 十六进制输出
- `log` / `flag` / `fmt` / `io` / `strings` / `time` — 工具库

## 安全声明

本项目仅用于 **TLS 协议学习与研究**，不包含完整的 Reality 认证实现。代码中明确标注了认证插槽位置，供进一步开发参考。

## License

本项目为学习用途，仅供技术研究。
