<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/Node.js-Fingerprint-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js"/>
  <img src="https://img.shields.io/badge/TLS-ClientHello-FF6F00?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="TLS"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"/>
</p>

<h1 align="center">🔐 Claude CLI TLS Fingerprint Capture</h1>

<p align="center">
  <b>自动捕获 Claude CLI (Node.js) 的真实 TLS ClientHello 指纹，生成 sub2api 可直接使用的 YAML 配置。</b>
</p>

<p align="center">
  <i>Automatically capture the real TLS ClientHello fingerprint of Claude CLI (Node.js) and generate YAML profiles ready for sub2api.</i>
</p>

---

## ✨ 功能特性

- 🔍 **自动探测** — 扫描系统中所有 Node.js 版本（支持 nvm / fnm / volta）
- 📡 **本地探针** — 零外部依赖，通过本地 TCP 探针捕获真实 ClientHello
- 🧬 **JA3 指纹** — 自动计算 JA3 Hash，便于指纹比对与验证
- 📦 **YAML 输出** — 直接生成 sub2api `config.yaml` 可用的 TLS Profile
- 🖥️ **跨平台** — 支持 macOS / Linux，自动识别 CPU 架构

## 🏗️ 工作原理

```
┌─────────────────┐       HTTPS        ┌──────────────────┐
│  Node.js Client │  ───────────────►  │  Local TCP Probe  │
│  (各版本)        │   ClientHello      │  (127.0.0.1:18443)│
└─────────────────┘                    └────────┬─────────┘
                                                │
                                         解析 TLS Record
                                                │
                                    ┌───────────▼──────────┐
                                    │   Cipher Suites      │
                                    │   Curves / Groups    │
                                    │   Extensions Order   │
                                    │   ALPN / GREASE      │
                                    │   JA3 Hash           │
                                    └───────────┬──────────┘
                                                │
                                         输出 YAML Profile
                                                ▼
                                    ┌──────────────────────┐
                                    │   sub2api config     │
                                    │   tls_profiles.yaml  │
                                    └──────────────────────┘
```

## 🚀 快速开始

### 1. 安装依赖

```bash
pip install pyyaml
```

### 2. 自动探测并抓取所有 Node.js 版本

```bash
python3 claude_cli_fingerprint_capture.py
```

### 3. 查看系统中所有可用的 Node.js 版本

```bash
python3 claude_cli_fingerprint_capture.py --list-node
```

### 4. 指定特定 Node.js 版本

```bash
python3 claude_cli_fingerprint_capture.py \
  --node ~/.nvm/versions/node/v18.20.4/bin/node \
  --node ~/.nvm/versions/node/v20.18.0/bin/node \
  --node ~/.nvm/versions/node/v22.17.1/bin/node
```

### 5. 输出到文件

```bash
python3 claude_cli_fingerprint_capture.py --output tls_profiles.yaml
```

## ⚙️ 命令行参数

| 参数 | 说明 | 默认值 |
|:---|:---|:---|
| `--node PATH` | 指定 node 二进制路径（可多次使用） | 自动探测 |
| `--port PORT` | 探针监听端口 | `18443` |
| `--list-node` | 列出系统中所有 node 版本（不抓取） | — |
| `--output FILE` | 输出 YAML 文件路径 | 标准输出 |

## 📄 输出示例

运行后会生成类似如下的 YAML 配置：

```yaml
gateway:
  tls_fingerprint:
    enabled: true
    profiles:
      # Darwin arm64 Node.js v22.21.1
      # JA3 Hash: 09018f013f117d7a5165647c16e56db3
      darwin_arm64_node_v22_21_1:
        name: "Darwin arm64 Node.js v22.21.1"
        enable_grease: false
        cipher_suites: [4866, 4867, 4865, 49199, ...]
        curves: [4588, 29, 23, 30, 24, 25, 256, 257]
        point_formats: [0, 1, 2]
```

## 🧰 项目结构

```
.
├── claude_cli_fingerprint_capture.py   # 主程序：探针 + 解析 + 输出
├── tls_profiles.yaml                   # 已捕获的 TLS 指纹配置
└── README.md
```

## 🔑 关键概念

| 术语 | 说明 |
|:---|:---|
| **ClientHello** | TLS 握手的第一个消息，包含客户端支持的密码套件、扩展等信息 |
| **JA3** | 基于 ClientHello 字段计算的 MD5 指纹，用于识别 TLS 客户端 |
| **GREASE** | Generate Random Extensions And Sustain Extensibility，防止中间设备僵化的机制 |
| **sub2api** | Claude API 代理网关，使用 TLS 指纹模拟真实客户端行为 |
| **Cipher Suites** | 客户端支持的加密算法组合列表 |
| **ALPN** | 应用层协议协商，如 `h2`、`http/1.1` |

## 📋 系统要求

- **Python** 3.8+
- **PyYAML** (`pip install pyyaml`)
- **Node.js** — 至少一个版本（通过 nvm / fnm / volta 或系统安装均可）

## 📝 License

MIT License — 自由使用，风险自担。
