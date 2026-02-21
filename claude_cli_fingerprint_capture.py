#!/usr/bin/env python3
"""
claude_cli_fingerprint_capture.py

自动捕获 Claude CLI (Node.js) 的真实 TLS ClientHello 指纹，
并输出 sub2api 配置文件可直接使用的 YAML Profile。

用法:
# 1. 安装依赖
pip install pyyaml

# 2. 自动探测系统所有 node 版本并逐一抓取
python3 claude_cli_fingerprint_capture.py

# 3. 列出系统中找到的 node 版本（不抓取）
python3 claude_cli_fingerprint_capture.py --list-node

# 4. 指定多个特定版本
python3 claude_cli_fingerprint_capture.py \
  --node ~/.nvm/versions/node/v18.20.4/bin/node \
  --node ~/.nvm/versions/node/v20.18.0/bin/node \
  --node ~/.nvm/versions/node/v22.17.1/bin/node

# 5. 输出到文件
python3 claude_cli_fingerprint_capture.py --output tls_profiles.yaml
依赖:
  pip install pyyaml
"""

import argparse
import hashlib
import json
import platform
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import os
import time
from pathlib import Path

try:
    import ssl
    import yaml
except ImportError:
    print("缺少依赖，请先运行: pip install pyyaml")
    sys.exit(1)


# ──────────────────────────────────────────────
# TLS ClientHello 解析
# ──────────────────────────────────────────────

def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("连接已关闭")
        buf += chunk
    return buf


def parse_client_hello(data: bytes) -> dict:
    """
    解析 TLS ClientHello 报文，提取所有指纹相关字段。
    返回字典包含: cipher_suites, curves, point_formats, extensions, sig_algs,
                  supported_versions, alpn, key_share_groups
    """
    pos = 0

    # TLS Record Layer
    if len(data) < 5:
        raise ValueError("数据太短")
    content_type = data[pos]; pos += 1
    tls_version = struct.unpack_from(">H", data, pos)[0]; pos += 2
    record_length = struct.unpack_from(">H", data, pos)[0]; pos += 2

    if content_type != 0x16:  # Handshake
        raise ValueError(f"非握手记录: {content_type:#x}")

    # Handshake Header
    handshake_type = data[pos]; pos += 1
    if handshake_type != 0x01:  # ClientHello
        raise ValueError(f"非 ClientHello: {handshake_type:#x}")

    hs_length = struct.unpack_from(">I", b"\x00" + data[pos:pos+3])[0]; pos += 3

    # ClientHello Body
    client_version = struct.unpack_from(">H", data, pos)[0]; pos += 2
    client_random = data[pos:pos+32]; pos += 32

    # Session ID
    session_id_len = data[pos]; pos += 1
    pos += session_id_len

    # Cipher Suites
    cs_len = struct.unpack_from(">H", data, pos)[0]; pos += 2
    cipher_suites = []
    for i in range(cs_len // 2):
        cs = struct.unpack_from(">H", data, pos)[0]; pos += 2
        if cs != 0x00ff:  # 排除 SCSV（TLS_EMPTY_RENEGOTIATION_INFO_SCSV）—— 保留，sub2api 需要
            cipher_suites.append(cs)
        else:
            cipher_suites.append(cs)

    # Compression Methods
    comp_len = data[pos]; pos += 1
    compression_methods = list(data[pos:pos+comp_len]); pos += comp_len

    # Extensions
    if pos + 2 > len(data):
        return {
            "cipher_suites": cipher_suites,
            "curves": [],
            "point_formats": [],
            "extensions_order": [],
            "sig_algs": [],
            "supported_versions": [],
            "alpn": [],
            "key_share_groups": [],
            "enable_grease": False,
        }

    ext_total_len = struct.unpack_from(">H", data, pos)[0]; pos += 2
    ext_end = pos + ext_total_len

    extensions_order = []
    curves = []
    point_formats = []
    sig_algs = []
    supported_versions = []
    alpn = []
    key_share_groups = []
    has_grease = False

    while pos < ext_end:
        ext_type = struct.unpack_from(">H", data, pos)[0]; pos += 2
        ext_len  = struct.unpack_from(">H", data, pos)[0]; pos += 2
        ext_data = data[pos:pos+ext_len]; pos += ext_len

        # GREASE 检测（0x?a?a 格式）
        if (ext_type & 0x0f0f) == 0x0a0a and (ext_type >> 8) == (ext_type & 0xff):
            has_grease = True
            extensions_order.append(f"GREASE({ext_type:#06x})")
            continue

        extensions_order.append(ext_type)

        # 0x000a: supported_groups (curves)
        if ext_type == 0x000a:
            list_len = struct.unpack_from(">H", ext_data, 0)[0]
            for i in range(list_len // 2):
                curves.append(struct.unpack_from(">H", ext_data, 2 + i*2)[0])

        # 0x000b: ec_point_formats
        elif ext_type == 0x000b:
            fmt_len = ext_data[0]
            point_formats = list(ext_data[1:1+fmt_len])

        # 0x000d: signature_algorithms
        elif ext_type == 0x000d:
            sa_len = struct.unpack_from(">H", ext_data, 0)[0]
            for i in range(sa_len // 2):
                sig_algs.append(struct.unpack_from(">H", ext_data, 2 + i*2)[0])

        # 0x0010: ALPN
        elif ext_type == 0x0010:
            proto_list_len = struct.unpack_from(">H", ext_data, 0)[0]
            ep = 2
            while ep < 2 + proto_list_len:
                plen = ext_data[ep]; ep += 1
                alpn.append(ext_data[ep:ep+plen].decode()); ep += plen

        # 0x002b: supported_versions
        elif ext_type == 0x002b:
            ver_len = ext_data[0]
            for i in range(ver_len // 2):
                supported_versions.append(struct.unpack_from(">H", ext_data, 1 + i*2)[0])

        # 0x0033: key_share
        elif ext_type == 0x0033:
            ks_list_len = struct.unpack_from(">H", ext_data, 0)[0]
            kp = 2
            while kp < 2 + ks_list_len:
                group = struct.unpack_from(">H", ext_data, kp)[0]; kp += 2
                key_len = struct.unpack_from(">H", ext_data, kp)[0]; kp += 2 + key_len
                key_share_groups.append(group)

    return {
        "cipher_suites":      cipher_suites,
        "curves":             curves,
        "point_formats":      point_formats,
        "extensions_order":   extensions_order,
        "sig_algs":           sig_algs,
        "supported_versions": supported_versions,
        "alpn":               alpn,
        "key_share_groups":   key_share_groups,
        "enable_grease":      has_grease,
    }


# ──────────────────────────────────────────────
# JA3 计算
# ──────────────────────────────────────────────

GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa
}

def compute_ja3(parsed: dict, sni: str = "example.com") -> str:
    """根据解析结果计算 JA3 hash（和 tls.peet.ws 一致）"""
    # TLS version: 从 supported_versions 取最高版本，否则用 client_version
    vers = [v for v in parsed.get("supported_versions", []) if v not in GREASE_VALUES]
    tls_ver = max(vers) if vers else 0x0303

    cs = [c for c in parsed["cipher_suites"] if c not in GREASE_VALUES and c != 0x00ff]
    cs_str = "-".join(str(c) for c in cs)

    ext_ids = [e for e in parsed["extensions_order"] if isinstance(e, int) and e not in GREASE_VALUES]
    ext_str = "-".join(str(e) for e in ext_ids)

    cur = [c for c in parsed["curves"] if c not in GREASE_VALUES]
    cur_str = "-".join(str(c) for c in cur)

    pf_str = "-".join(str(p) for p in parsed["point_formats"])

    ja3_str = f"{tls_ver},{cs_str},{ext_str},{cur_str},{pf_str}"
    return hashlib.md5(ja3_str.encode()).hexdigest(), ja3_str


# ──────────────────────────────────────────────
# 探针服务器：监听 TCP，读取原始 ClientHello
# ──────────────────────────────────────────────

class ProbeServer:
    def __init__(self, host="127.0.0.1", port=18443):
        self.host = host
        self.port = port
        self.result = None
        self.event = threading.Event()
        self._server = None

    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(1)
        self._server.settimeout(15)
        t = threading.Thread(target=self._accept, daemon=True)
        t.start()

    def _accept(self):
        try:
            conn, addr = self._server.accept()
            conn.settimeout(5)
            # 读取足够多的字节（ClientHello 通常 < 2048 字节）
            data = b""
            try:
                while len(data) < 4096:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    # TLS record: 前5字节包含 record length
                    if len(data) >= 5:
                        rec_len = struct.unpack_from(">H", data, 3)[0]
                        if len(data) >= 5 + rec_len:
                            break
            except socket.timeout:
                pass
            conn.close()
            self.result = data
        except socket.timeout:
            pass
        finally:
            self._server.close()
            self.event.set()

    def wait(self, timeout=15):
        self.event.wait(timeout)
        return self.result


# ──────────────────────────────────────────────
# Node.js 驱动：让 Node.js 发起 HTTPS 请求到探针
# ──────────────────────────────────────────────

NODE_SCRIPT = """
const https = require('https');
const tls   = require('tls');

// 忽略自签证书（我们只需要 ClientHello，不需要完成握手）
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const req = https.request({
  host: '127.0.0.1',
  port: parseInt(process.argv[2] || '18443'),
  path: '/',
  method: 'GET',
  rejectUnauthorized: false,
}, (res) => {
  res.resume();
});

req.on('error', () => { /* 探针不完成握手，忽略错误 */ });
req.end();
"""


def get_node_version(node_bin: str) -> str:
    try:
        out = subprocess.check_output([node_bin, "--version"],
                                       stderr=subprocess.DEVNULL, timeout=5)
        return out.decode().strip()
    except Exception:
        return "unknown"


def find_all_node_bins() -> list:
    """尝试找到系统中常见位置的所有 node 二进制"""
    candidates = []
    # PATH 中的 node
    default = shutil.which("node")
    if default:
        candidates.append(default)

    # nvm / fnm / volta 等版本管理器常见路径
    home = Path.home()
    search_dirs = [
        home / ".nvm" / "versions" / "node",
        home / ".fnm" / "node-versions",
        home / ".volta" / "tools" / "image" / "node",
        Path("/usr/local/bin"),
        Path("/opt/homebrew/bin"),
    ]
    for d in search_dirs:
        if d.is_dir():
            for p in sorted(d.rglob("node")):
                if p.is_file() and os.access(p, os.X_OK):
                    resolved = str(p.resolve())
                    if resolved not in candidates:
                        candidates.append(resolved)

    return candidates


# ──────────────────────────────────────────────
# 输出 YAML Profile
# ──────────────────────────────────────────────

KNOWN_CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
}
KNOWN_CURVE_NAMES = {
    29: "X25519", 23: "P-256", 24: "P-384", 25: "P-521",
    30: "x448",
    256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096",
    259: "ffdhe6144", 260: "ffdhe8192",
}
KNOWN_EXT_NAMES = {
    0: "server_name", 10: "supported_groups", 11: "ec_point_formats",
    13: "signature_algorithms", 16: "alpn", 22: "encrypt_then_mac",
    23: "extended_master_secret", 35: "session_ticket",
    43: "supported_versions", 45: "psk_key_exchange_modes", 51: "key_share",
}


def format_cipher(c):
    name = KNOWN_CIPHER_NAMES.get(c, "")
    return f"{c}  # {name}" if name else str(c)

def format_curve(c):
    name = KNOWN_CURVE_NAMES.get(c, "")
    return f"{c}  # {name}" if name else str(c)

def format_ext(e):
    if isinstance(e, str):
        return e
    name = KNOWN_EXT_NAMES.get(e, "")
    return f"{e} ({name})" if name else str(e)


def build_profile_key(node_bin: str, node_ver: str) -> str:
    os_name = platform.system().lower()
    arch = platform.machine().lower().replace("x86_64", "x64").replace("aarch64", "arm64")
    ver_clean = node_ver.lstrip("v").replace(".", "_")
    return f"{os_name}_{arch}_node_v{ver_clean}"


def capture_fingerprint(node_bin: str, port: int = 18443) -> dict | None:
    """启动探针 → 触发 Node.js 连接 → 解析 ClientHello"""
    server = ProbeServer(port=port)
    server.start()
    time.sleep(0.1)  # 等待 server 就绪

    # 用临时 js 文件触发 Node.js 连接
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write(NODE_SCRIPT)
        js_path = f.name

    try:
        subprocess.Popen(
            [node_bin, js_path, str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        print(f"  ✗ 启动 Node.js 失败: {e}")
        return None
    finally:
        # 稍后清理
        threading.Timer(3, lambda: os.unlink(js_path)).start()

    raw = server.wait(timeout=10)
    if not raw:
        print("  ✗ 未收到 ClientHello（超时）")
        return None

    try:
        parsed = parse_client_hello(raw)
    except Exception as e:
        print(f"  ✗ 解析 ClientHello 失败: {e}")
        return None

    return parsed


def print_profile_yaml(profile_key: str, node_ver: str, parsed: dict):
    ja3_hash, ja3_str = compute_ja3(parsed)
    os_name  = platform.system()
    arch     = platform.machine()

    print(f"\n{'='*60}")
    print(f"  Profile: {profile_key}")
    print(f"  Node.js: {node_ver}  OS: {os_name}/{arch}")
    print(f"  JA3 Hash: {ja3_hash}")
    print(f"  JA3 String: {ja3_str[:80]}...")
    print(f"  Extensions order: {[format_ext(e) for e in parsed['extensions_order']]}")
    print(f"  ALPN: {parsed['alpn']}")
    print(f"  GREASE: {parsed['enable_grease']}")
    print(f"{'='*60}")

    # 生成 sub2api YAML 片段
    cs_inline = "[" + ", ".join(str(c) for c in parsed["cipher_suites"]) + "]"
    curves_inline = "[" + ", ".join(str(c) for c in parsed["curves"]) + "]"
    pf_inline = "[" + ", ".join(str(p) for p in parsed["point_formats"]) + "]"

    yaml_block = f"""
      # {os_name} {arch} Node.js {node_ver}
      # JA3 Hash: {ja3_hash}
      {profile_key}:
        name: "{os_name} {arch} Node.js {node_ver}"
        enable_grease: {str(parsed['enable_grease']).lower()}
        cipher_suites: {cs_inline}
        curves: {curves_inline}
        point_formats: {pf_inline}
"""
    print(yaml_block)
    return yaml_block


# ──────────────────────────────────────────────
# 主程序
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="自动抓取 Claude CLI TLS 指纹")
    parser.add_argument("--node", help="指定 node 二进制路径（可多次指定）", action="append")
    parser.add_argument("--port", type=int, default=18443, help="探针监听端口（默认 18443）")
    parser.add_argument("--list-node", action="store_true", help="列出系统中找到的所有 node 版本")
    parser.add_argument("--output", help="输出 YAML 文件路径（追加模式）")
    args = parser.parse_args()

    if args.list_node:
        bins = find_all_node_bins()
        if not bins:
            print("未找到任何 node 可执行文件")
        else:
            print(f"找到 {len(bins)} 个 node：")
            for b in bins:
                print(f"  {b}  ({get_node_version(b)})")
        return

    # 确定要抓取的 node 列表
    node_bins = args.node if args.node else []
    if not node_bins:
        node_bins = find_all_node_bins()
        if not node_bins:
            print("✗ 未找到 node，请用 --node 指定路径")
            sys.exit(1)
        print(f"自动检测到 {len(node_bins)} 个 node 版本，将逐一抓取...\n")

    all_yaml = []
    port = args.port

    for node_bin in node_bins:
        node_ver = get_node_version(node_bin)
        profile_key = build_profile_key(node_bin, node_ver)
        print(f"→ 正在抓取: {node_bin} ({node_ver})")

        parsed = capture_fingerprint(node_bin, port=port)
        port += 1  # 每次用不同端口避免 TIME_WAIT

        if parsed:
            yaml_snippet = print_profile_yaml(profile_key, node_ver, parsed)
            all_yaml.append(yaml_snippet)
        else:
            print(f"  跳过 {node_ver}")

    # 汇总输出完整 YAML 配置块
    full_yaml = "\ngateway:\n  tls_fingerprint:\n    enabled: true\n    profiles:\n"
    for snippet in all_yaml:
        full_yaml += snippet

    print("\n\n" + "="*60)
    print("# 完整 sub2api 配置片段（复制到 config.yaml）:")
    print("="*60)
    print(full_yaml)

    if args.output:
        with open(args.output, "w") as f:
            f.write(full_yaml)
        print(f"\n✓ 已写入: {args.output}")


if __name__ == "__main__":
    main()