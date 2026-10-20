#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
L1J ServerData 纯 Python 编解码器（Encode v3.63）
=================================================

完全脱离厂商 Encode.exe：编码与解码都在本文件内完成，输出与官方逐字节一致。

算法全貌
--------
    明文 p = <CRC8>*<版本>*<IP>*<PORT> + tail
    置换 q = swap(p)                                 # 互换 buf[i] 与 buf[half+i]
    密文 c[0] = q[0] ^ ks[0]
         c[i] = q[i] ^ ks[i] ^ c[i-1]                 (i >= 1)
    ServerData = Base64(c)

    * CRC8 : CRC-32（反射多项式 0xEDB88320，init 0xF0958FF3，xorout 0xFFFFFFFF）
             作用范围 = 版本号之后到结尾的整段明文（含功能位），小写十六进制 8 位
    * 版本  : 目前恒为 "36300"
    * ks   : 只与明文长度 n 有关的固定密钥流（26 个长度已标定，见 ks_table.json）
    * n    = 52 + len(IP) + len(str(PORT))；开启 bit0「封包加密」时再 +18

功能位（flags）位置
------------------
    把明文按 '*' 切开后，明文第 k 段对应功能位：
        bit1 -> 段 7      bit2 -> 段 8      bit3 -> 段 12
        bit4 -> 段 13     bit5 -> 段 14     bit6 -> 段 15     bit7 -> 段 16
    置位时该段由 "0" 变 "1"。bit0 不占段位，而是把 tail 换成包含
    "*1*<常量>*<常量>" 的长格式（长度 +18）。

用法
----
    python l1j_serverdata.py --decode "QkgoCwqg..."
    python l1j_serverdata.py --encode --ip 203.0.113.24 --port 2000 --flags 80
    python l1j_serverdata.py --decode-file servers.ini
    python l1j_serverdata.py --selftest
    python l1j_serverdata.py --ini out.ini --zone "一区,203.0.113.24,2000,80" \
                                          --zone "二区,203.0.113.24,2001,80"

注意
----
    bit3（變身檔）在官方工具里还需要额外的变档文件，本工具只能写出标志位；
    bit0（封包加密）会改变 ServerData 长度，客户端需具备对应能力。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys

__version__ = "3.0.0"

POLY = 0xEDB88320
CRC_INIT = 0xF0958FF3
CRC_XOUT = 0xFFFFFFFF

VERSION_FIELD = "36300"

# 不带 bit0 的尾部
TAIL_PLAIN = "*0" * 8 + "*00000000" + "*0" * 5 + "*"
# 带 bit0（封包加密）的尾部：中间两个十进制常量由官方工具写死
TAIL_SEALED = "*0*1*2671664405*2671664405*0*0*0*0*00000000" + "*0" * 5 + "*"

# flags 位 -> 明文按 '*' 切分后的段下标
FLAG_SLOTS = {1: 7, 2: 8, 3: 12, 4: 13, 5: 14, 6: 15, 7: 16}

FLAG_NAMES = {
    0: "封包加密",
    1: "防外掛",
    2: "進階防外掛",
    3: "變身檔",
    4: "內建喝水",
    5: "移動封包不加密",
    6: "允許多開",
    7: "驗證地圖檔",
}

_TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ks_table.json")


# --------------------------------------------------------------------------- #
# CRC-32
# --------------------------------------------------------------------------- #
def _make_crc_table():
    tab = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (POLY if c & 1 else 0)
        tab.append(c & 0xFFFFFFFF)
    return tab


_CRC_TAB = _make_crc_table()


def crc32_raw(data: bytes, init: int = CRC_INIT) -> int:
    """反射 CRC-32，使用本格式专属的初值"""
    c = init
    for b in data:
        c = _CRC_TAB[(c ^ b) & 0xFF] ^ (c >> 8)
    return (c ^ CRC_XOUT) & 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# 置换
# --------------------------------------------------------------------------- #
def swap(buf: bytes) -> bytes:
    """互换 buf[i] 与 buf[half+i]（i 取 0,2,4,...；half = n//2）。自逆。"""
    b = bytearray(buf)
    n = len(b)
    half = n // 2
    for i in range(0, half, 2):
        b[i], b[half + i] = b[half + i], b[i]
    return bytes(b)


# --------------------------------------------------------------------------- #
# 明文构造 / 解析
# --------------------------------------------------------------------------- #
def _segments(tail: str):
    """把 tail 切成分段列表（丢弃首尾空串）"""
    return [x for x in tail.split("*")[1:]]


def build_plain(ip: str, port: int, flags: int = 0, version: str = VERSION_FIELD) -> bytes:
    """按输入生成完整明文（含 CRC 头）"""
    segs = [version, ip, str(port)] + _segments(TAIL_SEALED if flags & 1 else TAIL_PLAIN)
    for bit, idx in FLAG_SLOTS.items():
        if (flags >> bit) & 1:
            if idx >= len(segs):
                raise ValueError("当前布局不支持功能位 bit%d" % bit)
            segs[idx] = "1"
    body = ("*" + "*".join(segs)).encode("latin1")
    return ("%08x" % crc32_raw(body)).encode() + body


def parse_plain(p: bytes) -> dict:
    s = p.decode("latin1")
    if len(s) < 26 or s[8] != "*":
        raise ValueError("明文结构不符")
    segs = s[9:].split("*")
    if len(segs) < 17:
        raise ValueError("明文尾部结构不符")
    flags = 0
    for bit, idx in FLAG_SLOTS.items():
        if idx < len(segs) and segs[idx] == "1":
            flags |= 1 << bit
    return {
        "checksum": s[0:8],
        "version": segs[0],
        "ip": segs[1],
        "port": int(segs[2]),
        "flags": flags,
        "sealed": (len(segs) >= 7 and segs[3] == "0" and segs[4] == "1"
                   and segs[5].isdigit() and len(segs[5]) >= 8),
        "plaintext": s,
    }


# --------------------------------------------------------------------------- #
# 密钥流表
# --------------------------------------------------------------------------- #
class KeyStream:
    def __init__(self, table: dict):
        self.table = {int(k): bytes.fromhex(v) for k, v in table.items()}

    @classmethod
    def load(cls, path: str = _TABLE_PATH) -> "KeyStream":
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f))

    def get(self, n: int):
        return self.table.get(n)

    def lengths(self):
        return sorted(self.table)


# --------------------------------------------------------------------------- #
# 编解码
# --------------------------------------------------------------------------- #
class Codec:
    def __init__(self, ks: KeyStream):
        self.ks = ks

    # -- 编码 ---------------------------------------------------------------
    def encode_bytes(self, ip: str, port: int, flags: int = 0) -> bytes:
        p = build_plain(ip, port, flags)
        n = len(p)
        k = self.ks.get(n)
        if k is None:
            raise ValueError("长度 %d 没有密钥流（已标定 %s）" % (n, self.ks.lengths()))
        return self._crypt(p, k)

    def encode(self, ip: str, port: int, flags: int = 0) -> str:
        return base64.b64encode(self.encode_bytes(ip, port, flags)).decode("ascii")

    # -- 解码 ---------------------------------------------------------------
    def _decode_with(self, c: bytes, k: bytes) -> dict:
        n = len(c)
        q = bytearray(n)
        q[0] = c[0] ^ k[0]
        for i in range(1, n):
            q[i] = c[i] ^ c[i - 1] ^ k[i]
        p = swap(bytes(q))
        info = parse_plain(p)
        info["length"] = n
        info["crc_ok"] = info["checksum"] == ("%08x" % crc32_raw(p[8:]))
        return info

    def decode_bytes(self, c: bytes) -> dict:
        """按长度自动匹配密钥流；用 CRC 自校验区分「封包加密」与普通布局"""
        n = len(c)
        cands = [n, n + 18]
        tried = []
        for cn in cands:
            k = self.ks.get(cn)
            if k is None:
                continue
            tried.append(cn)
            try:
                info = self._decode_with(c, k)
            except Exception:
                continue
            if info["crc_ok"]:
                if info["sealed"] or cn != n:
                    info["flags"] |= 1
                    info["sealed"] = True
                info["length"] = cn
                return info
        if tried:
            # 长度可解但 CRC 不符：返回最接近的一次并标记
            info = self._decode_with(c, self.ks.get(n if n in tried else tried[0]))
            info["crc_ok"] = False
            return info
        raise ValueError("无法解码：长度 %d 不在已标定范围 %s" % (n, self.ks.lengths()))

    def decode(self, serverdata: str) -> dict:
        return self.decode_bytes(base64.b64decode(serverdata))

    # -- 底层 ---------------------------------------------------------------
    @staticmethod
    def _crypt(p: bytes, k: bytes) -> bytes:
        n = len(p)
        q = swap(p)
        c = bytearray(n)
        c[0] = q[0] ^ k[0]
        for i in range(1, n):
            c[i] = q[i] ^ k[i] ^ c[i - 1]
        return bytes(c)


# --------------------------------------------------------------------------- #
# 自检
# --------------------------------------------------------------------------- #
KNOWN = [
    # 官方 Encode.exe 的实测产物（回归锚点）
    ("127.0.0.1", 2000, 0,
     "QkgoCwqg5LnT+PdWGE0hDhuk9L/J/fRLC0gqEBO9+6awqoUVchVXS3zmiOGvuYgOfhdZS2T4kv29pZoIdhNPUQ4="),
    ("127.0.0.2", 2000, 0,
     "Qh9/DA31se+FrqEATht3WE3youmfq6IeXh1/RUborvPk/osbdBNWSn3nieCuuIkPfxZYSmX5k/y8pJsJdxJOUA8="),
]


def selftest(verbose: bool = True) -> bool:
    codec = Codec(KeyStream.load())
    ok = True
    bad = 0
    total = 0
    for ip, port, fl, want in KNOWN:
        total += 1
        got = codec.encode(ip, port, fl)
        if got != want:
            ok = False
            bad += 1
            if verbose:
                print("  ✘ 已知向量不符 %s:%d" % (ip, port))
    if verbose:
        print("官方向量：%d/%d 通过" % (total - bad, total))

    ips = ["127.0.0.1", "1.1.1.1", "10.0.0.1", "111.1.11.1", "11.11.11.11",
           "111.11.11.11", "111.111.11.11", "111.111.111.11", "255.255.255.255",
           "203.0.113.24"]
    ports = [5, 80, 123, 2000, 65535]
    flags = [0, 80, 1, 81, 2, 4, 16, 32, 64, 128]
    total = bad = 0
    for ip in ips:
        for port in ports:
            for fl in flags:
                total += 1
                try:
                    s = codec.encode(ip, port, fl)
                    info = codec.decode(s)
                except ValueError:
                    bad += 1
                    continue
                if (info["ip"] != ip or info["port"] != port
                        or info["flags"] != fl or not info["crc_ok"]):
                    bad += 1
                    if verbose and bad <= 5:
                        print("  ✘ %s:%d f=%d -> %s" % (ip, port, fl, info))
    if verbose:
        print("往返/CRC：%d/%d 通过" % (total - bad, total))
    return ok and bad == 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def write_ini(path: str, zones, encoding="gbk"):
    """生成 servers.ini（区名不参与加密）"""
    codec = Codec(KeyStream.load())
    lines = []
    for i, (name, ip, port, flags) in enumerate(zones, 1):
        lines.append("[Server%d]" % i)
        lines.append("ServerName=%s" % name)
        lines.append("ServerData=%s" % codec.encode(ip, int(port), int(flags, 0)))
    with open(path, "w", encoding=encoding, newline="\r\n") as f:
        f.write("\n".join(lines) + "\n")
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description="L1J ServerData 纯 Python 编解码器")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    ap.add_argument("--decode", metavar="SERVERDATA", help="解码 Base64 的 ServerData")
    ap.add_argument("--decode-file", metavar="INI", help="解码 servers.ini 中的全部条目")
    ap.add_argument("--encode", action="store_true", help="编码（需 --ip/--port）")
    ap.add_argument("--ip", help="IP 或域名")
    ap.add_argument("--port", type=int, default=2000, help="端口，默认 2000")
    ap.add_argument("--flags", type=lambda s: int(s, 0), default=0, help="功能位，支持 0x 前缀")
    ap.add_argument("--raw", action="store_true", help="同时显示明文")
    ap.add_argument("--selftest", action="store_true", help="运行自检")
    ap.add_argument("--ini", metavar="OUT", help="生成 servers.ini")
    ap.add_argument("--zone", action="append", default=[], help='区服："区名,IP,端口[,flags]"')
    a = ap.parse_args(argv)

    codec = Codec(KeyStream.load())

    if a.selftest:
        return 0 if selftest() else 1

    if a.decode:
        info = codec.decode(a.decode)
        print("IP      : %s" % info["ip"])
        print("PORT    : %d" % info["port"])
        names = [FLAG_NAMES[b] for b in range(8) if (info["flags"] >> b) & 1]
        print("FLAGS   : %d (0x%x)%s" % (info["flags"], info["flags"],
                                         ("  " + "、".join(names)) if names else ""))
        print("VERSION : %s" % info["version"])
        print("LEN     : %d%s" % (info["length"], "  (封包加密)" if info["flags"] & 1 else ""))
        print("CRC     : %s (%s)" % (info["checksum"], "OK" if info["crc_ok"] else "MISMATCH"))
        if a.raw:
            print("PLAIN   : %s" % info["plaintext"])
        return 0

    if a.decode_file:
        with open(a.decode_file, "rb") as f:
            text = f.read().decode("gbk", "replace")
        pat = re.compile(r"\[Server(\d+)\]\s*\r?\nServerName=(.*?)\r?\nServerData=([A-Za-z0-9+/=]+)")
        for m in pat.finditer(text):
            try:
                info = codec.decode(m.group(3))
                print("[Server%s] %-12s -> %s:%d flags=%d  %s" % (
                    m.group(1), m.group(2), info["ip"], info["port"], info["flags"],
                    "OK" if info["crc_ok"] else "CRC 不符"))
            except Exception as exc:
                print("[Server%s] %-12s -> 解码失败：%s" % (m.group(1), m.group(2), exc))
        return 0

    if a.encode:
        if not a.ip:
            ap.error("--encode 需要 --ip")
        print(codec.encode(a.ip, a.port, a.flags))
        if a.raw:
            print("# 明文: %s" % build_plain(a.ip, a.port, a.flags).decode("latin1"),
                  file=sys.stderr)
        return 0

    if a.ini:
        zones = []
        for z in a.zone:
            parts = [x.strip() for x in z.split(",")]
            if len(parts) < 3:
                ap.error('--zone 格式应为 "区名,IP,端口[,flags]"')
            zones.append((parts[0], parts[1], parts[2], parts[3] if len(parts) > 3 else "0"))
        if not zones:
            ap.error("--ini 至少需要一个 --zone")
        write_ini(a.ini, zones)
        print("已写出 %s（%d 个区服）" % (a.ini, len(zones)))
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
