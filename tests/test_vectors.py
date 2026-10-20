#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""已知答案回归：tests/vectors.json 全部由官方 Encode.exe 生成

覆盖两个方向：
  1. 编码一致 —— 本工具输出必须与官方逐字节相同
  2. 解码还原 —— 官方输出的 ServerData 必须解回原始 IP / 端口 / 功能位
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from l1j_serverdata import Codec, KeyStream  # noqa: E402


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    codec = Codec(KeyStream.load(os.path.join(here, "..", "ks_table.json")))
    vecs = json.load(open(os.path.join(here, "vectors.json"), encoding="utf-8"))

    enc_ok = enc_bad = dec_ok = dec_bad = 0
    for v in vecs:
        sd, ip, port, fl = v["serverdata"], v["ip"], v["port"], v["flags"]
        same = codec.encode(ip, port, fl) == sd
        enc_ok, enc_bad = enc_ok + same, enc_bad + (not same)

        try:
            info = codec.decode(sd)
            good = (info["ip"] == ip and info["port"] == port
                    and info["flags"] == fl and info["crc_ok"])
        except Exception as exc:                      # noqa: BLE001
            info = {"ip": "?", "port": 0, "flags": 0, "crc_ok": False, "detail": str(exc)}
            good = False
        dec_ok, dec_bad = dec_ok + good, dec_bad + (not good)

        print("  %-16s:%-6d f=%-3d len=%3d  编码 %s  解码 %s  -> %s:%d f=%d"
              % (ip, port, fl, len(base64.b64decode(sd)),
                 "OK  " if same else "FAIL",
                 "OK  " if good else "FAIL",
                 info["ip"], info["port"], info["flags"]))

    print("\n编码逐字节一致：%d 通过 / %d 失败" % (enc_ok, enc_bad))
    print("解码完全还原  ：%d 通过 / %d 失败" % (dec_ok, dec_bad))
    return 0 if (enc_bad == 0 and dec_bad == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
