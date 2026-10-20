#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""随机往返测试：不依赖 Encode.exe，纯属性验证

对每个可用布局随机造 IP/端口/功能位，编码后再解码，必须与原值完全一致，
并且解码出的 CRC 必须自校验通过（CRC 通过即代表明文没有被解错一个字节）。
"""
import json
import os
import random
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from l1j_serverdata import Codec, KeyStream  # noqa: E402


def rand_ip(rng, length):
    need = length - 3                      # 四个字段的位数之和
    for _ in range(5000):
        cuts = sorted(rng.sample(range(1, need), 3))
        ds = [cuts[0], cuts[1] - cuts[0], cuts[2] - cuts[1], need - cuts[2]]
        if all(1 <= d <= 3 for d in ds):
            parts = [rng.randint(10 ** (d - 1), 10 ** d - 1) for d in ds]
            cand = "%d.%d.%d.%d" % tuple(parts)
            if len(cand) == length:
                return cand
    raise RuntimeError("长度 %d 的 IP 生成失败" % length)


def main(rounds: int = 2000) -> int:
    rng = random.Random(20261020)
    codec = Codec(KeyStream.load())
    flags_pool = [0, 2, 4, 8, 16, 32, 64, 128, 80, 6, 80 | 2, 1, 81, 1 | 80, 1 | 4]
    bad = 0
    total = 0
    for _ in range(rounds):
        L = rng.randint(7, 15)
        P = rng.randint(1, 5)
        ip = rand_ip(rng, L)
        port = rng.randint(1, 9) if P == 1 else rng.randint(10 ** (P - 1), 10 ** P - 1)
        fl = rng.choice(flags_pool)
        total += 1
        try:
            sd = codec.encode(ip, port, fl)
            info = codec.decode(sd)
        except Exception as exc:                      # noqa: BLE001
            bad += 1
            print("  ✘ %s:%d f=%d 异常 %s" % (ip, port, fl, exc))
            continue
        if (info["ip"] != ip or info["port"] != port
                or info["flags"] != fl or not info["crc_ok"]):
            bad += 1
            if bad <= 10:
                print("  ✘ %s:%d f=%d -> %s" % (ip, port, fl, info))
    print("往返 %d/%d 通过" % (total - bad, total))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
