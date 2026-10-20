# L1J-Encode-CLI

**Lineage 1（天堂1）登录器 `ServerData` 编解码工具** —— 把厂商 `Encode.exe` 的黑盒编码，完整还原成公开算法。

> 现在**不需要 Encode.exe**：编码、解码都是纯 Python，输出与官方逐字节一致。

---

## 能力

| 能力 | 状态 |
|---|---|
| 从密文反解 IP / 端口 / 功能位 | ✅ 100%（含 CRC 自校验，可判定解错） |
| 不依赖 Encode.exe 生成 ServerData | ✅ 100%（与官方逐字节一致） |
| 覆盖 IP 长度 7–15、端口 1–5 位 | ✅ 45 种布局全支持 |
| 功能位 bit0–bit7 | ✅ 全部可编可解 |
| 外部依赖 | 无（纯标准库） |

---

## 算法全貌

```
明文  p = <CRC8> * <版本> * <IP> * <PORT> + tail
置换  q = swap(p)                      # 互换 buf[i] 与 buf[half+i]
密文  c[0] = q[0] ^ ks[0]
      c[i] = q[i] ^ ks[i] ^ c[i-1]     (i >= 1)
输出  ServerData = Base64(c)
```

三段关键参数：

**1. CRC8 —— 明文头部 8 位十六进制**

| 参数 | 值 |
|---|---|
| 多项式 | `0xEDB88320`（反射，即标准 CRC-32） |
| 初值 init | `0xF0958FF3` |
| 终值 xorout | `0xFFFFFFFF` |
| 作用范围 | `<版本>` 起到明文结尾的整段（含功能位） |
| 输出格式 | 小写十六进制 8 位 |

**2. swap —— 字节置换**

`half = n // 2`，对 `i = 0, 2, 4, ...`（`i < half`）交换 `buf[i]` 与 `buf[half+i]`。
自逆，解密用同一个函数。

**3. ks —— 密钥流**

只与明文长度 `n` 有关，与 IP / 端口 / 功能位无关。
`n = 52 + len(IP) + len(str(PORT))`，开启 bit0（封包加密）时再 `+18`。
26 个长度的完整表在 `ks_table.json`。

### 功能位位置

把明文按 `*` 切开后：

| 功能位 | 段号 | 名称 |
|---|---|---|
| bit0 | — | 封包加密（不占段位，改为 `+18` 长度并插入 `*1*<常量>*<常量>`） |
| bit1 | 7 | 防外掛 |
| bit2 | 8 | 進階防外掛 |
| bit3 | 12 | 變身檔 |
| bit4 | 13 | 內建喝水 |
| bit5 | 14 | 移動封包不加密 |
| bit6 | 15 | 允許多開 |
| bit7 | 16 | 驗證地圖檔 |

置位时该段由 `0` 变 `1`。

---

## 用法

```bash
# 解码
python l1j_serverdata.py --decode "QkgoCwqg5LnT+PdWGE0hDhuk9L/J/fRLC0gqEBO9+6awqoUVchVXS3zmiOGvuYgOfhdZS2T4kv29pZoIdhNPUQ4="

# 编码
python l1j_serverdata.py --encode --ip 203.0.113.24 --port 2000 --flags 80

# 批量解码一份 servers.ini
python l1j_serverdata.py --decode-file servers.ini

# 直接生成 servers.ini（GBK + CRLF）
python l1j_serverdata.py --ini servers.ini \
    --zone "一区,203.0.113.24,2000,80" \
    --zone "二区,203.0.113.24,2001,80"

# 自检
python l1j_serverdata.py --selftest
```

作为库使用：

```python
from l1j_serverdata import Codec, KeyStream

codec = Codec(KeyStream.load())
sd = codec.encode("203.0.113.24", 2000, flags=0x50)
info = codec.decode(sd)
# {'ip': '203.0.113.24', 'port': 2000, 'flags': 80, 'crc_ok': True, ...}
```

---

## 验证

| 测试 | 内容 | 结果 |
|---|---|---|
| `python l1j_serverdata.py --selftest` | 500 组往返 + CRC 自洽 | 500/500 |
| `python tests/test_vectors.py` | 15 组官方 Encode.exe 固化向量 | 编码 15/15、解码 15/15 |
| `python tests/fuzz_roundtrip.py` | 2000 组随机往返 | 2000/2000 |
| 对抗测试（需 Encode.exe） | 106 组随机输入与官方逐字节比对 | 106/106 |
| 线上实配回放 | 生产 `servers.ini` 两区解码 + 重编码 | 完全一致 |

---

## 目录

```
l1j_serverdata.py      编解码器（纯 Python，无依赖）
ks_table.json          26 个长度的密钥流表（约 4 KB）
tests/vectors.json     官方产物固化向量
tests/test_vectors.py  向量回归
tests/fuzz_roundtrip.py 随机往返
docs/破解报告.md        还原过程与技术证据
```

---

## 局限

- **bit3（變身檔）**：官方工具还需要额外的变档文件才会置位，本工具只能写出标志位，客户端是否接受取决于是否配了对应文件。
- **bit0（封包加密）**：能编能解，但会让 `ServerData` 变长 18 字节，客户端需具备该能力。
- 密钥流是按 **Encode v3.63** 标定的；换版本需要重新标定 `ks_table.json`。
