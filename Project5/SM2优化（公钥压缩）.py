from math import ceil
from typing import Tuple
import os
import struct


p  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
a  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
b  = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
n  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
Gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
Gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)


def mod_inv(x: int, m: int = p) -> int:
    if m <= 0:
        raise ValueError("modulus must be positive")
    x = x % m
    if x == 0:
        raise ZeroDivisionError("inverse of 0")
    a = x
    b = m
    lm, hm = 1, 0
    low, high = a, b

    while low > 1:
        q = high // low
        high, low = low, high - q * low
        hm, lm = lm, hm - q * lm

    if low != 1:
        raise ZeroDivisionError("inverse does not exist")
    inv = lm % m
    return inv

def is_on_curve(P: Tuple[int,int]) -> bool:
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % p == 0

def point_neg(P: Tuple[int,int]):
    if P is None:
        return None
    x, y = P
    return (x, (-y) % p)

def point_add(P: Tuple[int,int], Q: Tuple[int,int]):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * mod_inv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * mod_inv(x2 - x1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k: int, P: Tuple[int,int], window_size: int = 4):
    if k % n == 0 or P is None:
        return None
    if k < 0:
        return scalar_mult(-k, point_neg(P), window_size)

    k = k % n
    w = window_size
    if w < 1:
        result = None
        addend = P
        while k:
            if k & 1:
                result = point_add(result, addend)
            addend = point_add(addend, addend)
            k >>= 1
        return result

    table_size = (1 << w)
    table = [None] * table_size
    table[1] = P
    for i in range(2, table_size):
        table[i] = point_add(table[i-1], P)

    kb = bin(k)[2:]
    i = 0
    result = None
    L = len(kb)
    while i < L:
        if kb[i] == '0':
            result = point_add(result, result)
            i += 1
        else:
            l = min(w, L - i)
            while l > 1 and kb[i:i+l][0] == '0':
                l -= 1
            val = int(kb[i:i+l], 2)
            for _ in range(l):
                result = point_add(result, result)
            if val != 0:
                result = point_add(result, table[val])
            i += l
    return result


IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
]

T_j = [0x79CC4519 if j <= 15 else 0x7A879D8A for j in range(64)]

def rotl(x, n):
    n &= 31
    x &= 0xFFFFFFFF
    if n == 0:
        return x
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def ff_j(x, y, z, j):
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:
        return (x & y) | (x & z) | (y & z)

def gg_j(x, y, z, j):
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:
        return (x & y) | ((~x) & z)

def p0(x):
    return x ^ rotl(x, 9) ^ rotl(x, 17)

def p1(x):
    return x ^ rotl(x, 15) ^ rotl(x, 23)

def sm3_hash(msg: bytes) -> bytes:
    m = bytearray(msg)
    l = len(m) * 8
    m.append(0x80)
    while ((len(m) * 8) % 512) != 448:
        m.append(0x00)
    m += struct.pack(">Q", l)
    V = IV[:]
    for i in range(0, len(m), 64):
        B = m[i:i+64]
        W = [0]*68
        W1 = [0]*64
        for j in range(16):
            W[j] = struct.unpack(">I", bytes(B[4*j:4*j+4]))[0]
        for j in range(16, 68):
            W[j] = (p1(W[j-16] ^ W[j-9] ^ rotl(W[j-3], 15)) ^ rotl(W[j-13], 7) ^ W[j-6]) & 0xFFFFFFFF
        for j in range(64):
            W1[j] = W[j] ^ W[j+4]
        A,Bb,C,D,E,F,G,H = V
        for j in range(64):
            SS1 = rotl(((rotl(A,12) + E + rotl(T_j[j], j)) & 0xFFFFFFFF), 7)
            SS2 = SS1 ^ rotl(A,12)
            TT1 = (ff_j(A,Bb,C,j) + D + SS2 + W1[j]) & 0xFFFFFFFF
            TT2 = (gg_j(E,F,G,j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = rotl(Bb, 9)
            Bb = A
            A = TT1
            H = G
            G = rotl(F, 19)
            F = E
            E = p0(TT2)
        V = [x ^ y for x,y in zip(V, [A,Bb,C,D,E,F,G,H])]
    out = b''.join(struct.pack(">I", x) for x in V)
    return out

def kdf(z: bytes, klen: int) -> bytes:
    ct = 1
    digest = b""
    for i in range(ceil(klen / 32)):
        msg = z + struct.pack(">I", ct)
        digest += sm3_hash(msg)
        ct += 1
    return digest[:klen]

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes(32, 'big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def point_to_bytes(P: Tuple[int,int], compressed: bool = True) -> bytes:
    """
    压缩格式: 0x02/0x03 || x (32 bytes)
    非压缩格式: 0x04 || x (32) || y (32)
    """
    if P is None:
        raise ValueError("point is None")
    x, y = P
    xb = int_to_bytes(x)
    yb = int_to_bytes(y)
    if compressed:
        prefix = b'\x03' if (y & 1) else b'\x02'
        return prefix + xb
    else:
        return b'\x04' + xb + yb

def modular_sqrt(a: int, p_mod: int = p) -> int:
    a %= p_mod
    if a == 0:
        return 0
    ls = pow(a, (p_mod - 1) // 2, p_mod)
    if ls == p_mod - 1:
        return None
    if p_mod % 4 == 3:
        y = pow(a, (p_mod + 1) // 4, p_mod)
        if (y * y) % p_mod != a % p_mod:
            return None
        return y
    raise NotImplementedError("modular_sqrt requires p % 4 == 3 or TS algorithm implemented")

def bytes_to_point(pubkey_bytes: bytes) -> Tuple[int,int]:
    """
    将公钥字节（压缩或非压缩）解析为点 (x, y)。
    支持前缀 0x02/0x03/0x04。
    """
    if len(pubkey_bytes) == 0:
        raise ValueError("empty pubkey bytes")

    prefix = pubkey_bytes[0]
    if prefix == 0x04:
        if len(pubkey_bytes) != 1 + 32 + 32:
            raise ValueError("invalid uncompressed pubkey length")
        x = bytes_to_int(pubkey_bytes[1:33])
        y = bytes_to_int(pubkey_bytes[33:65])
        P = (x, y)
        if not is_on_curve(P):
            raise ValueError("point not on curve")
        return P
    elif prefix in (0x02, 0x03):
        if len(pubkey_bytes) != 1 + 32:
            raise ValueError("invalid compressed pubkey length")
        x = bytes_to_int(pubkey_bytes[1:33])
        rhs = (pow(x, 3, p) + (a * x) + b) % p
        y = modular_sqrt(rhs, p)
        if y is None:
            raise ValueError("x does not correspond to a curve point (no sqrt)")
        # prefix 0x02 means y is even; 0x03 means y is odd
        need_odd = (prefix == 0x03)
        if (y & 1) != need_odd:
            y = (-y) % p
        P = (x, y)
        if not is_on_curve(P):
            raise ValueError("recovered point not on curve")
        return P
    else:
        raise ValueError("unsupported pubkey prefix")

G = (Gx, Gy)

def gen_keypair() -> Tuple[int, Tuple[int,int]]:
    while True:
        d = int.from_bytes(os.urandom(32), 'big') % n
        if 1 <= d <= n-2:
            break
    P = scalar_mult(d, G)
    return d, P

def sm2_encrypt(P: Tuple[int,int], msg: bytes) -> bytes:
    mlen = len(msg)
    while True:
        k = int.from_bytes(os.urandom(32), 'big') % n
        if k == 0:
            continue
        C1 = scalar_mult(k, G)
        x1, y1 = C1
        S = scalar_mult(k, P)
        if S is None:
            continue
        x2, y2 = S
        t = kdf(int_to_bytes(x2) + int_to_bytes(y2), mlen)
        if any(t):
            C2 = bytes(a ^ b for a,b in zip(msg, t))
            C3 = sm3_hash(int_to_bytes(x2) + msg + int_to_bytes(y2))
            c1_bytes = b'\x04' + int_to_bytes(x1) + int_to_bytes(y1)
            return c1_bytes + C3 + C2

def sm2_decrypt(d: int, cipher: bytes) -> bytes:
    if len(cipher) < 1 + 64 + 32:
        raise ValueError("cipher too short")
    if cipher[0] != 0x04:
        raise ValueError("only uncompressed point supported")
    c1_bytes = cipher[:1+64]
    C3 = cipher[1+64:1+64+32]
    C2 = cipher[1+64+32:]
    x1 = bytes_to_int(c1_bytes[1:33])
    y1 = bytes_to_int(c1_bytes[33:65])
    C1 = (x1, y1)
    if not is_on_curve(C1):
        raise ValueError("C1 not on curve")
    S = scalar_mult(d, C1)
    if S is None:
        raise ValueError("S is infinite (invalid)")
    x2, y2 = S
    mlen = len(C2)
    t = kdf(int_to_bytes(x2) + int_to_bytes(y2), mlen)
    if all(b == 0 for b in t):
        raise ValueError("kdf result is zero -> decryption fail")
    M = bytes(a ^ b for a,b in zip(C2, t))
    u = sm3_hash(int_to_bytes(x2) + M + int_to_bytes(y2))
    if u != C3:
        raise ValueError("C3 mismatch -> decryption fail (integrity)")
    return M

if __name__ == "__main__":
    print("生成密钥对...")
    d, P = gen_keypair()
    print("私钥 d =", hex(d))
    print("原公钥 P = (", hex(P[0]), ",", hex(P[1]), ")")
    # 非压缩序列化
    uncompressed = point_to_bytes(P, compressed=False)
    print("非压缩公钥:", uncompressed.hex())
    # 压缩序列化
    compressed = point_to_bytes(P, compressed=True)
    print("压缩公钥:", compressed.hex())

    # 从压缩公钥恢复
    P_rec = bytes_to_point(compressed)
    print("恢复后的公钥 P_rec = (", hex(P_rec[0]), ",", hex(P_rec[1]), ")")
    assert P_rec == P
    print("压缩/恢复自检通过。")

    # 兼容性测试：用压缩公钥来解码后进行加解密流程
    # 将压缩公钥转回 bytes->point，再进行加解密以确保所有流程兼容
    P_from_bytes = bytes_to_point(compressed)
    msg = b"abcdefg"
    ct = sm2_encrypt(P_from_bytes, msg)
    print("密文长度:", len(ct))
    pt = sm2_decrypt(d, ct)
    print("解密得到:", pt)
    assert pt == msg
    print("加解密自检通过。")
