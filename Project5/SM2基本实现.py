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
    x %= m
    if x == 0:
        raise ZeroDivisionError("inverse of 0")
    # p 是素数，可以用 pow 快速求逆
    return pow(x, m - 2, m)

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

def scalar_mult(k: int, P: Tuple[int,int]):
    if k % n == 0 or P is None:
        return None
    if k < 0:
        return scalar_mult(-k, point_neg(P))
    result = None
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
]

T_j = [0x79CC4519 if j <= 15 else 0x7A879D8A for j in range(64)]

def rotl(x, n):
    """32-bit 循环左移，确保 n 在 0..31 之间，避免负移位错误"""
    n &= 31  # 等同于 n % 32
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
    print("公钥 P = (", hex(P[0]), ",", hex(P[1]), ")")
    msg = b"abcdefg"
    print("明文:", msg)
    ct = sm2_encrypt(P, msg)
    print("密文长度:", len(ct), "字节")
    pt = sm2_decrypt(d, ct)
    print("解密得到:", pt)
    assert pt == msg
    print("解密成功，消息一致。")