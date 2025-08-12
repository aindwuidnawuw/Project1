import os, struct
from math import ceil
from typing import Tuple


p  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
a  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
b  = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
n  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
Gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
Gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
G = (Gx, Gy)


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
            W[j] = int.from_bytes(bytes(B[4*j:4*j+4]), 'big')
        for j in range(16, 68):
            W[j] = (p1(W[j-16] ^ W[j-9] ^ rotl(W[j-3], 15)) ^ rotl(W[j-13], 7) ^ W[j-6]) & 0xFFFFFFFF
        for j in range(64):
            W1[j] = W[j] ^ W[j+4]
        A,Bb,C,D,E,F,Gv,H = V
        for j in range(64):
            SS1 = rotl(((rotl(A,12) + E + rotl(T_j[j], j)) & 0xFFFFFFFF), 7)
            SS2 = SS1 ^ rotl(A,12)
            TT1 = (ff_j(A,Bb,C,j) + D + SS2 + W1[j]) & 0xFFFFFFFF
            TT2 = (gg_j(E,F,Gv,j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = rotl(Bb, 9)
            Bb = A
            A = TT1
            H = Gv
            Gv = rotl(F, 19)
            F = E
            E = p0(TT2)
        V = [x ^ y for x,y in zip(V, [A,Bb,C,D,E,F,Gv,H])]
    return b''.join(x.to_bytes(4, 'big') for x in V)


def mod_inv(x: int, m: int = p) -> int:
    x %= m
    if x == 0:
        raise ZeroDivisionError("inverse of 0")
    return pow(x, m - 2, m)
def is_on_curve(P):
    if P is None:
        return True
    x,y = P
    return (y*y - (x*x*x + a*x + b)) % p == 0
def point_neg(P):
    if P is None:
        return None
    x,y = P
    return (x, (-y) % p)
def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1,y1 = P
    x2,y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * mod_inv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * mod_inv(x2 - x1, p) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)
def scalar_mult(k: int, P):
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


def _int_from_msg(msg: bytes) -> int:
    return int.from_bytes(sm3_hash(msg), 'big') % n

def sm2sign_return_k(d: int, msg: bytes, forced_k: int = None) -> Tuple[int,int,int]:
    e = _int_from_msg(msg)
    while True:
        if forced_k is not None:
            k = forced_k % n
        else:
            k = int.from_bytes(os.urandom(32), 'big') % n
        if k == 0:
            if forced_k is not None:
                raise RuntimeError("forced k invalid")
            continue
        x1y1 = scalar_mult(k, G)
        if x1y1 is None:
            if forced_k is not None:
                raise RuntimeError("k resulted in infinity")
            continue
        x1, y1 = x1y1
        r = (e + x1) % n
        if r == 0 or r + k == n:
            if forced_k is not None:
                raise RuntimeError("bad r for forced k")
            continue
        inv_1pd = mod_inv((1 + d) % n, n)
        s = (inv_1pd * (k - r * d)) % n
        if s == 0:
            if forced_k is not None:
                raise RuntimeError("bad s for forced k")
            continue
        return r, s, k


def recover_d(r1:int, s1:int, r2:int, s2:int) -> int:
    num = (s2 - s1) % n
    denom = ( (s1 - s2) + (r1 - r2) ) % n
    if denom == 0:
        raise ZeroDivisionError("denominator == 0 (cannot invert)")
    inv = pow(denom, -1, n)
    d_rec = (num * inv) % n
    return d_rec

if __name__ == "__main__":
    print("=== 演示 #2: SM2 重复使用同一 k 对两条消息签名 -> 恢复私钥 ===")
    while True:
        d = int.from_bytes(os.urandom(32), 'big') % n
        if 1 <= d <= n-2:
            break
    P = scalar_mult(d, G)
    print("私钥 d =", hex(d))
    print("公钥  P.x =", hex(P[0]))

    forced_k = int.from_bytes(os.urandom(16), 'big')  # shorter but non-zero; or set a constant for reproducible PoC
    print("固定的 k =", hex(forced_k))

    msg1 = b"abcde"
    msg2 = b"abcdefg"

    r1, s1, k1 = sm2sign_return_k(d, msg1, forced_k=forced_k)
    r2, s2, k2 = sm2sign_return_k(d, msg2, forced_k=forced_k)
    print("签名1 r1 =", r1)
    print("签名1 s1 =", s1)
    print("签名2 r2 =", r2)
    print("签名2 s2 =", s2)
    print("k1 是否等于 k2 (mod n) ?", (k1 - k2) % n == 0)

    d_rec = recover_d(r1, s1, r2, s2)
    print("恢复的私钥 d =", hex(d_rec))

    P_rec = scalar_mult(d_rec, G)
    print("恢复的公钥 P_rec.x =", hex(P_rec[0]))
    if P_rec == P:
        print("成功: 恢复的私钥与原始私钥匹配")
    else:
        print("失败: 恢复的私钥与原始私钥不匹配")

