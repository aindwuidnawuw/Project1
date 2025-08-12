import os
import hashlib

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def mod_inv(x: int, m: int) -> int:
    x %= m
    if x == 0:
        raise ZeroDivisionError("inverse of 0")
    return pow(x, -1, m)

def point_add(P, Q):
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
        lam = (y2 - y1) * mod_inv((x2 - x1) % p, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k: int, P):
    if k % n == 0 or P is None:
        return None
    if k < 0:
        # 负数处理
        return scalar_mult(-k, (P[0], (-P[1]) % p))
    result = None
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def int_from_msg_sha256(msg: bytes) -> int:
    h = hashlib.sha256(msg).digest()
    return int.from_bytes(h, 'big') % n

def sign(d: int, msg: bytes, forced_k: int = None):
    e = int_from_msg_sha256(msg)
    while True:
        if forced_k is None:
            k = int.from_bytes(os.urandom(32), 'big') % n
        else:
            k = forced_k % n
        if k == 0:
            if forced_k is not None:
                raise RuntimeError("forced k == 0")
            continue
        P = scalar_mult(k, G)
        if P is None:
            if forced_k is not None:
                raise RuntimeError("k produced infinity")
            continue
        rx = P[0] % n
        if rx == 0:
            if forced_k is not None:
                raise RuntimeError("bad r for forced k")
            continue
        invk = mod_inv(k, n)
        s = (invk * (e + d * rx)) % n
        if s == 0:
            if forced_k is not None:
                raise RuntimeError("bad s for forced k")
            continue
        return rx, s, k


def verify(Q, msg: bytes, sig):
    r, s = sig
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    e = int_from_msg_sha256(msg)
    w = mod_inv(s, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    P1 = scalar_mult(u1, G)
    P2 = scalar_mult(u2, Q)
    R = point_add(P1, P2)
    if R is None:
        return False
    xR = R[0] % n
    return xR == r


def recover_d(r: int, s: int, k: int, e:int) -> int:
    denom = r % n
    if denom == 0:
        raise ZeroDivisionError("r == 0 mod n")
    inv_r = mod_inv(denom, n)
    d_rec = ((k * s - e) * inv_r) % n
    return d_rec


if __name__ == "__main__":
    print("中本聪数字签名伪造")

    while True:
        d = int.from_bytes(os.urandom(32), 'big') % n
        if 1 <= d <= n-2:
            break
    Q = scalar_mult(d, G)
    print("私钥 d :", hex(d))
    print("公钥 Q.x :", hex(Q[0]))

    msg_orig = b"abcde"
    r, s, k = sign(d, msg_orig, forced_k=None)  # 如需可复现请传 forced_k=...
    e = int_from_msg_sha256(msg_orig)
    print("\n原始签名 (r, s):")
    print(" msg:", msg_orig)
    print(" r =", r)
    print(" s =", s)
    print(" k =", k)

    d_recovered = recover_d(r, s, k, e)
    print("\n攻击者恢复出的私钥 ", hex(d_recovered))
    print("与原私钥一致:", d_recovered == d)

    msg_forge = b"abcdefg"
    r_f, s_f, k_f = sign(d_recovered, msg_forge, forced_k=None)
    print("\n伪造签名 (r_f, s_f):")
    print(" msg:", msg_forge)
    print(" r_f =", r_f)
    print(" s_f =", s_f)

    ok = verify(Q, msg_forge, (r_f, s_f))
    print("\n在原公钥下对伪造签名的验签结果：", ok)
    assert ok, "伪造签名验证失败"
