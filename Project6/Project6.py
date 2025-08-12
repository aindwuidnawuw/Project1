import hashlib
import secrets
import math
from typing import List, Tuple

def is_prime(n, k=12):
    if n < 2: return False
    sp = [2,3,5,7,11,13,17,19,23,29]
    for p in sp:
        if n % p == 0: return n == p
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2; s += 1
    def _trial(a):
        x = pow(a, d, n)
        if x in (1, n-1): return True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1: return True
        return False
    for _ in range(k):
        if not _trial(secrets.randbelow(n - 3) + 2):
            return False
    return True

def gen_prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(c): return c

def L(x, n): return (x - 1) // n

class PubKey:
    def __init__(self, n, g):
        self.n, self.g, self.n2 = n, g, n*n

class PriKey:
    def __init__(self, lam, mu):
        self.lam, self.mu = lam, mu

def keygen(bits=512):
    p, q = gen_prime(bits//2), gen_prime(bits//2)
    while p == q: q = gen_prime(bits//2)
    n, g, n2 = p*q, p*q + 1, (p*q)*(p*q)
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    mu = pow(L(pow(g, lam, n2), n), -1, n)
    return PubKey(n, g), PriKey(lam, mu)

def enc(pk, m):
    n, g, n2 = pk.n, pk.g, pk.n2
    m %= n
    while True:
        r = secrets.randbelow(n)
        if math.gcd(r, n) == 1 and r != 0: break
    return (pow(g, m, n2) * pow(r, n, n2)) % n2

def dec(pk, sk, c):
    n, n2 = pk.n, pk.n2
    return (L(pow(c, sk.lam, n2), n) * sk.mu) % n

def add(pk, c1, c2): return (c1 * c2) % pk.n2
def mul(pk, c, k): return pow(c, k, pk.n2)

def re_rand(pk, c):
    while True:
        r = secrets.randbelow(pk.n)
        if math.gcd(r, pk.n) == 1 and r != 0: break
    return (c * pow(r, pk.n, pk.n2)) % pk.n2

class Group:
    def __init__(self, p, q, g): self.p, self.q, self.g = p, q, g

def gen_group(q_bits=256):
    q = gen_prime(q_bits)
    for k in range(2, 10000):
        p = k * q + 1
        if is_prime(p):
            for _ in range(50):
                h = secrets.randbelow(p - 3) + 2
                g = pow(h, k, p)
                if pow(g, q, p) == 1 and g != 1:
                    return Group(p, q, g)
    raise RuntimeError("生成群失败")

def hash_item(G, x: bytes):
    e = int.from_bytes(hashlib.sha256(x).digest(), 'big') % G.q
    if e == 0: e = 1
    return pow(G.g, e, G.p)

class A:
    def __init__(self, G, data: List[Tuple[bytes, int]]):
        self.G, self.data = G, data[:]
        self.k1 = secrets.randbelow(G.q - 1) + 1
        self.pk = None

    def recv_pk(self, pk): self.pk = pk

    def r1(self):
        out = []
        for (w, t) in self.data:
            lbl = pow(hash_item(self.G, w), self.k1, self.G.p)
            c = enc(self.pk, t)
            out.append((lbl, c))
        secrets.SystemRandom().shuffle(out)
        return out

    def r3(self, M_list):
        S = [pow(M, self.k1, self.G.p) for M in M_list]
        secrets.SystemRandom().shuffle(S)
        return S

    def recv_res(self, agg, sk):
        return dec(self.pk, sk, agg)

class B:
    def __init__(self, G, items: List[bytes]):
        self.G, self.items = G, items[:]
        self.k2 = secrets.randbelow(G.q - 1) + 1
        self.pk, self.sk = None, None
        self.map = {}

    def gen_pk(self, bits=512):
        self.pk, self.sk = keygen(bits)
        return self.pk

    def r2(self, lbl_enc):
        self.map = {}
        for (lbl, c) in lbl_enc:
            Lk = pow(lbl, self.k2, self.G.p)
            self.map.setdefault(Lk, []).append(c)
        M_list = [pow(hash_item(self.G, v), self.k2, self.G.p) for v in self.items]
        secrets.SystemRandom().shuffle(M_list)
        return M_list

    def r4(self, S_list):
        agg = None
        for S in S_list:
            if S in self.map:
                for c in self.map[S]:
                    agg = c if agg is None else add(self.pk, agg, c)
        if agg is None: agg = enc(self.pk, 0)
        return re_rand(self.pk, agg)

def demo():
    print("正在生成 DDH 群（可能需要几秒钟）...")
    G = gen_group(q_bits=160)
    print("群 p 位数:", G.p.bit_length(), "q 位数:", G.q.bit_length())

    a_data = [(b"3536581355@qq.com", 5), (b"1109861583@qq.com", 9), (b"1234567890@qq.com", 11)]
    b_items = [b"1109861583@qq.com", b"3536581355@qq.com"]

    A1 = A(G, a_data)
    B1 = B(G, b_items)

    pk = B1.gen_pk(bits=512)
    A1.recv_pk(pk)

    lbl_enc = A1.r1()
    M_list = B1.r2(lbl_enc)
    S_list = A1.r3(M_list)
    agg = B1.r4(S_list)

    res = A1.recv_res(agg, B1.sk)
    print("交集求和解密结果（A 看到）:", res)
    print("理论交集和:", 14)

if __name__ == "__main__":
    demo()
