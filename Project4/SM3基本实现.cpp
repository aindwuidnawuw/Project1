#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
using namespace std;

using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

static inline u32 ROTL(u32 x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}

static inline u32 P0(u32 x) {
    return x ^ ROTL(x, 9) ^ ROTL(x, 17);
}

static inline u32 P1(u32 x) {
    return x ^ ROTL(x, 15) ^ ROTL(x, 23);
}

static inline u32 FF(u32 x, u32 y, u32 z, int j) {
    if (j >= 0 && j <= 15) return x ^ y ^ z;
    return (x & y) | (x & z) | (y & z);
}

static inline u32 GG(u32 x, u32 y, u32 z, int j) {
    if (j >= 0 && j <= 15) return x ^ y ^ z;
    return (x & y) | ((~x) & z);
}

string to_hex(const vector<u8>& bs) {
    static const char hex[] = "0123456789abcdef";
    string s;
    s.reserve(bs.size() * 2);
    for (u8 b : bs) {
        s.push_back(hex[b >> 4]);
        s.push_back(hex[b & 0xF]);
    }
    return s;
}

vector<u8> sm3(const vector<u8>& msg) {
    // IV
    u32 V[8] = {
        0x7380166f,
        0x4914b2b9,
        0x172442d7,
        0xda8a0600,
        0xa96f30bc,
        0x163138aa,
        0xe38dee4d,
        0xb0fb0e4e
    };

    // 填充
    vector<u8> M = msg;
    u64 bitlen = (u64)msg.size() * 8;
    M.push_back(0x80);
    while ((M.size() % 64) != 56) M.push_back(0x00);
    for (int i = 7; i >= 0; --i) {
        M.push_back((u8)((bitlen >> (i * 8)) & 0xFF));
    }

    size_t nblocks = M.size() / 64;
    for (size_t bi = 0; bi < nblocks; ++bi) {
        u32 W[68];
        u32 W1[64];

        for (int i = 0; i < 16; ++i) {
            size_t off = bi * 64 + i * 4;
            W[i] =
                ((u32)M[off] << 24) |
                ((u32)M[off + 1] << 16) |
                ((u32)M[off + 2] << 8) |
                ((u32)M[off + 3]);
        }
        for (int j = 16; j <= 67; ++j) {
            u32 x = W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15);
            W[j] = P1(x) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
        }
        for (int j = 0; j <= 63; ++j) {
            W1[j] = W[j] ^ W[j + 4];
        }

        u32 A = V[0], B = V[1], C = V[2], D = V[3];
        u32 E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j <= 63; ++j) {
            u32 Tj = (j <= 15) ? 0x79cc4519u : 0x7a879d8au;
            u32 SS1 = ROTL((ROTL(A, 12) + E + ROTL(Tj, j)), 7);
            u32 SS2 = SS1 ^ ROTL(A, 12);
            u32 TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            u32 TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = ROTL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
            F = E;
            E = P0(TT2);
        }

        V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }

    vector<u8> digest(32);
    for (int i = 0; i < 8; ++i) {
        digest[i * 4 + 0] = (u8)((V[i] >> 24) & 0xFF);
        digest[i * 4 + 1] = (u8)((V[i] >> 16) & 0xFF);
        digest[i * 4 + 2] = (u8)((V[i] >> 8) & 0xFF);
        digest[i * 4 + 3] = (u8)((V[i] >> 0) & 0xFF);
    }
    return digest;
}

int main() {
    // 测试 "abcdefg" 
    string test = "abcdefg";
    vector<u8> data(test.begin(), test.end());
    vector<u8> dg = sm3(data);
    cout << "SM3(\"" << test << "\") = " << to_hex(dg) << "\n";
    vector<u8> empty;
    auto test1 = sm3(empty);
    cout << "SM3(\"\") = " << to_hex(test1) << "\n";

    return 0;
}