// sm3_avx2_fixed.cpp
#include <immintrin.h>
#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <cstdint>
#include <iomanip>
using namespace std;

using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

static inline u32 ROTL(u32 x, unsigned n) {
    n &= 31u;
    if (n == 0) return x;
    return (x << n) | (x >> (32 - n));
}
static inline u32 P0(u32 x) { return x ^ ROTL(x, 9) ^ ROTL(x, 17); }
static inline u32 P1(u32 x) { return x ^ ROTL(x, 15) ^ ROTL(x, 23); }
static inline u32 FF(u32 x, u32 y, u32 z, int j) {
    if (j >= 0 && j <= 15) return x ^ y ^ z;
    return (x & y) | (x & z) | (y & z);
}
static inline u32 GG(u32 x, u32 y, u32 z, int j) {
    if (j >= 0 && j <= 15) return x ^ y ^ z;
    return (x & y) | ((~x) & z);
}

vector<u8> sm3_scalar(const vector<u8>& msg) {
    u32 V[8] = {
        0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,
        0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e
    };

    vector<u8> M = msg;
    u64 bitlen = (u64)msg.size() * 8;
    M.push_back(0x80);
    while ((M.size() % 64) != 56) M.push_back(0x00);
    for (int i = 7; i >= 0; --i) M.push_back((u8)((bitlen >> (i * 8)) & 0xFF));

    size_t nblocks = M.size() / 64;
    for (size_t bi = 0; bi < nblocks; ++bi) {
        u32 W[68]; u32 W1[64];
        for (int i = 0; i < 16; ++i) {
            size_t off = bi * 64 + i * 4;
            W[i] = ((u32)M[off] << 24) | ((u32)M[off + 1] << 16) | ((u32)M[off + 2] << 8) | ((u32)M[off + 3]);
        }
        for (int j = 16; j <= 67; ++j) {
            u32 x = W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15);
            W[j] = P1(x) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
        }
        for (int j = 0; j <= 63; ++j) W1[j] = W[j] ^ W[j + 4];

        u32 A = V[0], B = V[1], C = V[2], D = V[3];
        u32 E = V[4], F = V[5], G = V[6], H = V[7];
        for (int j = 0; j <= 63; ++j) {
            u32 Tj = (j <= 15) ? 0x79cc4519u : 0x7a879d8au;
            u32 SS1 = ROTL((ROTL(A, 12) + E + ROTL(Tj, j)), 7);
            u32 SS2 = SS1 ^ ROTL(A, 12);
            u32 TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            u32 TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C; C = ROTL(B, 9); B = A; A = TT1;
            H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
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

string to_hex(const vector<u8>& bs) {
    static const char hex[] = "0123456789abcdef";
    string s; s.reserve(bs.size() * 2);
    for (u8 b : bs) { s.push_back(hex[b >> 4]); s.push_back(hex[b & 0xF]); }
    return s;
}

static inline __m256i set4_u32(u32 a, u32 b, u32 c, u32 d) {
    return _mm256_setr_epi32((int)a, (int)b, (int)c, (int)d, 0, 0, 0, 0);
}
static inline __m256i set1_u32(u32 x) {
    return set4_u32(x, x, x, x);
}
static inline u32 extract_lane_u32(__m256i v, int lane) {
    alignas(32) u32 tmp[8];
    _mm256_storeu_si256((__m256i*)tmp, v);
    return tmp[lane];
}
static inline __m256i xor4(__m256i a, __m256i b) { return _mm256_xor_si256(a, b); }
static inline __m256i and4(__m256i a, __m256i b) { return _mm256_and_si256(a, b); }
static inline __m256i or4(__m256i a, __m256i b) { return _mm256_or_si256(a, b); }
static inline __m256i not4(__m256i a) { return _mm256_xor_si256(a, _mm256_set1_epi32(-1)); }
static inline __m256i add4(__m256i a, __m256i b) { return _mm256_add_epi32(a, b); }

static inline __m256i rol4(__m256i x, int n) {
    int r = n & 31;
    if (r == 0) return x;
    return _mm256_or_si256(_mm256_slli_epi32(x, r), _mm256_srli_epi32(x, 32 - r));
}

static inline __m256i P0_4(__m256i x) { return xor4(x, xor4(rol4(x, 9), rol4(x, 17))); }
static inline __m256i P1_4(__m256i x) { return xor4(x, xor4(rol4(x, 15), rol4(x, 23))); }
static inline __m256i FF_4(__m256i x, __m256i y, __m256i z, int j) {
    if (j >= 0 && j <= 15) return xor4(x, xor4(y, z));
    return or4(or4(and4(x, y), and4(x, z)), and4(y, z));
}
static inline __m256i GG_4(__m256i x, __m256i y, __m256i z, int j) {
    if (j >= 0 && j <= 15) return xor4(x, xor4(y, z));
    return or4(and4(x, y), and4(not4(x), z));
}
static inline __m256i load_w4(const array<u32, 4>& w) {
    return set4_u32(w[0], w[1], w[2], w[3]);
}


array<array<u32, 8>, 4> sm3_compress_4way_single_block(const array<array<u8, 64>, 4>& blocks, const array<array<u32, 8>, 4>& initialVs) {
    __m256i Wv[68];
    __m256i W1v[64];

    for (int j = 0; j < 16; ++j) {
        array<u32, 4> tmp{};
        for (int lane = 0; lane < 4; ++lane) {
            size_t off = j * 4;
            tmp[lane] = ((u32)blocks[lane][off] << 24) |
                ((u32)blocks[lane][off + 1] << 16) |
                ((u32)blocks[lane][off + 2] << 8) |
                ((u32)blocks[lane][off + 3]);
        }
        Wv[j] = load_w4(tmp);
    }

    //扩展
    for (int j = 16; j <= 67; ++j) {
        __m256i x = xor4(xor4(Wv[j - 16], Wv[j - 9]), rol4(Wv[j - 3], 15));
        Wv[j] = xor4(xor4(P1_4(x), rol4(Wv[j - 13], 7)), Wv[j - 6]);
    }

    for (int j = 0; j <= 63; ++j) {
        W1v[j] = xor4(Wv[j], Wv[j + 4]);
    }

    //A..H
    __m256i A = set4_u32(initialVs[0][0], initialVs[1][0], initialVs[2][0], initialVs[3][0]);
    __m256i B = set4_u32(initialVs[0][1], initialVs[1][1], initialVs[2][1], initialVs[3][1]);
    __m256i C = set4_u32(initialVs[0][2], initialVs[1][2], initialVs[2][2], initialVs[3][2]);
    __m256i D = set4_u32(initialVs[0][3], initialVs[1][3], initialVs[2][3], initialVs[3][3]);
    __m256i E = set4_u32(initialVs[0][4], initialVs[1][4], initialVs[2][4], initialVs[3][4]);
    __m256i F = set4_u32(initialVs[0][5], initialVs[1][5], initialVs[2][5], initialVs[3][5]);
    __m256i G = set4_u32(initialVs[0][6], initialVs[1][6], initialVs[2][6], initialVs[3][6]);
    __m256i H = set4_u32(initialVs[0][7], initialVs[1][7], initialVs[2][7], initialVs[3][7]);

    for (int j = 0; j <= 63; ++j) {
        u32 Tj_scalar = (j <= 15) ? 0x79cc4519u : 0x7a879d8au;
        u32 Tj_rot = ROTL(Tj_scalar, (unsigned)j);
        __m256i Tjv = set1_u32(Tj_rot);

        __m256i SS1 = rol4(add4(add4(rol4(A, 12), E), Tjv), 7);
        __m256i SS2 = xor4(SS1, rol4(A, 12));
        __m256i TT1 = add4(add4(add4(FF_4(A, B, C, j), D), SS2), W1v[j]);
        __m256i TT2 = add4(add4(add4(GG_4(E, F, G, j), H), SS1), Wv[j]);

        D = C;
        C = rol4(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = rol4(F, 19);
        F = E;
        E = P0_4(TT2);
    }

    array<array<u32, 8>, 4> outVs;
    for (int lane = 0; lane < 4; ++lane) {
        u32 a = extract_lane_u32(A, lane);
        u32 b = extract_lane_u32(B, lane);
        u32 c = extract_lane_u32(C, lane);
        u32 d = extract_lane_u32(D, lane);
        u32 e = extract_lane_u32(E, lane);
        u32 f = extract_lane_u32(F, lane);
        u32 g = extract_lane_u32(G, lane);
        u32 h = extract_lane_u32(H, lane);
        for (int i = 0; i < 8; ++i) outVs[lane][i] = initialVs[lane][i];
        outVs[lane][0] ^= a; outVs[lane][1] ^= b; outVs[lane][2] ^= c; outVs[lane][3] ^= d;
        outVs[lane][4] ^= e; outVs[lane][5] ^= f; outVs[lane][6] ^= g; outVs[lane][7] ^= h;
    }
    return outVs;
}


array<vector<u8>, 4> sm3_4way(const array<vector<u8>, 4>& msgs) {
    array<vector<u8>, 4> Ms;
    array<size_t, 4> nblocks{};
    for (int i = 0; i < 4; ++i) {
        Ms[i] = msgs[i];
        u64 bitlen = (u64)msgs[i].size() * 8;
        Ms[i].push_back(0x80);
        while ((Ms[i].size() % 64) != 56) Ms[i].push_back(0x00);
        for (int b = 7; b >= 0; --b) Ms[i].push_back((u8)((bitlen >> (b * 8)) & 0xFF));
        nblocks[i] = Ms[i].size() / 64;
    }

    array<vector<u8>, 4> digests;

    bool all_single_block = true;
    for (int i = 0; i < 4; ++i) if (nblocks[i] != 1) { all_single_block = false; break; }

    if (all_single_block) {
        array<array<u8, 64>, 4> blocks;
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 64; ++j) blocks[i][j] = Ms[i][j];
        }
        array<array<u32, 8>, 4> Vs_init;
        for (int lane = 0; lane < 4; ++lane) {
            Vs_init[lane] = { 0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600, 0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e };
        }
        auto outVs = sm3_compress_4way_single_block(blocks, Vs_init);
        for (int i = 0; i < 4; ++i) {
            vector<u8> dg(32);
            for (int k = 0; k < 8; ++k) {
                dg[k * 4 + 0] = (u8)((outVs[i][k] >> 24) & 0xFF);
                dg[k * 4 + 1] = (u8)((outVs[i][k] >> 16) & 0xFF);
                dg[k * 4 + 2] = (u8)((outVs[i][k] >> 8) & 0xFF);
                dg[k * 4 + 3] = (u8)((outVs[i][k] >> 0) & 0xFF);
            }
            digests[i] = move(dg);
        }
        return digests;
    }

    for (int i = 0; i < 4; ++i) digests[i] = sm3_scalar(msgs[i]);
    return digests;
}


int main() {
    string test = "abc";
    vector<u8> data(test.begin(), test.end());
    auto dg = sm3_scalar(data);
    cout << "SM3(\"" << test << "\") = " << to_hex(dg) << "\n";


    // 4-way test (single-block messages)
    array<vector<u8>, 4> msgs;
    msgs[0] = vector<u8>({ 'a' });
    msgs[1] = vector<u8>({ 'a','b','c' });
    msgs[2] = vector<u8>({ 't','e','s','t' });
    msgs[3] = vector<u8>{};

    auto dgs = sm3_4way(msgs);
    cout << "4-way SM3 结果:\n";
    for (int i = 0; i < 4; ++i) {
        cout << "msg[" << i << "] = \"" << string(msgs[i].begin(), msgs[i].end()) << "\" -> " << to_hex(dgs[i]) << "\n";
    }

    auto dg_scalar_abc = sm3_scalar(vector<u8>{'a', 'b', 'c'});
    cout << "\n与SM3(\"abc\")结果是否相等: "
        << (to_hex(dgs[1]) == to_hex(dg_scalar_abc) ? "相等" : "不相等") << "\n";

    return 0;
}
