#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
#include <array>    
using namespace std;

using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

static inline u32 ROTL(u32 x, unsigned n) {
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

string to_hex(const vector<u8>& bs) {
    static const char hex[] = "0123456789abcdef";
    string s; s.reserve(bs.size() * 2);
    for (u8 b : bs) { s.push_back(hex[b >> 4]); s.push_back(hex[b & 0xF]); }
    return s;
}

// 原始SM3
vector<u8> sm3(const vector<u8>& msg) {
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
        u32 W[68], W1[64];
        for (int i = 0; i < 16; ++i) {
            size_t off = bi * 64 + i * 4;
            W[i] = ((u32)M[off] << 24) | ((u32)M[off + 1] << 16) |
                ((u32)M[off + 2] << 8) | ((u32)M[off + 3]);
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

// 单块压缩
void sm3_compress_block(u32 V[8], const u8 block[64]) {
    u32 W[68], W1[64];
    for (int i = 0; i < 16; ++i) {
        size_t off = i * 4;
        W[i] = ((u32)block[off] << 24) | ((u32)block[off + 1] << 16) |
            ((u32)block[off + 2] << 8) | ((u32)block[off + 3]);
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

// 生成 SM3 填充
vector<u8> sm3_padding(u64 message) {
    vector<u8> pad;
    pad.push_back(0x80);
    while (((message + pad.size()) % 64) != 56) pad.push_back(0x00);
    u64 bitlen = message * 8;
    for (int i = 7; i >= 0; --i) pad.push_back((u8)((bitlen >> (i * 8)) & 0xFF));
    return pad;
}

// 从已知 digest 恢复 IV
array<u32, 8> iv_digest(const vector<u8>& digest) {
    array<u32, 8> iv;
    for (int i = 0; i < 8; ++i) {
        iv[i] = ((u32)digest[i * 4] << 24) | ((u32)digest[i * 4 + 1] << 16) |
            ((u32)digest[i * 4 + 2] << 8) | ((u32)digest[i * 4 + 3]);
    }
    return iv;
}

// 从给定IV继续处理，并返回最终 digest
vector<u8> forge_sm3_iv(const array<u32, 8>& IV_arr, size_t original_len_bytes, const vector<u8>& appended) {
    vector<u8> glue = sm3_padding((u64)original_len_bytes);
    size_t glue_len = glue.size();
    u64 total_len = (u64)original_len_bytes + (u64)glue_len + (u64)appended.size();

    vector<u8> suffix = appended;
    vector<u8> final_pad = sm3_padding(total_len);
    suffix.insert(suffix.end(), final_pad.begin(), final_pad.end());

    u32 V[8];
    for (int i = 0; i < 8; ++i) V[i] = IV_arr[i];

    if (suffix.size() % 64 != 0) {
        cerr << "内部错误: 后缀不是64字节的倍数\n";
        exit(1);
    }
    for (size_t off = 0; off < suffix.size(); off += 64) {
        sm3_compress_block(V, &suffix[off]);
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
    string secret = "topsecret_";
    string original_known = "userid=1001";
    vector<u8> real_msg;
    real_msg.insert(real_msg.end(), secret.begin(), secret.end());
    real_msg.insert(real_msg.end(), original_known.begin(), original_known.end());

    vector<u8> server_digest = sm3(real_msg);
    cout << "服务器哈希值: " << to_hex(server_digest) << "\n";

    size_t attacker_known_original_len = secret.size() + original_known.size();

    string append_str = ";admin=true";
    vector<u8> appended(append_str.begin(), append_str.end());

    array<u32, 8> IV = iv_digest(server_digest);
    vector<u8> forged_digest = forge_sm3_iv(IV, attacker_known_original_len, appended);
    cout << "伪造哈希值: " << to_hex(forged_digest) << "\n";

    vector<u8> glue = sm3_padding(attacker_known_original_len);
    vector<u8> forged_message;
    forged_message.insert(forged_message.end(), real_msg.begin(), real_msg.end());
    forged_message.insert(forged_message.end(), glue.begin(), glue.end());
    forged_message.insert(forged_message.end(), appended.begin(), appended.end());

    vector<u8> server_check = sm3(forged_message);
    cout << "服务器校验哈希值: " << to_hex(server_check) << "\n";

    if (server_check == forged_digest) cout << "长度扩展攻击成功。\n";
    else cout << "失败，不匹配。\n";

    return 0;
}
