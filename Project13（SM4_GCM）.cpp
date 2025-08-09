#include <iostream>
#include <cstring>
#include <vector>
#include <cstdint>

using namespace std;

typedef uint32_t u32;
typedef uint8_t u8;
typedef uint64_t u64;

const u32 FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
const u32 CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

u8 Sbox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

u32 rotl(u32 x, int n) {
    return (x << n) | (x >> (32 - n));
}

u32 Tau(u32 A) {
    u8 a[4];
    a[0] = Sbox[(A >> 24) & 0xFF];
    a[1] = Sbox[(A >> 16) & 0xFF];
    a[2] = Sbox[(A >> 8) & 0xFF];
    a[3] = Sbox[A & 0xFF];
    return (u32(a[0]) << 24) | (u32(a[1]) << 16) | (u32(a[2]) << 8) | u32(a[3]);
}

u32 T(u32 x) {
    u32 B = Tau(x);
    return B ^ rotl(B, 2) ^ rotl(B, 10) ^ rotl(B, 18) ^ rotl(B, 24);
}

u32 T_prime(u32 x) {
    u32 B = Tau(x);
    return B ^ rotl(B, 13) ^ rotl(B, 23);
}

void KeyExpansion(const u8 MK[16], u32 rk[32]) {
    u32 K[36];
    for (int i = 0; i < 4; i++) {
        K[i] = ((u32)MK[4 * i] << 24) | ((u32)MK[4 * i + 1] << 16) |
            ((u32)MK[4 * i + 2] << 8) | ((u32)MK[4 * i + 3]);
        K[i] ^= FK[i];
    }

    for (int i = 0; i < 32; i++) {
        K[i + 4] = K[i] ^ T_prime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
        rk[i] = K[i + 4];
    }
}

void sm4_encryptblock(const u8 input[16], u8 output[16], const u32 rk[32]) {
    u32 X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = ((u32)input[4 * i] << 24) | ((u32)input[4 * i + 1] << 16) |
            ((u32)input[4 * i + 2] << 8) | ((u32)input[4 * i + 3]);
    }

    for (int i = 0; i < 32; i++) {
        X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
    }

    for (int i = 0; i < 4; i++) {
        u32 x = X[35 - i];
        output[4 * i] = (x >> 24) & 0xFF;
        output[4 * i + 1] = (x >> 16) & 0xFF;
        output[4 * i + 2] = (x >> 8) & 0xFF;
        output[4 * i + 3] = x & 0xFF;
    }
}

// 解密单个块
void sm4_decryptblock(const u8 input[16], u8 output[16], const u32 rk[32]) {
    u32 rk_inv[32];
    for (int i = 0; i < 32; i++) {
        rk_inv[i] = rk[31 - i];
    }
    sm4_encryptblock(input, output, rk_inv);
}

struct u128_t {
    u64 hi;
    u64 lo;
};

u128_t bytes_to_u128_be(const u8 b[16]) {
    u128_t r;
    r.hi = 0; r.lo = 0;
    for (int i = 0; i < 8; i++) r.hi = (r.hi << 8) | b[i];
    for (int i = 8; i < 16; i++) r.lo = (r.lo << 8) | b[i];
    return r;
}

void u128_to_bytes_be(const u128_t& v, u8 out[16]) {
    u64 hi = v.hi;  
    u64 lo = v.lo;  
    for (int i = 7; i >= 0; --i) {
        out[i] = (u8)(hi & 0xFF);
        hi >>= 8;
    }

    for (int i = 15; i >= 8; --i) {
        out[i] = (u8)(lo & 0xFF);
        lo >>= 8;
    }
}
void u128_to_bytes_be2(const u128_t &v, u8 out[16]) {
    u64 hi = v.hi;
    u64 lo = v.lo;
    for (int i = 7; i >= 0; --i) {
        out[i] = (u8)(hi & 0xFF);
        hi >>= 8;
    }
    for (int i = 15; i >= 8; --i) {
        out[i] = (u8)(lo & 0xFF);
        lo >>= 8;
    }
}

u128_t xor128(const u128_t &a, const u128_t &b) {
    return u128_t{a.hi ^ b.hi, a.lo ^ b.lo};
}

u128_t shr1(const u128_t &v) {
    u128_t r;
    r.lo = (v.lo >> 1) | (v.hi << 63);
    r.hi = (v.hi >> 1);
    return r;
}

u128_t shl1(const u128_t &v) {
    u128_t r;
    r.hi = (v.hi << 1) | (v.lo >> 63);
    r.lo = (v.lo << 1);
    return r;
}

// 乘法
u128_t gf_mul(const u128_t &X, const u128_t &Y) {
    const u128_t R = { 0xE100000000000000ULL, 0x0ULL };
    u128_t V = X;
    u128_t Z = {0ULL, 0ULL};
    u128_t Ytmp = Y;

    for (int i = 0; i < 128; i++) {
        // 检查 Ytmp 的最左比特
        bool y_msb = ( (Ytmp.hi & 0x8000000000000000ULL) != 0 );
        if (y_msb) {
            Z.hi ^= V.hi;
            Z.lo ^= V.lo;
        }
        bool v_lsb = (V.lo & 1ULL) != 0;
        V = shr1(V);
        if (v_lsb) {
            V.hi ^= R.hi;
            V.lo ^= R.lo;
        }       
        Ytmp = shl1(Ytmp);
    }
    return Z;
}

u128_t GHASH(const u8 H_bytes[16], const vector<u8> &A, const vector<u8> &C) {
    u128_t H = bytes_to_u128_be(H_bytes);
    u128_t Y = {0ULL, 0ULL};

    auto process_blocks = [&](const vector<u8> &data) {
        size_t n = data.size();
        size_t blocks = (n + 15) / 16;
        for (size_t i = 0; i < blocks; i++) {
            u8 block[16] = {0};
            size_t take = min((size_t)16, n - i*16);
            memcpy(block, &data[i*16], take);
            u128_t X = bytes_to_u128_be(block);
            Y = xor128(Y, X);
            Y = gf_mul(Y, H);
        }
    };

    process_blocks(A);
    process_blocks(C);

    u8 len_block[16] = {0};
    uint64_t alen_bits = (uint64_t)A.size() * 8;
    uint64_t clen_bits = (uint64_t)C.size() * 8;
    for (int i = 0; i < 8; i++) len_block[7 - i] = (u8)((alen_bits >> (8*i)) & 0xFF);
    for (int i = 0; i < 8; i++) len_block[15 - i] = (u8)((clen_bits >> (8*i)) & 0xFF);
    u128_t Xlen = bytes_to_u128_be(len_block);
    Y = xor128(Y, Xlen);
    Y = gf_mul(Y, H);

    return Y;
}


void inc32(u8 counter[16]) {
    for (int i = 15; i >= 12; --i) {
        if (++counter[i] != 0) break;
    }
}


void build_J0(const u8 H_bytes[16], const vector<u8> &IV, u8 J0[16]) {
    if (IV.size() == 12) {
        memcpy(J0, IV.data(), 12);
        J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
    } else { 
        vector<u8> emptyAAD;
        u128_t S = GHASH(H_bytes, emptyAAD, IV);
        u128_to_bytes_be2(S, J0);
    }
}

void block_encrypt_BE(const u8 in[16], u8 out[16], const u32 rk[32]) {
    sm4_encryptblock(in, out, rk);
}

// 输出 CT  和 tag 
void SM4_GCM_Encrypt(const u8 key16[16],
                    const vector<u8> &IV,
                    const vector<u8> &AAD,
                    const vector<u8> &PT,
                    vector<u8> &CT,
                    u8 tag[16]) {
    // 1. 生成轮密钥
    u32 rk[32];
    KeyExpansion(key16, rk);

    // 2. 计算 H = E_K(0^128)
    u8 zero_block[16] = {0};
    u8 H_bytes[16];
    sm4_encryptblock(zero_block, H_bytes, rk);

    // 计算 J0
    u8 J0[16];
    build_J0(H_bytes, IV, J0);

    // 用 CTR 生成密文：计数器从 inc(J0) 开始
    u8 counter[16];
    memcpy(counter, J0, 16);
    inc32(counter); 

    size_t n = PT.size();
    CT.resize(n);
    u8 stream_block[16];
    size_t blocks = (n + 15) / 16;
    for (size_t i = 0; i < blocks; i++) {
        block_encrypt_BE(counter, stream_block, rk);
        size_t take = min((size_t)16, n - i*16);
        for (size_t j = 0; j < take; j++) {
            CT[i*16 + j] = PT[i*16 + j] ^ stream_block[j];
        }
        inc32(counter);
    }

    //计算 Tag
    u128_t S = GHASH(H_bytes, AAD, CT);
    u8 S_bytes[16];
    u128_to_bytes_be2(S, S_bytes);

    u8 E_J0[16];
    sm4_encryptblock(J0, E_J0, rk);
    for (int i = 0; i < 16; i++) tag[i] = E_J0[i] ^ S_bytes[i];
}

// SM4-GCM 解密并验证。返回 true 表示 MAC 验证通过，CT 解密到 PT_out
bool sm4_GCM_decrypt(const u8 key16[16],
                    const vector<u8> &IV,
                    const vector<u8> &AAD,
                    const vector<u8> &CT,
                    const u8 tag[16],
                    vector<u8> &PT_out) {
    u32 rk[32];
    KeyExpansion(key16, rk);

    u8 zero_block[16] = {0};
    u8 H_bytes[16];
    sm4_encryptblock(zero_block, H_bytes, rk);

    u8 J0[16];
    build_J0(H_bytes, IV, J0);

    u8 counter[16];
    memcpy(counter, J0, 16);
    inc32(counter);

    size_t n = CT.size();
    PT_out.resize(n);
    u8 stream_block[16];
    size_t blocks = (n + 15) / 16;
    for (size_t i = 0; i < blocks; i++) {
        block_encrypt_BE(counter, stream_block, rk);
        size_t take = min((size_t)16, n - i*16);
        for (size_t j = 0; j < take; j++) {
            PT_out[i*16 + j] = CT[i*16 + j] ^ stream_block[j];
        }
        inc32(counter);
    }

    u128_t S = GHASH(H_bytes, AAD, CT);
    u8 S_bytes[16];
    u128_to_bytes_be2(S, S_bytes);

    u8 E_J0[16];
    sm4_encryptblock(J0, E_J0, rk);
    u8 expected_tag[16];
    for (int i = 0; i < 16; i++) expected_tag[i] = E_J0[i] ^ S_bytes[i];

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (expected_tag[i] ^ tag[i]);
    return diff == 0;
}

int main() {
    u8 key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };

    vector<u8> IV = { 0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07, 0x08,0x09,0x0A,0x0B }; // 12 bytes
    vector<u8> AAD = { 0x30,0x31,0x32 }; 
    vector<u8> PT = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };

    vector<u8> CT;
    u8 tag[16];

    SM4_GCM_Encrypt(key, IV, AAD, PT, CT, tag);

    cout << "C  : ";
    for (size_t i = 0; i < CT.size(); ++i) printf("%02X ", CT[i]);
    cout << "\nTag: ";
    for (int i = 0; i < 16; ++i) printf("%02X ", tag[i]);
    cout << endl;

    // 解密验证
    vector<u8> PT_rec;
    bool ok = sm4_GCM_decrypt(key, IV, AAD, CT, tag, PT_rec);
    cout << " tag valid? " << (ok ? "YES" : "NO") << endl;
    if (ok) {
        cout << "recovered P: ";
        for (size_t i = 0; i < PT_rec.size(); ++i) printf("%02X ", PT_rec[i]);
        cout << endl;
    }

    return 0;
}