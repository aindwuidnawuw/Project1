#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <immintrin.h>   

typedef uint32_t u32;
typedef uint8_t  u8;

typedef struct {
    u32 rk[32];
} sm4_key;

static const u32 FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
static const u32 CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

static const u8 SBOX[256] = {
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


static inline u32 rotl32(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

static inline u32 sm4_sbox_scalar(u32 x) {
    u8 b0 = (x >> 24) & 0xFF;
    u8 b1 = (x >> 16) & 0xFF;
    u8 b2 = (x >> 8) & 0xFF;
    u8 b3 = x & 0xFF;
    return ((u32)SBOX[b0] << 24) | ((u32)SBOX[b1] << 16) |
        ((u32)SBOX[b2] << 8) | ((u32)SBOX[b3]);
}

static inline u32 sm4_l(u32 x) {
    return x ^ rotl32(x, 2) ^ rotl32(x, 10) ^ rotl32(x, 18) ^ rotl32(x, 24);
}

static inline u32 sm4_t(u32 x) {
    return sm4_l(sm4_sbox_scalar(x));
}

void sm4_keyinit(u8* key, sm4_key* sm4_key) {
    u32 K[4];
    for (int i = 0; i < 4; i++) {
        int j = 4 * i;
        K[i] = ((u32)key[j + 0] << 24) |
            ((u32)key[j + 1] << 16) |
            ((u32)key[j + 2] << 8) |
            ((u32)key[j + 3]);
        K[i] ^= FK[i];
    }
    for (int i = 0; i < 32; i++) {
        u32 tmp = K[1] ^ K[2] ^ K[3] ^ CK[i];
        tmp = sm4_sbox_scalar(tmp);
        tmp = tmp ^ rotl32(tmp, 13) ^ rotl32(tmp, 23);
        K[0] ^= tmp;
        sm4_key->rk[i] = K[0];
        u32 t = K[0]; K[0] = K[1]; K[1] = K[2]; K[2] = K[3]; K[3] = t;
    }
}


static void sm4_encrypt_block_scalar(const u8 in[16], u8 out[16], const sm4_key* key) {
    u32 x[4];
    for (int i = 0; i < 4; i++) {
        x[i] = ((u32)in[4 * i + 0] << 24) | ((u32)in[4 * i + 1] << 16) |
            ((u32)in[4 * i + 2] << 8) | ((u32)in[4 * i + 3]);
    }
    for (int i = 0; i < 32; i++) {
        u32 tmp = x[1] ^ x[2] ^ x[3] ^ key->rk[i];
        u32 t = sm4_t(tmp);
        u32 nx = x[0] ^ t;
        x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = nx;
    }
    u32 y[4] = { x[3], x[2], x[1], x[0] };
    for (int i = 0; i < 4; i++) {
        out[4 * i + 0] = (y[i] >> 24) & 0xFF;
        out[4 * i + 1] = (y[i] >> 16) & 0xFF;
        out[4 * i + 2] = (y[i] >> 8) & 0xFF;
        out[4 * i + 3] = y[i] & 0xFF;
    }
}

//AES-NI x4并行实现
#define MM_PACK0_EPI32(a,b,c,d) _mm_unpacklo_epi64(_mm_unpacklo_epi32((a),(b)), _mm_unpacklo_epi32((c),(d)))
#define MM_PACK1_EPI32(a,b,c,d) _mm_unpackhi_epi64(_mm_unpacklo_epi32((a),(b)), _mm_unpacklo_epi32((c),(d)))
#define MM_PACK2_EPI32(a,b,c,d) _mm_unpacklo_epi64(_mm_unpackhi_epi32((a),(b)), _mm_unpackhi_epi32((c),(d)))
#define MM_PACK3_EPI32(a,b,c,d) _mm_unpackhi_epi64(_mm_unpackhi_epi32((a),(b)), _mm_unpackhi_epi32((c),(d)))

#define MM_XOR2(a,b)        _mm_xor_si128((a),(b))
#define MM_XOR3(a,b,c)      MM_XOR2((a), MM_XOR2((b),(c)))
#define MM_XOR4(a,b,c,d)    MM_XOR2((a), MM_XOR3((b),(c),(d)))
#define MM_XOR5(a,b,c,d,e)  MM_XOR2((a), MM_XOR4((b),(c),(d),(e)))
#define MM_XOR6(a,b,c,d,e,f) MM_XOR2((a), MM_XOR5((b),(c),(d),(e),(f)))
#define MM_ROTL_EPI32(a,n)  MM_XOR2(_mm_slli_epi32((a),(n)), _mm_srli_epi32((a), 32-(n)))

// 仿射变换 + AESENCLAST 得到 SM4 SBox
static __m128i MulMatrix(__m128i x, __m128i higherMask, __m128i lowerMask) {
    __m128i andMask = _mm_set1_epi32(0x0f0f0f0f);
    __m128i lo = _mm_and_si128(x, andMask);
    __m128i hi = _mm_and_si128(_mm_srli_epi16(x, 4), andMask);
    __m128i t1 = _mm_shuffle_epi8(lowerMask, lo);
    __m128i t2 = _mm_shuffle_epi8(higherMask, hi);
    return _mm_xor_si128(t1, t2);
}
static __m128i MulMatrixATA(__m128i x) {
    __m128i higherMask = _mm_set_epi8(0x14, 0x07, 0xc6, 0xd5, 0x6c, 0x7f, 0xbe, 0xad, 0xb9, 0xaa, 0x6b, 0x78, 0xc1, 0xd2, 0x13, 0x00);
    __m128i lowerMask = _mm_set_epi8(0xd8, 0xb8, 0xfa, 0x9a, 0xc5, 0xa5, 0xe7, 0x87, 0x5f, 0x3f, 0x7d, 0x1d, 0x42, 0x22, 0x60, 0x00);
    return MulMatrix(x, higherMask, lowerMask);
}
static __m128i MulMatrixTA(__m128i x) {
    __m128i higherMask = _mm_set_epi8(0x22, 0x58, 0x1a, 0x60, 0x02, 0x78, 0x3a, 0x40, 0x62, 0x18, 0x5a, 0x20, 0x42, 0x38, 0x7a, 0x00);
    __m128i lowerMask = _mm_set_epi8(0xe2, 0x28, 0x95, 0x5f, 0x69, 0xa3, 0x1e, 0xd4, 0x36, 0xfc, 0x41, 0x8b, 0xbd, 0x77, 0xca, 0x00);
    return MulMatrix(x, higherMask, lowerMask);
}
static inline __m128i AddTC(__m128i x) { return _mm_xor_si128(x, _mm_set1_epi8(0x23)); }
static inline __m128i AddATAC(__m128i x) { return _mm_xor_si128(x, _mm_set1_epi8(0x3b)); }

static __m128i sm4_sbox(__m128i x) {
    //把每个 32-bit 内字节位置调到仿射流程所需的顺序
    __m128i MASK = _mm_set_epi8(0x03, 0x06, 0x09, 0x0c, 0x0f, 0x02, 0x05, 0x08, 0x0b, 0x0e, 0x01, 0x04, 0x07, 0x0a, 0x0d, 0x00);
    x = _mm_shuffle_epi8(x, MASK);
    x = AddTC(MulMatrixTA(x));
    x = _mm_aesenclast_si128(x, _mm_setzero_si128());
    x = AddATAC(MulMatrixATA(x));
    return x;
}


static void sm4_aesni(const u8* in, u8* out, const sm4_key* key, int enc) {
    __m128i X[4], Tmp[4];
    Tmp[0] = _mm_loadu_si128((const __m128i*)(in + 16 * 0));
    Tmp[1] = _mm_loadu_si128((const __m128i*)(in + 16 * 1));
    Tmp[2] = _mm_loadu_si128((const __m128i*)(in + 16 * 2));
    Tmp[3] = _mm_loadu_si128((const __m128i*)(in + 16 * 3));
    // 把 4 组的第 0/1/2/3 个 32-bit word 分别打包到 X[0..3]
    X[0] = MM_PACK0_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[1] = MM_PACK1_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[2] = MM_PACK2_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[3] = MM_PACK3_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    // 转换端序
    const __m128i vindex = _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
    X[0] = _mm_shuffle_epi8(X[0], vindex);
    X[1] = _mm_shuffle_epi8(X[1], vindex);
    X[2] = _mm_shuffle_epi8(X[2], vindex);
    X[3] = _mm_shuffle_epi8(X[3], vindex);

    for (int i = 0; i < 32; i++) {
        __m128i rk = _mm_set1_epi32(enc ? key->rk[31 - i] : key->rk[i]);
        Tmp[0] = MM_XOR4(X[1], X[2], X[3], rk);
        Tmp[0] = sm4_sbox(Tmp[0]);
        Tmp[0] = MM_XOR6(X[0], Tmp[0],
            MM_ROTL_EPI32(Tmp[0], 2),
            MM_ROTL_EPI32(Tmp[0], 10),
            MM_ROTL_EPI32(Tmp[0], 18),
            MM_ROTL_EPI32(Tmp[0], 24));
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = Tmp[0];
    }
    // 端序还原
    X[0] = _mm_shuffle_epi8(X[0], vindex);
    X[1] = _mm_shuffle_epi8(X[1], vindex);
    X[2] = _mm_shuffle_epi8(X[2], vindex);
    X[3] = _mm_shuffle_epi8(X[3], vindex);
    // 反序并写回 4 组输出
    _mm_storeu_si128((__m128i*)(out + 16 * 0), MM_PACK0_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)(out + 16 * 1), MM_PACK1_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)(out + 16 * 2), MM_PACK2_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)(out + 16 * 3), MM_PACK3_EPI32(X[3], X[2], X[1], X[0]));
}

static inline void sm4_aesni_encrypt(const u8* plaintext, u8* ciphertext, const sm4_key* key) {
    sm4_aesni(plaintext, ciphertext, key, 0);
}
static inline void sm4_aesni_decrypt(const u8* ciphertext, u8* plaintext, const sm4_key* key) {
    sm4_aesni(ciphertext, plaintext, key, 1);
}


static void print_block(const char* tag, const u8* p) {
    printf("%s", tag);
    for (int i = 0; i < 16; i++) printf("%02x%s", p[i], i == 15 ? "" : " ");
    printf("\n");
}
int main(void) {
    u8 key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    u8 in[16 * 4] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
        // block1..block3 = 全零
        0
    };
    u8 out[16 * 4], dec[16 * 4];

    sm4_key sk;
    sm4_keyinit(key, &sk);

    // 标量单块
    u8 c_ref[16];
    sm4_encrypt_block_scalar(in, c_ref, &sk);
    print_block("Scalar Cipher (block0): ", c_ref);

    // 并行加密
    sm4_aesni_encrypt(in, out, &sk);

    printf("C:\n");
    for (int j = 0; j < 4; j++) {
        char tag[16]; snprintf(tag, sizeof(tag), "\t[%d] ", j);
        print_block(tag, out + 16 * j);
    }

    //并行解密
    sm4_aesni_decrypt(out, dec, &sk);

    printf("P:\n");
    for (int j = 0; j < 4; j++) {
        char tag[16]; snprintf(tag, sizeof(tag), "\t[%d] ", j);
        print_block(tag, dec + 16 * j);
    }

    if (memcmp(dec, in, sizeof(in)) == 0 && memcmp(out, out, sizeof(out)) == 0) {
        puts("decrypt( encrypt(plains) ) == plains");
    }
    else {
        puts("ERROR!");
    }
    return 0;
}