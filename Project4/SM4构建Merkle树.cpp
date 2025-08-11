// sm3_merkle_rfc6962_fixed.cpp
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
#include <algorithm>
#include <unordered_map>
#include <stdexcept>
#include <limits>

using namespace std;

using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

// ----------------------- SM3 实现（完整） -----------------------
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

vector<u8> sm3(const vector<u8>& msg) {
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

vector<u8> concat_bytes(const vector<u8>& a, const vector<u8>& b) {
    vector<u8> r; r.reserve(a.size() + b.size());
    r.insert(r.end(), a.begin(), a.end());
    r.insert(r.end(), b.begin(), b.end());
    return r;
}

// 叶子哈希 = H(0x00 || 叶子数据)
vector<u8> leaf_hash(const vector<u8>& leaf) {
    vector<u8> tmp;
    tmp.reserve(1 + leaf.size());
    tmp.push_back(0x00);
    tmp.insert(tmp.end(), leaf.begin(), leaf.end());
    return sm3(tmp);
}

// 节点哈希 = H(0x01 || 左子节点 || 右子节点)
vector<u8> node_hash(const vector<u8>& left, const vector<u8>& right) {
    vector<u8> tmp;
    tmp.reserve(1 + left.size() + right.size());
    tmp.push_back(0x01);
    tmp.insert(tmp.end(), left.begin(), left.end());
    tmp.insert(tmp.end(), right.begin(), right.end());
    return sm3(tmp);
}

// 小于 n 的最大 2 的幂
size_t largest_pow2(size_t n) {
    if (n < 2) return 0;
    size_t k = 1;
    while ((k << 1) < n) k <<= 1;
    return k;
}


struct MerkleTree {
    vector<vector<u8>> leaves;
    vector<vector<u8>> leaf_hashes;

    unordered_map<u64, vector<u8>> cache;

    MerkleTree(const vector<vector<u8>>& in_leaves) {
        leaves = in_leaves;
        leaf_hashes.resize(leaves.size());
        for (size_t i = 0; i < leaves.size(); ++i) {
            leaf_hashes[i] = leaf_hash(leaves[i]);
        }
        cache.reserve(leaves.size() * 2 + 10);
    }

    static u64 cache_key(size_t start, size_t n) {
        return ((u64)start << 32) | (u64)n;
    }

    // 递归计算并缓存子树哈希；范围: [start, start+n)
    vector<u8> subtree_hash(size_t start, size_t n) {
        if (n == 0) return vector<u8>();
        u64 key = cache_key(start, n);
        auto it = cache.find(key);
        if (it != cache.end()) return it->second;

        vector<u8> h;
        if (n == 1) {
            h = leaf_hashes[start];
        }
        else {
            size_t k = largest_pow2(n);
            auto left = subtree_hash(start, k);
            auto right = subtree_hash(start + k, n - k);
            h = node_hash(left, right);
        }
        cache.emplace(key, h);
        return h;
    }

    // 根哈希
    vector<u8> root() {
        if (leaf_hashes.empty()) return vector<u8>();
        return subtree_hash(0, leaf_hashes.size());
    }

    // 为指定叶子索引构建存在性证明路径
    void build_path(size_t start, size_t n, size_t idx, vector<vector<u8>>& out_path) {
        if (n == 1) return;
        size_t k = largest_pow2(n);
        if (idx < k) {
            // 在左子树
            build_path(start, k, idx, out_path);
            auto right_root = subtree_hash(start + k, n - k);
            out_path.push_back(right_root);
        }
        else {
            // 在右子树
            build_path(start + k, n - k, idx - k, out_path);
            auto left_root = subtree_hash(start, k);
            out_path.push_back(left_root);
        }
    }

    vector<vector<u8>> inclusion_proof(size_t idx) {
        if (idx >= leaf_hashes.size()) throw runtime_error("索引超出范围");
        vector<vector<u8>> path;
        if (leaf_hashes.empty()) return path;
        build_path(0, leaf_hashes.size(), idx, path);
        return path;
    }

    // 验证存在性证明：给定叶子字节、索引、证明叶子总数、期望根哈希
    static bool verify_inclusion(const vector<u8>& leaf,
        size_t idx,
        const vector<vector<u8>>& proof,
        size_t n,
        const vector<u8>& expected_root) {
        if (n == 0) return expected_root.empty();
        vector<u8> cur = leaf_hash(leaf);
        size_t node_index = idx;
        for (size_t i = 0; i < proof.size(); ++i) {
            const auto& sibling = proof[i];
            if ((node_index & 1) == 0) {
                // 当前节点是左子节点
                cur = node_hash(cur, sibling);
            }
            else {
                // 当前节点是右子节点
                cur = node_hash(sibling, cur);
            }
            node_index >>= 1;
        }
        return cur == expected_root;
    }

    // 不存在性证明（假设叶子按字典序排序）
    struct NonInclusionProof {
        bool found_equal;
        size_t equal_index;
        int64_t left_idx;
        vector<vector<u8>> left_proof;
        int64_t right_idx;
        vector<vector<u8>> right_proof;

        NonInclusionProof()
            : found_equal(false),
            equal_index(std::numeric_limits<size_t>::max()),
            left_idx(-1),
            right_idx(-1)
        {
        }
    };

    NonInclusionProof noninclusion_proof_sorted(const vector<u8>& value) {
        NonInclusionProof ret;
        auto cmp = [](const vector<u8>& a, const vector<u8>& b) {
            return a < b;
            };
        auto it = lower_bound(leaves.begin(), leaves.end(), value, cmp);
        size_t pos = it - leaves.begin();
        if (it != leaves.end() && *it == value) {
            ret.found_equal = true;
            ret.equal_index = pos;
            return ret;
        }
        if (pos > 0) {
            ret.left_idx = (int64_t)(pos - 1);
            ret.left_proof = inclusion_proof(pos - 1);
        }
        if (pos < leaves.size()) {
            ret.right_idx = (int64_t)pos;
            ret.right_proof = inclusion_proof(pos);
        }
        return ret;
    }
};


int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    // 构造 100000 个叶子，保证按字典序排序以便做不存在性证明
    vector<vector<u8>> leaves;
    leaves.reserve(100000);
    for (int i = 0; i < 100000; ++i) {
        string s = "leaf-" + to_string(i);
        vector<u8> v(s.begin(), s.end());
        leaves.push_back(move(v));
    }

    MerkleTree mt(leaves);
    auto root = mt.root();
    cout << "根哈希 = " << to_hex(root) << "\n";

    // 测试存在性证明
    size_t idx = 12345;
    auto proof = mt.inclusion_proof(idx);
    cout << "索引 " << idx << " 的存在性证明包含 " << proof.size() << " 个兄弟哈希\n";
    for (size_t i = 0; i < min<size_t>(proof.size(), 4); ++i) {
        cout << "  兄弟[" << i << "] = " << to_hex(proof[i]) << "\n";
    }

    bool ok = MerkleTree::verify_inclusion(leaves[idx], idx, proof, leaves.size(), root);
    cout << "验证存在性证明 -> " << (ok ? "成功" : "失败") << "\n";

    // 测试不存在性证明
    string q = "leaf-1000000";
    vector<u8> qbytes(q.begin(), q.end());
    auto nproof = mt.noninclusion_proof_sorted(qbytes);
    if (nproof.found_equal) {
        cout << "值存在于索引 " << nproof.equal_index << "\n";
    }
    else {
        cout << "值不存在; 左邻索引 = " << nproof.left_idx << ", 右邻索引 = " << nproof.right_idx << "\n";
        if (nproof.left_idx != -1) {
            cout << " 左邻证明大小 = " << nproof.left_proof.size() << "\n";
            cout << " 左邻叶子索引 " << nproof.left_idx << " 值 = ";
            cout << string(mt.leaves[nproof.left_idx].begin(), mt.leaves[nproof.left_idx].end()) << "\n";
        }
        if (nproof.right_idx != -1) {
            cout << " 右邻证明大小 = " << nproof.right_proof.size() << "\n";
            cout << " 右邻叶子索引 " << nproof.right_idx << " 值 = ";
            cout << string(mt.leaves[nproof.right_idx].begin(), mt.leaves[nproof.right_idx].end()) << "\n";
        }
    }

    return 0;
}
