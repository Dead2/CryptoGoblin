#include "cn_gpu.hpp"

template<bool PREFETCH, xmrstak_algo_id ALGO>
void cn_explode_scratchpad_gpu(const uint8_t* input, uint8_t* output, const xmrstak_algo& algo)
{
    constexpr size_t hash_size = 200; // 25x8 bytes
    alignas(128) uint64_t hash[25];
    const size_t mem = algo.Mem();

    for (uint64_t i = 0; i < mem / 512; i++)
    {
        memcpy(hash, input, hash_size);
        hash[0] ^= i;

        keccakf_24(hash);
        memcpy(output, hash, 160);
        output+=160;

        keccakf_24(hash);
        memcpy(output, hash, 176);
        output+=176;

        keccakf_24(hash);
        memcpy(output, hash, 176);
        output+=176;

        if(PREFETCH)
        {
            _mm_prefetch((const char*)output - 512, _MM_HINT_T2);
            _mm_prefetch((const char*)output - 384, _MM_HINT_T2);
            _mm_prefetch((const char*)output - 256, _MM_HINT_T2);
            _mm_prefetch((const char*)output - 128, _MM_HINT_T2);
        }
    }
}

struct Cryptonight_hash_gpu
{
    static constexpr size_t N = 1;

    template<xmrstak_algo_id ALGO, bool SOFT_AES, bool PREFETCH>
    static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx, const xmrstak_algo& algo)
    {
        keccak_200((const uint8_t *)input, len, ctx[0]->hash_state);
        cn_explode_scratchpad_gpu<PREFETCH, ALGO>(ctx[0]->hash_state, ctx[0]->long_state, algo);

        if(cngpu_check_avx2())
            cn_gpu_inner_avx(ctx[0]->hash_state, ctx[0]->long_state, algo);
        else
            cn_gpu_inner_ssse3(ctx[0]->hash_state, ctx[0]->long_state, algo);

        cn_implode_scratchpad<ALGO, PREFETCH>((__m128i*)ctx[0]->long_state, (__m128i*)ctx[0]->hash_state, algo);
        keccakf_24((uint64_t*)ctx[0]->hash_state);
        memcpy(output, ctx[0]->hash_state, 32);
    }
};
