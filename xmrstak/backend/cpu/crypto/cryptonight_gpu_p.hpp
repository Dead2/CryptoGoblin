#include "cn_gpu.hpp"

template<size_t MEM, bool PREFETCH, xmrstak_algo ALGO>
void cn_explode_scratchpad_gpu(const uint8_t* input, uint8_t* output)
{
    constexpr size_t hash_size = 200; // 25x8 bytes
    alignas(128) uint64_t hash[25];

    for (uint64_t i = 0; i < MEM / 512; i++)
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

    template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
    static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
    {
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        keccak_200((const uint8_t *)input, len, ctx[0]->hash_state);
        cn_explode_scratchpad_gpu<MEM, PREFETCH, ALGO>(ctx[0]->hash_state, ctx[0]->long_state);

        if(cngpu_check_avx2())
            cn_gpu_inner_avx<ITERATIONS, MASK>(ctx[0]->hash_state, ctx[0]->long_state);
        else
            cn_gpu_inner_ssse3<ITERATIONS, MASK>(ctx[0]->hash_state, ctx[0]->long_state);

        cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH, ALGO>((__m128i*)ctx[0]->long_state, (__m128i*)ctx[0]->hash_state);
        keccakf_24((uint64_t*)ctx[0]->hash_state);
        memcpy(output, ctx[0]->hash_state, 32);
    }
};
