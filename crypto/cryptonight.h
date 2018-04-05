#pragma once
#include "../common.h"
#include <stddef.h>
#include <inttypes.h>

#if defined(__GNUC__)
# if defined(_WIN64)
#  include <intrin.h>
# else
#  include <x86intrin.h>
# endif
# define _umul128 _xmr_umul128
# define _mm256_set_m128i(v0, v1)  _mm256_insertf128_si256(_mm256_castsi128_si256(v1), (v0), 1)
#else
# include <intrin.h>
#endif // __GNUC__

#define MEMORY  2097152

typedef struct {
    uint8_t hash_state[200];
    uint8_t ctx_info[2]; //Use some of the extra memory for flags (0=hugepages, 1=mlocked)
    uint8_t* long_state;
} ALIGN(64) cryptonight_ctx;

typedef struct {
    const char* warning;
} alloc_msg;

size_t cryptonight_init(size_t use_fast_mem, size_t use_mlock, alloc_msg* msg);
cryptonight_ctx* cryptonight_alloc_ctx(size_t use_fast_mem, size_t use_mlock, alloc_msg* msg);
void cryptonight_free_ctx(cryptonight_ctx* ctx);
