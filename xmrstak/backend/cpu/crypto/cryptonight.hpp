#pragma once
#include "../common.h"
#include <stddef.h>
#include <inttypes.h>

#if defined(__GNUC__)
# if defined(_WIN64)
#  include <intrin.h>
# else
#  include <x86intrin.h>
#  define _umul128 _xmr_umul128
# endif
#else
# include <intrin.h>
#endif // __GNUC__

typedef struct {
    uint8_t hash_state[224];
    uint8_t* long_state;
    uint8_t ctx_info[24]; //Use some of the extra memory for flags (0=hugepages, 1=mlocked)
} ALIGN(64) cryptonight_ctx;

typedef struct {
    const char* warning;
} alloc_msg;

size_t cryptonight_init(size_t use_fast_mem, size_t use_mlock, alloc_msg* msg);
cryptonight_ctx* cryptonight_alloc_ctx(size_t use_fast_mem, size_t use_mlock, alloc_msg* msg);
void cryptonight_free_ctx(cryptonight_ctx* ctx);
