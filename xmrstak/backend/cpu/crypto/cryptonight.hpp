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

#include "variant4_random_math.h"

struct extra_ctx_r
{
    uint64_t height = 0;
    // the buffer must be able to hold NUM_INSTRUCTIONS_MAX and a termination instruction
    V4_Instruction code[NUM_INSTRUCTIONS_MAX + 1];
};

struct cryptonight_ctx
{
    uint8_t hash_state[224]; // Need only 200, explicit align
    uint8_t* long_state;
    uint8_t ctx_info[24]; //Use some of the extra memory for flags (0=hugepages, 1=mlocked)
    extra_ctx_r cn_r_ctx;
} ALIGN(64);

struct alloc_msg
{
    const char* warning;
};

size_t cryptonight_init(size_t use_fast_mem, size_t use_mlock, alloc_msg* msg);
cryptonight_ctx* cryptonight_alloc_ctx(size_t use_fast_mem, size_t use_mlock, alloc_msg* msg);
void cryptonight_free_ctx(cryptonight_ctx* ctx);
