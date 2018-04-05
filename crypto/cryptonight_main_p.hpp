/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  */
#pragma once

#include <memory.h>
#include <stdio.h>

#include "../common.h"
#include "cryptonight.h"
#include "cryptonight_aesni_p.hpp"
#include "cryptonight_softaes_p.hpp"
#include "cryptonight_common_p.hpp"
#include "keccak.hpp"
#include "extrahashes_p.hpp"

#if !defined(_LP64) && !defined(_WIN64)
#error You are trying to do a 32-bit build. This will all end in tears. I know it.
#endif

extern void(*const extra_hashes[4])(const void *, char *);

template<size_t ITERATIONS, size_t MEM, bool SOFT_AES, bool PREFETCH>
TARGETS("avx2,avx,popcnt,fma,fma4,bmi,bmi2,xop,sse4.2,sse4.1,sse4a,ssse3,sse3,default")
OPTIMIZE("no-align-loops")
ALIGN(64) void cryptonight_hash(const void* input, size_t len, void* output, cryptonight_ctx* ctx0)
{
    keccak<200>((const uint8_t *)input, len, ctx0->hash_state);

    // Optim - 99% time boundary
    if(SOFT_AES)
        soft_cn_explode_scratchpad<MEM, PREFETCH>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);
    else
        cn_explode_scratchpad<MEM, PREFETCH>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);

    uint8_t* l0 = ctx0->long_state;
    uint64_t* h0 = (uint64_t*)ctx0->hash_state;

    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);

    uint64_t idx0 = h0[0] ^ h0[4];

    // Optim - 90% time boundary
    for(size_t i = 0; i < ITERATIONS; i++)
    {
        __m128i cx;
        cx = _mm_load_si128((__m128i *)&l0[idx0 & 0x1FFFF0]);

        if(SOFT_AES)
            cx = soft_aesenc(cx, _mm_set_epi64x(ah0, al0));
        else
            cx = _mm_aesenc_si128(cx, _mm_set_epi64x(ah0, al0));

        _mm_store_si128((__m128i *)&l0[idx0 & 0x1FFFF0], _mm_xor_si128(bx0, cx));
        uint64_t idx1 = _mm_cvtsi128_si64(cx);
        bx0 = cx;

        if(PREFETCH)
            _mm_prefetch((const char*)&l0[idx1 & 0x1FFFF0], _MM_HINT_T0);

        uint64_t hi, lo, cl, ch;
        cl = ((uint64_t*)&l0[idx1 & 0x1FFFF0])[0];
        ch = ((uint64_t*)&l0[idx1 & 0x1FFFF0])[1];

        lo = _umul128(idx1, cl, &hi);

        al0 += hi;
        ah0 += lo;
        ((uint64_t*)&l0[idx1 & 0x1FFFF0])[0] = al0;
        ((uint64_t*)&l0[idx1 & 0x1FFFF0])[1] = ah0;
        ah0 ^= ch;
        al0 ^= cl;
        idx0 = al0;

        if(PREFETCH)
            _mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T0);
    }

    // Optim - 90% time boundary
    if(SOFT_AES)
        soft_cn_implode_scratchpad<MEM, PREFETCH>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
    else
        cn_implode_scratchpad<MEM, PREFETCH>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);

    // Optim - 99% time boundary

    keccakf<24>((uint64_t*)ctx0->hash_state);
    extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, (char*)output);
}

// This lovely creation will do 2 cn hashes at a time. We have plenty of space on silicon
// to fit temporary vars for two contexts. Function will read len*2 from input and write 64 bytes to output
// We are still limited by L3 cache, so doubling will only work with CPUs where we have more than 2MB to core (Xeons)
template<size_t ITERATIONS, size_t MEM, bool SOFT_AES, bool PREFETCH>
TARGETS("avx2,avx,popcnt,fma,fma4,bmi,bmi2,xop,sse4.2,sse4.1,sse4a,ssse3,sse3,default")
OPTIMIZE("no-align-loops")
ALIGN(64) void cryptonight_double_hash(const void* input, size_t len, void* output, cryptonight_ctx* __restrict ctx0, cryptonight_ctx* __restrict ctx1)
{
    keccak<200>((const uint8_t *)input, len, ctx0->hash_state);
    keccak<200>((const uint8_t *)input+len, len, ctx1->hash_state);

    // Optim - 99% time boundary
    if(SOFT_AES){
        soft_cn_explode_scratchpad<MEM, PREFETCH>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);
        soft_cn_explode_scratchpad<MEM, PREFETCH>((__m128i*)ctx1->hash_state, (__m128i*)ctx1->long_state);
    }else{
        cn_explode_scratchpad<MEM, PREFETCH>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);
        cn_explode_scratchpad<MEM, PREFETCH>((__m128i*)ctx1->hash_state, (__m128i*)ctx1->long_state);
    }

    uint8_t* l0 = ctx0->long_state;
    uint64_t* h0 = (uint64_t*)ctx0->hash_state;
    uint8_t* l1 = ctx1->long_state;
    uint64_t* h1 = (uint64_t*)ctx1->hash_state;

    uint64_t axl0 = h0[0] ^ h0[4];
    uint64_t axh0 = h0[1] ^ h0[5];
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    uint64_t axl1 = h1[0] ^ h1[4];
    uint64_t axh1 = h1[1] ^ h1[5];
    __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);

    uint64_t idx0 = h0[0] ^ h0[4];
    uint64_t idx1 = h1[0] ^ h1[4];

    // Optim - 90% time boundary
    for (size_t i = 0; i < ITERATIONS; i++)
    {
        __m128i cx;
        cx = _mm_load_si128((__m128i *)&l0[idx0 & 0x1FFFF0]);

        if(SOFT_AES)
            cx = soft_aesenc(cx, _mm_set_epi64x(axh0, axl0));
        else
            cx = _mm_aesenc_si128(cx, _mm_set_epi64x(axh0, axl0));

        _mm_store_si128((__m128i *)&l0[idx0 & 0x1FFFF0], _mm_xor_si128(bx0, cx));
        idx0 = _mm_cvtsi128_si64(cx);
        bx0 = cx;

        if(PREFETCH)
            _mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T0);

        cx = _mm_load_si128((__m128i *)&l1[idx1 & 0x1FFFF0]);

        if(SOFT_AES)
            cx = soft_aesenc(cx, _mm_set_epi64x(axh1, axl1));
        else
            cx = _mm_aesenc_si128(cx, _mm_set_epi64x(axh1, axl1));

        _mm_store_si128((__m128i *)&l1[idx1 & 0x1FFFF0], _mm_xor_si128(bx1, cx));
        idx1 = _mm_cvtsi128_si64(cx);
        bx1 = cx;

        if(PREFETCH)
            _mm_prefetch((const char*)&l1[idx1 & 0x1FFFF0], _MM_HINT_T0);

        uint64_t hi, lo, cl, ch;
        cl = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[0];
        ch = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[1];

        lo = _umul128(idx0, cl, &hi);

        axl0 += hi;
        axh0 += lo;
        ((uint64_t*)&l0[idx0 & 0x1FFFF0])[0] = axl0;
        ((uint64_t*)&l0[idx0 & 0x1FFFF0])[1] = axh0;
        axh0 ^= ch;
        axl0 ^= cl;
        idx0 = axl0;

        if(PREFETCH)
            _mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T0);

        cl = ((uint64_t*)&l1[idx1 & 0x1FFFF0])[0];
        ch = ((uint64_t*)&l1[idx1 & 0x1FFFF0])[1];

        lo = _umul128(idx1, cl, &hi);

        axl1 += hi;
        axh1 += lo;
        ((uint64_t*)&l1[idx1 & 0x1FFFF0])[0] = axl1;
        ((uint64_t*)&l1[idx1 & 0x1FFFF0])[1] = axh1;
        axh1 ^= ch;
        axl1 ^= cl;
        idx1 = axl1;

        if(PREFETCH)
            _mm_prefetch((const char*)&l1[idx1 & 0x1FFFF0], _MM_HINT_T0);
    }

    // Optim - 90% time boundary
    if(SOFT_AES){
        soft_cn_implode_scratchpad<MEM, PREFETCH>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
        soft_cn_implode_scratchpad<MEM, PREFETCH>((__m128i*)ctx1->long_state, (__m128i*)ctx1->hash_state);
    }else{
        cn_implode_scratchpad<MEM, PREFETCH>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
        cn_implode_scratchpad<MEM, PREFETCH>((__m128i*)ctx1->long_state, (__m128i*)ctx1->hash_state);
    }

    // Optim - 99% time boundary

    keccakf<24>((uint64_t*)ctx0->hash_state);
    extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, (char*)output);
    keccakf<24>((uint64_t*)ctx1->hash_state);
    extra_hashes[ctx1->hash_state[0] & 3](ctx1->hash_state, (char*)output + 32);
}
