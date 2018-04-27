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
#include "xmrstak/backend/cryptonight.hpp"
#include "cryptonight.hpp"
#include "cryptonight_aesni_p.hpp"
#include "cryptonight_softaes_p.hpp"
#include "cryptonight_common_p.hpp"
#include "keccak.hpp"
#include "extrahashes_p.hpp"

#if !defined(_LP64) && !defined(_WIN64)
#error You are trying to do a 32-bit build. This will all end in tears. I know it.
#endif

extern void(*const extra_hashes[4])(const void *, char *);

//TARGETS("arch=haswell,default")
//TARGETS("arch=k8-sse3,arch=barcelona,arch=bdver1,arch=bdver2,arch=bdver4,arch=btver1,arch=btver2,arch=core2,arch=nehalem,arch=westmere,arch=sandybridge,arch=ivybridge,arch=haswell,arch=broadwell,arch=skylake,arch=bonnell,arch=silvermont,arch=knl,default")
//OPTIMIZE("no-align-loops")
//TARGETS("avx2,avx,popcnt,fma,fma4,bmi,bmi2,xop,sse4.2,sse4.1,sse4a,ssse3,sse3,default")
template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
TARGETS("avx,fma,bmi,sse4.1,sse3,default")
OPTIMIZE("no-align-loops")
ALIGN(64) void cryptonight_hash(const void* input, size_t len, void* output, cryptonight_ctx* ctx){
    constexpr size_t MASK = cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
    constexpr size_t MEM = cn_select_memory<ALGO>();


    if ((ALGO == cryptonight_monero || ALGO == cryptonight_aeon) && len < 43){
        memset(output, 0, 32);
        return;
    }

    keccak<200>((const uint8_t *)input, len, ctx->hash_state);

    uint64_t monero_const;
    if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon){
        monero_const  = *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + 35);
        monero_const ^= *(reinterpret_cast<const uint64_t*>(ctx->hash_state) + 24);
    }

    // Optim - 99% time boundary
    if(SOFT_AES)
        soft_cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx->hash_state, (__m128i*)ctx->long_state);
    else
        cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx->hash_state, (__m128i*)ctx->long_state);

    uint8_t* l0 = ctx->long_state;
    uint64_t* h0 = (uint64_t*)ctx->hash_state;

    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);

    uint64_t idx0 = h0[0] ^ h0[4];

    // Optim - 90% time boundary
    for(size_t i = 0; i < ITERATIONS; i++)
    {
        __m128i cx;
        cx = _mm_load_si128((__m128i *)&l0[idx0 & MASK]);

        if(SOFT_AES)
            cx = soft_aesenc(cx, _mm_set_epi64x(ah0, al0));
        else
            cx = _mm_aesenc_si128(cx, _mm_set_epi64x(ah0, al0));


        if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon)
            if(SOFT_AES)
                soft_cryptonight_monero_tweak((uint64_t*)&l0[idx0 & MASK], _mm_xor_si128(bx0, cx));
            else
                cryptonight_monero_tweak((uint64_t*)&l0[idx0 & MASK], _mm_xor_si128(bx0, cx));
        else
            _mm_store_si128((__m128i *)&l0[idx0 & MASK], _mm_xor_si128(bx0, cx));

        uint64_t idx1 = _mm_cvtsi128_si64(cx);
        bx0 = cx;

        if(PREFETCH)
            _mm_prefetch((const char*)&l0[idx1 & MASK], _MM_HINT_T0);

        uint64_t hi, lo, cl, ch;
        cl = ((uint64_t*)&l0[idx1 & MASK])[0];
        ch = ((uint64_t*)&l0[idx1 & MASK])[1];

        lo = _umul128(idx1, cl, &hi);
        ah0 += lo;

        al0 += hi;
        ((uint64_t*)&l0[idx1 & MASK])[0] = al0;
        al0 ^= cl;

        if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon)
            ((uint64_t*)&l0[idx1 & MASK])[1] = ah0 ^ monero_const;
        else
            ((uint64_t*)&l0[idx1 & MASK])[1] = ah0;

        ah0 ^= ch;

        if(ALGO == cryptonight_heavy) {
            int64_t n  = ((int64_t*)&l0[al0 & MASK])[0];
            int32_t d  = ((int32_t*)&l0[al0 & MASK])[2];
            int64_t q = n / (d | 0x5);

            ((int64_t*)&l0[al0 & MASK])[0] = n ^ q;
            idx0 = d ^ q;
        }else{
            idx0 = al0;
        }

        if(PREFETCH)
            _mm_prefetch((const char*)&l0[idx0 & MASK], _MM_HINT_T0);
    }

    // Optim - 90% time boundary
    if(SOFT_AES)
        soft_cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx->long_state, (__m128i*)ctx->hash_state);
    else
        cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx->long_state, (__m128i*)ctx->hash_state);

    // Optim - 99% time boundary

    keccakf<24>((uint64_t*)ctx->hash_state);
    extra_hashes[ctx->hash_state[0] & 3](ctx->hash_state, (char*)output);
}

// This lovely creation will do 2 cn hashes at a time. We have plenty of space on silicon
// to fit temporary vars for two contexts. Function will read len*2 from input and write 64 bytes to output
// We are still limited by L3 cache, so doubling will only work with CPUs where we have more than 2MB to core (Xeons)
template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
TARGETS("avx,fma,bmi,sse4.1,sse3,default")
OPTIMIZE("no-align-loops")
ALIGN(64) void cryptonight_double_hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx){
    constexpr size_t MASK = cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
    constexpr size_t MEM = cn_select_memory<ALGO>();

    if ((ALGO == cryptonight_monero || ALGO == cryptonight_aeon) && len < 43){
        memset(output, 0, 64);
        return;
    }

    keccak<200>((const uint8_t *)input, len, ctx[0]->hash_state);
    keccak<200>((const uint8_t *)input+len, len, ctx[1]->hash_state);

    uint64_t monero_const[2];
    if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon) {
        monero_const[0]  = *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + 35);
        monero_const[0] ^= *(reinterpret_cast<const uint64_t*>(ctx[0]->hash_state) + 24);
        monero_const[1]  = *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + 35 + len);
        monero_const[1] ^= *(reinterpret_cast<const uint64_t*>(ctx[0]->hash_state) + 24);
    }

    // Optim - 99% time boundary
    if(SOFT_AES){
        soft_cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[0]->hash_state, (__m128i*)ctx[0]->long_state);
        soft_cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[1]->hash_state, (__m128i*)ctx[1]->long_state);
    }else{
        cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[0]->hash_state, (__m128i*)ctx[0]->long_state);
        cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[1]->hash_state, (__m128i*)ctx[1]->long_state);
    }

    uint8_t* l0 = ctx[0]->long_state;
    uint64_t* h0 = (uint64_t*)ctx[0]->hash_state;
    uint8_t* l1 = ctx[1]->long_state;
    uint64_t* h1 = (uint64_t*)ctx[1]->hash_state;

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
        cx = _mm_load_si128((__m128i *)&l0[idx0 & MASK]);

        if(SOFT_AES)
            cx = soft_aesenc(cx, _mm_set_epi64x(axh0, axl0));
        else
            cx = _mm_aesenc_si128(cx, _mm_set_epi64x(axh0, axl0));

        if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon)
            if(SOFT_AES)
                soft_cryptonight_monero_tweak((uint64_t*)&l0[idx0 & MASK], _mm_xor_si128(bx0, cx));
            else
                cryptonight_monero_tweak((uint64_t*)&l0[idx0 & MASK], _mm_xor_si128(bx0, cx));
        else
            _mm_store_si128((__m128i *)&l0[idx0 & MASK], _mm_xor_si128(bx0, cx));

        idx0 = _mm_cvtsi128_si64(cx);
        bx0 = cx;

        if(PREFETCH)
            _mm_prefetch((const char*)&l0[idx0 & MASK], _MM_HINT_T0);

        cx = _mm_load_si128((__m128i *)&l1[idx1 & MASK]);

        if(SOFT_AES)
            cx = soft_aesenc(cx, _mm_set_epi64x(axh1, axl1));
        else
            cx = _mm_aesenc_si128(cx, _mm_set_epi64x(axh1, axl1));

        if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon)
            if(SOFT_AES)
                soft_cryptonight_monero_tweak((uint64_t*)&l1[idx1 & MASK], _mm_xor_si128(bx1, cx));
            else
                cryptonight_monero_tweak((uint64_t*)&l1[idx1 & MASK], _mm_xor_si128(bx1, cx));
        else
            _mm_store_si128((__m128i *)&l1[idx1 & MASK], _mm_xor_si128(bx1, cx));

        idx1 = _mm_cvtsi128_si64(cx);
        bx1 = cx;

        if(PREFETCH)
            _mm_prefetch((const char*)&l1[idx1 & MASK], _MM_HINT_T0);

        uint64_t hi, lo, cl, ch;
        cl = ((uint64_t*)&l0[idx0 & MASK])[0];
        ch = ((uint64_t*)&l0[idx0 & MASK])[1];

        lo = _umul128(idx0, cl, &hi);

        axl0 += hi;
        axh0 += lo;
        ((uint64_t*)&l0[idx0 & MASK])[0] = axl0;

        if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon)
            ((uint64_t*)&l0[idx0 & MASK])[1] = axh0 ^ monero_const[0];
        else
            ((uint64_t*)&l0[idx0 & MASK])[1] = axh0;

        axh0 ^= ch;
        axl0 ^= cl;
        idx0 = axl0;

        if(ALGO == cryptonight_heavy) {
            int64_t n  = ((int64_t*)&l0[idx0 & MASK])[0];
            int32_t d  = ((int32_t*)&l0[idx0 & MASK])[2];
            int64_t q = n / (d | 0x5);

            ((int64_t*)&l0[idx0 & MASK])[0] = n ^ q;
            idx0 = d ^ q;
        }

        if(PREFETCH)
            _mm_prefetch((const char*)&l0[idx0 & MASK], _MM_HINT_T0);

        cl = ((uint64_t*)&l1[idx1 & MASK])[0];
        ch = ((uint64_t*)&l1[idx1 & MASK])[1];

        lo = _umul128(idx1, cl, &hi);

        axl1 += hi;
        axh1 += lo;
        ((uint64_t*)&l1[idx1 & MASK])[0] = axl1;

        if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon)
            ((uint64_t*)&l1[idx1 & MASK])[1] = axh1 ^ monero_const[1];
        else
            ((uint64_t*)&l1[idx1 & MASK])[1] = axh1;

        axh1 ^= ch;
        axl1 ^= cl;
        idx1 = axl1;

        if(ALGO == cryptonight_heavy) {
            int64_t n  = ((int64_t*)&l1[idx1 & MASK])[0];
            int32_t d  = ((int32_t*)&l1[idx1 & MASK])[2];
            int64_t q = n / (d | 0x5);

            ((int64_t*)&l1[idx1 & MASK])[0] = n ^ q;
            idx1 = d ^ q;
        }

        if(PREFETCH)
            _mm_prefetch((const char*)&l1[idx1 & MASK], _MM_HINT_T0);
    }

    // Optim - 90% time boundary
    if(SOFT_AES){
        soft_cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[0]->long_state, (__m128i*)ctx[0]->hash_state);
        soft_cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[1]->long_state, (__m128i*)ctx[1]->hash_state);
    }else{
        cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[0]->long_state, (__m128i*)ctx[0]->hash_state);
        cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[1]->long_state, (__m128i*)ctx[1]->hash_state);
    }

    // Optim - 99% time boundary

    keccakf<24>((uint64_t*)ctx[0]->hash_state);
    extra_hashes[ctx[0]->hash_state[0] & 3](ctx[0]->hash_state, (char*)output);
    keccakf<24>((uint64_t*)ctx[1]->hash_state);
    extra_hashes[ctx[1]->hash_state[0] & 3](ctx[1]->hash_state, (char*)output + 32);
}


#define CN_STEP1(a, b, c, l, ptr, idx)                          \
        ptr = (__m128i *)&l[idx & MASK];                        \
        if(PREFETCH)                                            \
                _mm_prefetch((const char*)ptr, _MM_HINT_T0);    \
        c = _mm_load_si128(ptr);

#define CN_STEP2(a, b, c, l, ptr, idx)                          \
        if(SOFT_AES)                                            \
                c = soft_aesenc(c, a);                          \
        else                                                    \
                c = _mm_aesenc_si128(c, a);                     \
        b = _mm_xor_si128(b, c);                                \
        if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon) \
            if(SOFT_AES) \
                soft_cryptonight_monero_tweak((uint64_t*)ptr, b); \
            else \
                cryptonight_monero_tweak((uint64_t*)ptr, b); \
        else \
                _mm_store_si128(ptr, b);\

#define CN_STEP3(a, b, c, l, ptr, idx)                          \
        idx = _mm_cvtsi128_si64(c);                             \
        ptr = (__m128i *)&l[idx & MASK];                        \
        if(PREFETCH)                                            \
                _mm_prefetch((const char*)ptr, _MM_HINT_T0);    \
        b = _mm_load_si128(ptr);

#define CN_STEP4(a, b, c, l, mc, ptr, idx)                              \
        lo = _umul128(idx, _mm_cvtsi128_si64(b), &hi);          \
        a = _mm_add_epi64(a, _mm_set_epi64x(lo, hi));           \
        if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon) \
                _mm_store_si128(ptr, _mm_xor_si128(a, mc)); \
        else \
                _mm_store_si128(ptr, a);\
        a = _mm_xor_si128(a, b); \
        idx = _mm_cvtsi128_si64(a);     \
        if(ALGO == cryptonight_heavy) \
        { \
                int64_t n  = ((int64_t*)&l[idx & MASK])[0]; \
                int32_t d  = ((int32_t*)&l[idx & MASK])[2]; \
                int64_t q = n / (d | 0x5); \
                ((int64_t*)&l[idx & MASK])[0] = n ^ q; \
                idx = d ^ q; \
        }

#define CONST_INIT(ctx, n) \
        __m128i mc##n = _mm_set_epi64x(*reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + n * len + 35) ^ \
        *(reinterpret_cast<const uint64_t*>((ctx)->hash_state) + 24), 0);

// This lovelier creation will do 3 cn hashes at a time.
template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
OPTIMIZE("no-align-loops")
ALIGN(64) void cryptonight_triple_hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
{
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        if((ALGO == cryptonight_monero || ALGO == cryptonight_aeon) && len < 43)
        {
                memset(output, 0, 32 * 3);
                return;
        }

        for (size_t i = 0; i < 3; i++)
        {
                keccak<200>((const uint8_t *)input + len * i, len, ctx[i]->hash_state);
                if(SOFT_AES)
                    soft_cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
                else
                    cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
        }

        CONST_INIT(ctx[0], 0);
        CONST_INIT(ctx[1], 1);
        CONST_INIT(ctx[2], 2);

        uint8_t* l0 = ctx[0]->long_state;
        uint64_t* h0 = (uint64_t*)ctx[0]->hash_state;
        uint8_t* l1 = ctx[1]->long_state;
        uint64_t* h1 = (uint64_t*)ctx[1]->hash_state;
        uint8_t* l2 = ctx[2]->long_state;
        uint64_t* h2 = (uint64_t*)ctx[2]->hash_state;

        __m128i ax0 = _mm_set_epi64x(h0[1] ^ h0[5], h0[0] ^ h0[4]);
        __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
        __m128i ax1 = _mm_set_epi64x(h1[1] ^ h1[5], h1[0] ^ h1[4]);
        __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
        __m128i ax2 = _mm_set_epi64x(h2[1] ^ h2[5], h2[0] ^ h2[4]);
        __m128i bx2 = _mm_set_epi64x(h2[3] ^ h2[7], h2[2] ^ h2[6]);
        __m128i cx0 = _mm_set_epi64x(0, 0);
        __m128i cx1 = _mm_set_epi64x(0, 0);
        __m128i cx2 = _mm_set_epi64x(0, 0);

        uint64_t idx0, idx1, idx2;
        idx0 = _mm_cvtsi128_si64(ax0);
        idx1 = _mm_cvtsi128_si64(ax1);
        idx2 = _mm_cvtsi128_si64(ax2);

        for (size_t i = 0; i < ITERATIONS/2; i++)
        {
                uint64_t hi, lo;
                __m128i *ptr0, *ptr1, *ptr2;

                // EVEN ROUND
                CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
                CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
                CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);

                CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
                CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
                CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);

                CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
                CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
                CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);

                CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
                CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
                CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);

                // ODD ROUND
                CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
                CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
                CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);

                CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
                CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
                CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);

                CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
                CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
                CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);

                CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
                CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
                CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
        }

        for (size_t i = 0; i < 3; i++)
        {
                if(SOFT_AES){
                    soft_cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
                }else{
                    cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
                }
                keccakf<24>((uint64_t*)ctx[i]->hash_state);
                extra_hashes[ctx[i]->hash_state[0] & 3](ctx[i]->hash_state, (char*)output + 32 * i);
        }
}

// This even lovelier creation will do 4 cn hashes at a time.
template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
OPTIMIZE("no-align-loops")
ALIGN(64) void cryptonight_quad_hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
{
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        if((ALGO == cryptonight_monero || ALGO == cryptonight_aeon) && len < 43)
        {
                memset(output, 0, 32 * 4);
                return;
        }

        for (size_t i = 0; i < 4; i++)
        {
                keccak<200>((const uint8_t *)input + len * i, len, ctx[i]->hash_state);
                if(SOFT_AES)
                    soft_cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
                else
                    cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
        }

        CONST_INIT(ctx[0], 0);
        CONST_INIT(ctx[1], 1);
        CONST_INIT(ctx[2], 2);
        CONST_INIT(ctx[3], 3);

        uint8_t* l0 = ctx[0]->long_state;
        uint64_t* h0 = (uint64_t*)ctx[0]->hash_state;
        uint8_t* l1 = ctx[1]->long_state;
        uint64_t* h1 = (uint64_t*)ctx[1]->hash_state;
        uint8_t* l2 = ctx[2]->long_state;
        uint64_t* h2 = (uint64_t*)ctx[2]->hash_state;
        uint8_t* l3 = ctx[3]->long_state;
        uint64_t* h3 = (uint64_t*)ctx[3]->hash_state;

        __m128i ax0 = _mm_set_epi64x(h0[1] ^ h0[5], h0[0] ^ h0[4]);
        __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
        __m128i ax1 = _mm_set_epi64x(h1[1] ^ h1[5], h1[0] ^ h1[4]);
        __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
        __m128i ax2 = _mm_set_epi64x(h2[1] ^ h2[5], h2[0] ^ h2[4]);
        __m128i bx2 = _mm_set_epi64x(h2[3] ^ h2[7], h2[2] ^ h2[6]);
        __m128i ax3 = _mm_set_epi64x(h3[1] ^ h3[5], h3[0] ^ h3[4]);
        __m128i bx3 = _mm_set_epi64x(h3[3] ^ h3[7], h3[2] ^ h3[6]);
        __m128i cx0 = _mm_set_epi64x(0, 0);
        __m128i cx1 = _mm_set_epi64x(0, 0);
        __m128i cx2 = _mm_set_epi64x(0, 0);
        __m128i cx3 = _mm_set_epi64x(0, 0);

        uint64_t idx0, idx1, idx2, idx3;
        idx0 = _mm_cvtsi128_si64(ax0);
        idx1 = _mm_cvtsi128_si64(ax1);
        idx2 = _mm_cvtsi128_si64(ax2);
        idx3 = _mm_cvtsi128_si64(ax3);

        for (size_t i = 0; i < ITERATIONS/2; i++)
        {
                uint64_t hi, lo;
                __m128i *ptr0, *ptr1, *ptr2, *ptr3;

                // EVEN ROUND
                CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
                CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
                CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);
                CN_STEP1(ax3, bx3, cx3, l3, ptr3, idx3);

                CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
                CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
                CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);
                CN_STEP2(ax3, bx3, cx3, l3, ptr3, idx3);

                CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
                CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
                CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);
                CN_STEP3(ax3, bx3, cx3, l3, ptr3, idx3);

                CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
                CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
                CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);
                CN_STEP4(ax3, bx3, cx3, l3, mc3, ptr3, idx3);

                // ODD ROUND
                CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
                CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
                CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);
                CN_STEP1(ax3, cx3, bx3, l3, ptr3, idx3);

                CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
                CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
                CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);
                CN_STEP2(ax3, cx3, bx3, l3, ptr3, idx3);

                CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
                CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
                CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);
                CN_STEP3(ax3, cx3, bx3, l3, ptr3, idx3);

                CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
                CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
                CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
                CN_STEP4(ax3, cx3, bx3, l3, mc3, ptr3, idx3);
        }

        for (size_t i = 0; i < 4; i++)
        {
                if(SOFT_AES){
                    soft_cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
                }else{
                    cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
                }
                keccakf<24>((uint64_t*)ctx[i]->hash_state);
                extra_hashes[ctx[i]->hash_state[0] & 3](ctx[i]->hash_state, (char*)output + 32 * i);
        }
}

// This most lovely creation will do 5 cn hashes at a time.
template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
OPTIMIZE("no-align-loops")
ALIGN(64) void cryptonight_penta_hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
{
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        if((ALGO == cryptonight_monero || ALGO == cryptonight_aeon) && len < 43)
        {
                memset(output, 0, 32 * 5);
                return;
        }

        for (size_t i = 0; i < 5; i++)
        {
                keccak<200>((const uint8_t *)input + len * i, len, ctx[i]->hash_state);
                if(SOFT_AES)
                    soft_cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
                else
                    cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
        }

        CONST_INIT(ctx[0], 0);
        CONST_INIT(ctx[1], 1);
        CONST_INIT(ctx[2], 2);
        CONST_INIT(ctx[3], 3);
        CONST_INIT(ctx[4], 4);

        uint8_t* l0 = ctx[0]->long_state;
        uint64_t* h0 = (uint64_t*)ctx[0]->hash_state;
        uint8_t* l1 = ctx[1]->long_state;
        uint64_t* h1 = (uint64_t*)ctx[1]->hash_state;
        uint8_t* l2 = ctx[2]->long_state;
        uint64_t* h2 = (uint64_t*)ctx[2]->hash_state;
        uint8_t* l3 = ctx[3]->long_state;
        uint64_t* h3 = (uint64_t*)ctx[3]->hash_state;
        uint8_t* l4 = ctx[4]->long_state;
        uint64_t* h4 = (uint64_t*)ctx[4]->hash_state;

        __m128i ax0 = _mm_set_epi64x(h0[1] ^ h0[5], h0[0] ^ h0[4]);
        __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
        __m128i ax1 = _mm_set_epi64x(h1[1] ^ h1[5], h1[0] ^ h1[4]);
        __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
        __m128i ax2 = _mm_set_epi64x(h2[1] ^ h2[5], h2[0] ^ h2[4]);
        __m128i bx2 = _mm_set_epi64x(h2[3] ^ h2[7], h2[2] ^ h2[6]);
        __m128i ax3 = _mm_set_epi64x(h3[1] ^ h3[5], h3[0] ^ h3[4]);
        __m128i bx3 = _mm_set_epi64x(h3[3] ^ h3[7], h3[2] ^ h3[6]);
        __m128i ax4 = _mm_set_epi64x(h4[1] ^ h4[5], h4[0] ^ h4[4]);
        __m128i bx4 = _mm_set_epi64x(h4[3] ^ h4[7], h4[2] ^ h4[6]);
        __m128i cx0 = _mm_set_epi64x(0, 0);
        __m128i cx1 = _mm_set_epi64x(0, 0);
        __m128i cx2 = _mm_set_epi64x(0, 0);
        __m128i cx3 = _mm_set_epi64x(0, 0);
        __m128i cx4 = _mm_set_epi64x(0, 0);

        uint64_t idx0, idx1, idx2, idx3, idx4;
        idx0 = _mm_cvtsi128_si64(ax0);
        idx1 = _mm_cvtsi128_si64(ax1);
        idx2 = _mm_cvtsi128_si64(ax2);
        idx3 = _mm_cvtsi128_si64(ax3);
        idx4 = _mm_cvtsi128_si64(ax4);

        for (size_t i = 0; i < ITERATIONS/2; i++)
        {
                uint64_t hi, lo;
                __m128i *ptr0, *ptr1, *ptr2, *ptr3, *ptr4;

                // EVEN ROUND
                CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
                CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
                CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);
                CN_STEP1(ax3, bx3, cx3, l3, ptr3, idx3);
                CN_STEP1(ax4, bx4, cx4, l4, ptr4, idx4);

                CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
                CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
                CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);
                CN_STEP2(ax3, bx3, cx3, l3, ptr3, idx3);
                CN_STEP2(ax4, bx4, cx4, l4, ptr4, idx4);

                CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
                CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
                CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);
                CN_STEP3(ax3, bx3, cx3, l3, ptr3, idx3);
                CN_STEP3(ax4, bx4, cx4, l4, ptr4, idx4);

                CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
                CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
                CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);
                CN_STEP4(ax3, bx3, cx3, l3, mc3, ptr3, idx3);
                CN_STEP4(ax4, bx4, cx4, l4, mc4, ptr4, idx4);

                // ODD ROUND
                CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
                CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
                CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);
                CN_STEP1(ax3, cx3, bx3, l3, ptr3, idx3);
                CN_STEP1(ax4, cx4, bx4, l4, ptr4, idx4);

                CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
                CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
                CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);
                CN_STEP2(ax3, cx3, bx3, l3, ptr3, idx3);
                CN_STEP2(ax4, cx4, bx4, l4, ptr4, idx4);

                CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
                CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
                CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);
                CN_STEP3(ax3, cx3, bx3, l3, ptr3, idx3);
                CN_STEP3(ax4, cx4, bx4, l4, ptr4, idx4);

                CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
                CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
                CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
                CN_STEP4(ax3, cx3, bx3, l3, mc3, ptr3, idx3);
                CN_STEP4(ax4, cx4, bx4, l4, mc4, ptr4, idx4);
        }

        for (size_t i = 0; i < 5; i++)
        {
                if(SOFT_AES){
                    soft_cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
                }else{
                    cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
                }
                keccakf<24>((uint64_t*)ctx[i]->hash_state);
                extra_hashes[ctx[i]->hash_state[0] & 3](ctx[i]->hash_state, (char*)output + 32 * i);
        }
}
