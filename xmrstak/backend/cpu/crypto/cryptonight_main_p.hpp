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


#define CN_INIT_SINGLE \
    if((ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_stellite) && len < 43) \
    { \
        memset(output, 0, 32 * N); \
        return; \
    }

#define CN_INIT(n, monero_const, l0, ax0, bx0, idx0, ptr0) \
    keccak<200>((const uint8_t *)input + len * n, len, ctx[n]->hash_state); \
    uint64_t monero_const; \
    if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_stellite) \
    { \
        monero_const =  *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + len * n + 35); \
        monero_const ^=  *(reinterpret_cast<const uint64_t*>(ctx[n]->hash_state) + 24); \
    } \
    /* Optim - 99% time boundary */ \
    if(SOFT_AES) \
        soft_cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[n]->hash_state, (__m128i*)ctx[n]->long_state); \
    else \
        cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[n]->hash_state, (__m128i*)ctx[n]->long_state); \
    \
    __m128i ax0; \
    uint64_t idx0; \
    __m128i bx0; \
    uint8_t* l0 = ctx[n]->long_state; \
    { \
        uint64_t* h0 = (uint64_t*)ctx[n]->hash_state; \
        idx0 = h0[0] ^ h0[4]; \
        if(PREFETCH) \
            _mm_prefetch((const char*)&l0[idx0 & MASK], _MM_HINT_T0); \
        ax0 = _mm_set_epi64x(h0[1] ^ h0[5], idx0); \
        bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]); \
    } \
    __m128i *ptr0

#define CN_STEP1(n, monero_const, l0, ax0, bx0, idx0, ptr0, cx) \
    __m128i cx; \
    ptr0 = (__m128i *)&l0[idx0 & MASK]; \
    cx = _mm_load_si128(ptr0); \
    if(SOFT_AES) \
        cx = soft_aesenc(cx, ax0); \
    else \
        cx = _mm_aesenc_si128(cx, ax0); \

#define CN_STEP2(n, monero_const, l0, ax0, bx0, idx0, ptr0, cx) \
    if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_stellite) \
        if(SOFT_AES) \
            soft_cryptonight_monero_tweak<ALGO>((uint64_t*)ptr0, _mm_xor_si128(bx0, cx)); \
        else \
            cryptonight_monero_tweak<ALGO>((uint64_t*)ptr0, _mm_xor_si128(bx0, cx)); \
    else \
        _mm_store_si128((__m128i *)ptr0, _mm_xor_si128(bx0, cx)); \
    idx0 = _mm_cvtsi128_si64(cx); \
    \
    ptr0 = (__m128i *)&l0[idx0 & MASK]; \
    if(PREFETCH) \
        _mm_prefetch((const char*)ptr0, _MM_HINT_T0); \
    bx0 = cx; \

#define CN_STEP3(n, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0) \
    uint64_t lo, cl, ch; \
    uint64_t al0 = _mm_cvtsi128_si64(ax0); \
    uint64_t ah0 = ((uint64_t*)&ax0)[1]; \
    cl = ((uint64_t*)ptr0)[0]; \
    ch = ((uint64_t*)ptr0)[1]; \
    \
    { \
        uint64_t hi; \
        lo = _umul128(idx0, cl, &hi); \
        ah0 += lo; \
        al0 += hi; \
    } \
    ((uint64_t*)ptr0)[0] = al0; \
    if(PREFETCH) \
        _mm_prefetch((const char*)ptr0, _MM_HINT_T0)

#define CN_STEP4(n, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0) \
    if (ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_stellite) \
    { \
        if (ALGO == cryptonight_ipbc) \
            ((uint64_t*)ptr0)[1] = ah0 ^ monero_const ^ ((uint64_t*)ptr0)[0]; \
        else \
            ((uint64_t*)ptr0)[1] = ah0 ^ monero_const; \
    } \
    else \
        ((uint64_t*)ptr0)[1] = ah0; \
    al0 ^= cl; \
    ah0 ^= ch; \
    ax0 = _mm_set_epi64x(ah0, al0);

#define CN_STEP5(n, monero_const, l0, ax0, bx0, idx0, ptr0, al0) \
    if(ALGO == cryptonight_heavy) \
    { \
        ptr0 = (__m128i *)&l0[idx0 & MASK]; \
        int64_t u  = ((int64_t*)ptr0)[0]; \
        int32_t d  = ((int32_t*)ptr0)[2]; \
        int64_t q = u / (d | 0x5); \
        \
        ((int64_t*)ptr0)[0] = u ^ q; \
        idx0 = d ^ q; \
    } else { \
        idx0 = al0; \
    }

#define CN_FINALIZE(n) \
    /* Optim - 90% time boundary */ \
    if(SOFT_AES) \
        soft_cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[n]->long_state, (__m128i*)ctx[n]->hash_state); \
    else \
        cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[n]->long_state, (__m128i*)ctx[n]->hash_state); \
    /* Optim - 99% time boundary */ \
    keccakf<24>((uint64_t*)ctx[n]->hash_state); \
    extra_hashes[ctx[n]->hash_state[0] & 3](ctx[n]->hash_state, (char*)output + 32 * n)

//! defer the evaluation of an macro
#ifndef _MSC_VER
#   define CN_DEFER(...) __VA_ARGS__
#else
#   define CN_EMPTY(...)
#   define CN_DEFER(...) __VA_ARGS__ CN_EMPTY()
#endif

//! execute the macro f with the passed arguments
#define CN_EXEC(f,...) CN_DEFER(f)(__VA_ARGS__)

/** add append n to all arguments and keeps n as first argument
 *
 * @param n number which is appended to the arguments (expect the first argument n)
 *
 * @code{.cpp}
 * CN_ENUM_2(1, foo, bar)
 * // is transformed to
 * 1, foo1, bar1
 * @endcode
 */
#define CN_ENUM_0(n, ...) n
#define CN_ENUM_1(n, x1) n, x1 ## n
#define CN_ENUM_2(n, x1, x2) n, x1 ## n, x2 ## n
#define CN_ENUM_3(n, x1, x2, x3) n, x1 ## n, x2 ## n, x3 ## n
#define CN_ENUM_4(n, x1, x2, x3, x4) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n
#define CN_ENUM_5(n, x1, x2, x3, x4, x5) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n
#define CN_ENUM_6(n, x1, x2, x3, x4, x5, x6) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n
#define CN_ENUM_7(n, x1, x2, x3, x4, x5, x6, x7) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n
#define CN_ENUM_8(n, x1, x2, x3, x4, x5, x6, x7, x8) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n
#define CN_ENUM_9(n, x1, x2, x3, x4, x5, x6, x7, x8, x9) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n
#define CN_ENUM_10(n, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n, x10 ## n
#define CN_ENUM_11(n, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n, x10 ## n, x11 ## n
#define CN_ENUM_12(n, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n, x10 ## n, x11 ## n, x12 ## n

/** repeat a macro call multiple times
 *
 * @param n number of arguments followed after f
 * @param f name of the macro which should be executed
 * @param ... n parameter which name will get appended by a unique number
 *
 * @code{.cpp}
 * REPEAT_2(2, f, foo, bar)
 * // is transformed to
 * f(0, foo0, bar); f(1, foo1, bar1)
 * @endcode
 */
#define REPEAT_1(n, f, ...) CN_EXEC(f, CN_ENUM_ ## n(0, __VA_ARGS__))
#define REPEAT_2(n, f, ...) CN_EXEC(f, CN_ENUM_ ## n(0, __VA_ARGS__)); CN_EXEC(f, CN_ENUM_ ## n(1, __VA_ARGS__))
#define REPEAT_3(n, f, ...) CN_EXEC(f, CN_ENUM_ ## n(0, __VA_ARGS__)); CN_EXEC(f, CN_ENUM_ ## n(1, __VA_ARGS__)); CN_EXEC(f, CN_ENUM_ ## n(2, __VA_ARGS__))
#define REPEAT_4(n, f, ...) CN_EXEC(f, CN_ENUM_ ## n(0, __VA_ARGS__)); CN_EXEC(f, CN_ENUM_ ## n(1, __VA_ARGS__)); CN_EXEC(f, CN_ENUM_ ## n(2, __VA_ARGS__)); CN_EXEC(f, CN_ENUM_ ## n(3, __VA_ARGS__))
#define REPEAT_5(n, f, ...) CN_EXEC(f, CN_ENUM_ ## n(0, __VA_ARGS__)); CN_EXEC(f, CN_ENUM_ ## n(1, __VA_ARGS__)); CN_EXEC(f, CN_ENUM_ ## n(2, __VA_ARGS__)); CN_EXEC(f, CN_ENUM_ ## n(3, __VA_ARGS__)); CN_EXEC(f, CN_ENUM_ ## n(4, __VA_ARGS__))

template< size_t N>
struct Cryptonight_hash;

template< >
struct Cryptonight_hash<1>
{
    static constexpr size_t N = 1;

    template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
    static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
    {
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        CN_INIT_SINGLE;
        REPEAT_1(6, CN_INIT, monero_const, l0, ax0, bx0, idx0, ptr0);

        // Optim - 90% time boundary
        for(size_t i = 0; i < ITERATIONS; i++)
        {
            REPEAT_1(7, CN_STEP1, monero_const, l0, ax0, bx0, idx0, ptr0, cx);
            REPEAT_1(7, CN_STEP2, monero_const, l0, ax0, bx0, idx0, ptr0, cx);
            REPEAT_1(11, CN_STEP3, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0);
            REPEAT_1(11, CN_STEP4, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0);
            REPEAT_1(7, CN_STEP5, monero_const, l0, ax0, bx0, idx0, ptr0, al0);
        }
        REPEAT_1(0, CN_FINALIZE);
    }
};

template< >
struct Cryptonight_hash<2>
{
    static constexpr size_t N = 2;
    template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
    static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
    {
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        CN_INIT_SINGLE;
        REPEAT_2(6, CN_INIT, monero_const, l0, ax0, bx0, idx0, ptr0);

        // Optim - 90% time boundary
        for(size_t i = 0; i < ITERATIONS; i++)
        {
            REPEAT_2(7, CN_STEP1, monero_const, l0, ax0, bx0, idx0, ptr0, cx);
            REPEAT_2(7, CN_STEP2, monero_const, l0, ax0, bx0, idx0, ptr0, cx);
            REPEAT_2(11, CN_STEP3, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0);
            REPEAT_2(11, CN_STEP4, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0);
            REPEAT_2(7, CN_STEP5, monero_const, l0, ax0, bx0, idx0, ptr0, al0);
        }
        REPEAT_2(0, CN_FINALIZE);
    }
};

template< >
struct Cryptonight_hash<3>
{
    static constexpr size_t N = 3;

    template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
    static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
    {
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        CN_INIT_SINGLE;
        REPEAT_3(6, CN_INIT, monero_const, l0, ax0, bx0, idx0, ptr0);

        // Optim - 90% time boundary
        for(size_t i = 0; i < ITERATIONS; i++)
        {
            REPEAT_3(7, CN_STEP1, monero_const, l0, ax0, bx0, idx0, ptr0, cx);
            REPEAT_3(7, CN_STEP2, monero_const, l0, ax0, bx0, idx0, ptr0, cx);
            REPEAT_3(11, CN_STEP3, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0);
            REPEAT_3(11, CN_STEP4, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0);
            REPEAT_3(7, CN_STEP5, monero_const, l0, ax0, bx0, idx0, ptr0, al0);
        }

        REPEAT_3(0, CN_FINALIZE);
    }
};

template< >
struct Cryptonight_hash<4>
{
    static constexpr size_t N = 4;

    template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
    static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
    {
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        CN_INIT_SINGLE;
        REPEAT_4(6, CN_INIT, monero_const, l0, ax0, bx0, idx0, ptr0);

        // Optim - 90% time boundary
        for(size_t i = 0; i < ITERATIONS; i++)
        {
            REPEAT_4(7, CN_STEP1, monero_const, l0, ax0, bx0, idx0, ptr0, cx);
            REPEAT_4(7, CN_STEP2, monero_const, l0, ax0, bx0, idx0, ptr0, cx);
            REPEAT_4(11, CN_STEP3, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0);
            REPEAT_4(11, CN_STEP4, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0);
            REPEAT_4(7, CN_STEP5, monero_const, l0, ax0, bx0, idx0, ptr0, al0);
        }

        REPEAT_4(0, CN_FINALIZE);
    }
};

template< >
struct Cryptonight_hash<5>
{
    static constexpr size_t N = 5;

    template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
    static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
    {
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        CN_INIT_SINGLE;
        REPEAT_5(6, CN_INIT, monero_const, l0, ax0, bx0, idx0, ptr0);

        // Optim - 90% time boundary
        for(size_t i = 0; i < ITERATIONS; i++)
        {
            REPEAT_5(7, CN_STEP1, monero_const, l0, ax0, bx0, idx0, ptr0, cx);
            REPEAT_5(7, CN_STEP2, monero_const, l0, ax0, bx0, idx0, ptr0, cx);
            REPEAT_5(11, CN_STEP3, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0);
            REPEAT_5(11, CN_STEP4, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0);
            REPEAT_5(7, CN_STEP5, monero_const, l0, ax0, bx0, idx0, ptr0, al0);
        }

        REPEAT_5(0, CN_FINALIZE);
    }
};
