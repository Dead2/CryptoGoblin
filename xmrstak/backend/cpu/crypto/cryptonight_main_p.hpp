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
extern "C" void cryptonight_v8_mainloop_ivybridge_asm(cryptonight_ctx* ctx0);
extern "C" void cryptonight_v8_mainloop_ryzen_asm(cryptonight_ctx* ctx0);
extern "C" void cryptonight_v8_double_mainloop_sandybridge_asm(cryptonight_ctx* ctx0, cryptonight_ctx* ctx1);

#define CN_MONERO_V8_SHUFFLE_0(n, l0, idx0, ax0, bx0, bx1) \
    /* Shuffle the other 3x16 byte chunks in the current 64-byte cache line */ \
    if(ALGO == cryptonight_monero_v8 || ALGO == cryptonight_turtle){ \
        const uint64_t idx2 = idx0 & MASK; \
        const __m128i chunk1 = _mm_load_si128((__m128i *)&l0[idx2 ^ 0x10]); \
        const __m128i chunk2 = _mm_load_si128((__m128i *)&l0[idx2 ^ 0x20]); \
        const __m128i chunk3 = _mm_load_si128((__m128i *)&l0[idx2 ^ 0x30]); \
        _mm_store_si128((__m128i *)&l0[idx2 ^ 0x10], _mm_add_epi64(chunk3, bx1)); \
        _mm_store_si128((__m128i *)&l0[idx2 ^ 0x20], _mm_add_epi64(chunk1, bx0)); \
        _mm_store_si128((__m128i *)&l0[idx2 ^ 0x30], _mm_add_epi64(chunk2, ax0)); \
    }

#define CN_MONERO_V8_SHUFFLE_1(n, l0, idx1, ax0, bx0, bx1, lo, hi) \
    /* Shuffle the other 3x16 byte chunks in the current 64-byte cache line */ \
    if(ALGO == cryptonight_monero_v8 || ALGO == cryptonight_turtle) \
    { \
        const uint64_t idx2 = idx1 & MASK; \
        const __m128i chunk1 = _mm_xor_si128(_mm_load_si128((__m128i *)&l0[idx2 ^ 0x10]), _mm_set_epi64x(lo, hi)); \
        const __m128i chunk2 = _mm_load_si128((__m128i *)&l0[idx2 ^ 0x20]); \
        hi ^= ((uint64_t*)&chunk2)[0]; \
        lo ^= ((uint64_t*)&chunk2)[1]; \
        const __m128i chunk3 = _mm_load_si128((__m128i *)&l0[idx2 ^ 0x30]); \
        _mm_store_si128((__m128i *)&l0[idx2 ^ 0x10], _mm_add_epi64(chunk3, bx1)); \
        _mm_store_si128((__m128i *)&l0[idx2 ^ 0x20], _mm_add_epi64(chunk1, bx0)); \
        _mm_store_si128((__m128i *)&l0[idx2 ^ 0x30], _mm_add_epi64(chunk2, ax0)); \
    }


#define CN_MONERO_V8_DIV(cx, cx_64, sqrt_result, division_result, division_result_xmm, cl) \
    uint64_t division_result; \
    { \
        uint64_t sqrt_result_tmp; \
        assign(sqrt_result_tmp, sqrt_result); \
        /* Use division and square root results from the _previous_ iteration to hide the latency */ \
        cx_64 = _mm_cvtsi128_si64(cx); \
        cl ^= static_cast<uint64_t>(_mm_cvtsi128_si64(division_result_xmm)) ^ (sqrt_result_tmp << 32); \
        const uint32_t d = (cx_64 + (sqrt_result_tmp << 1)) | 0x80000001UL; \
        /* Most and least significant bits in the divisor are set to 1 \
         * to make sure we don't divide by a small or even number, \
         * so there are no shortcuts for such cases \
         * \
         * Quotient may be as large as (2^64 - 1)/(2^31 + 1) = 8589934588 = 2^33 - 4 \
         * We drop the highest bit to fit both quotient and remainder in 32 bits \
         */  \
        /* Compiler will optimize it to a single div instruction */ \
        const uint64_t cx_s = _mm_cvtsi128_si64(_mm_srli_si128(cx, 8)); \
        division_result = static_cast<uint32_t>(cx_s / d) + ((cx_s % d) << 32); \
        division_result_xmm = _mm_cvtsi64_si128(static_cast<int64_t>(division_result)); \
    }

#define CN_MONERO_V8_DIV_FIN(cx_64, sqrt_result, division_result) \
    /* Use division_result as an input for the square root to prevent parallel implementation in hardware */ \
    assign(sqrt_result, int_sqrt33_1_double_precision(cx_64 + division_result)); \

#define CN_MONERO_V8_DIV_FIN_DBL(cx_64A, sqrt_resultA, division_resultA, \
                                 cx_64B, sqrt_resultB, division_resultB) \
    { \
        /* Use division_result as an input for the square root to prevent parallel implementation in hardware */ \
        uint64_t r1B; \
        assign(sqrt_resultA, int_sqrt33_1_double_precision_dbl(cx_64A + division_resultA, cx_64B + division_resultB, r1B)); \
        assign(sqrt_resultB, r1B); \
    }

#define CN_INIT_SINGLE \
    if((ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_stellite || ALGO == cryptonight_masari || ALGO == cryptonight_bittube2) && len < 43){ \
        memset(output, 0, 32 * N); \
        return; \
    }

#define CN_INIT(n, monero_const, l0, ax0, bx0, idx0, idx1, ptr0, ptr1, bx1, cx_64, sqrt_result, division_result_xmm, cl) \
    keccak_200((const uint8_t *)input + len * n, len, ctx[n]->hash_state); \
    uint64_t monero_const; \
    if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_stellite || ALGO == cryptonight_masari || ALGO == cryptonight_bittube2){ \
        monero_const =  *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + len * n + 35); \
        monero_const ^=  *(reinterpret_cast<const uint64_t*>(ctx[n]->hash_state) + 24); \
    } \
    /* Optim - 99% time boundary */ \
    if(SOFT_AES) \
        soft_cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[n]->hash_state, (__m128i*)ctx[n]->long_state); \
    else \
        cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[n]->hash_state, (__m128i*)ctx[n]->long_state); \
    \
    __m128i* ptr0; \
    uint64_t* ptr1; \
    uint8_t* l0 = ctx[n]->long_state; \
    __m128i ax0; \
    __m128i bx0; \
    uint64_t idx0; \
    uint64_t idx1; \
    /* BEGIN cryptonight_monero_v8 variables */ \
    __m128i bx1; \
    __m128i division_result_xmm; \
    uint64_t cx_64; \
    uint64_t cl; \
    GetOptimalSqrtType_t<N> sqrt_result; \
    /* END cryptonight_monero_v8 variables */ \
    { \
        uint64_t* h0 = (uint64_t*)ctx[n]->hash_state; \
        idx0 = h0[0] ^ h0[4]; \
        if(PREFETCH) \
            _mm_prefetch((const char*)&l0[idx0 & MASK], _MM_HINT_T0); \
        ax0 = _mm_set_epi64x(h0[1] ^ h0[5], idx0); \
        bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]); \
        if(ALGO == cryptonight_monero_v8 || ALGO == cryptonight_turtle){ \
            bx1 = _mm_set_epi64x(h0[9] ^ h0[11], h0[8] ^ h0[10]); \
            division_result_xmm = _mm_cvtsi64_si128(h0[12]); \
            assign(sqrt_result, h0[13]); \
            set_float_rounding_mode(); \
        } \
    }

#define CN_STEP1(n, monero_const, l0, ax0, bx0, idx0, ptr0, cx, bx1) \
    __m128i cx; \
    ptr0 = (__m128i *)&l0[idx0 & MASK]; \
    cx = _mm_load_si128(ptr0); \
    if (ALGO == cryptonight_bittube2){\
        cx = aes_round_bittube2(cx, ax0); \
    }else{ \
        if(SOFT_AES) \
            cx = soft_aesenc(cx, ax0); \
        else \
            cx = _mm_aesenc_si128(cx, ax0); \
    } \
    CN_MONERO_V8_SHUFFLE_0(n, l0, idx0, ax0, bx0, bx1)

#define CN_STEP2(n, monero_const, l0, ax0, bx0, idx1, ptr0, ptr1, cx, cl) \
    if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_stellite || ALGO == cryptonight_masari || ALGO == cryptonight_bittube2) \
        if(SOFT_AES) \
            soft_cryptonight_monero_tweak<ALGO>((uint64_t*)ptr0, _mm_xor_si128(bx0, cx)); \
        else \
            cryptonight_monero_tweak<ALGO>((uint64_t*)ptr0, _mm_xor_si128(bx0, cx)); \
    else \
        _mm_store_si128((__m128i *)ptr0, _mm_xor_si128(bx0, cx)); \
    idx1 = _mm_cvtsi128_si64(cx); \
    ptr1 = (uint64_t *)&l0[idx1 & MASK]; \
    if(PREFETCH) \
        _mm_prefetch((const char*)ptr1, _MM_HINT_T0); \
    if(ALGO != cryptonight_monero_v8 || ALGO == cryptonight_turtle) \
        bx0 = cx; \
    cl = ptr1[0];

#define CN_STEP3(n, monero_const, l0, ax0, bx0, idx1, ptr1, lo, cl, ch, al0, ah0, cx, bx1, sqrt_result, division_result_xmm) \
    uint64_t lo, ch; \
    uint64_t al0 = _mm_cvtsi128_si64(ax0); \
    uint64_t ah0 = ((uint64_t*)&ax0)[1]; \
    ch = ptr1[1]; \
    \
    { \
        uint64_t hi; \
        lo = _umul128(idx1, cl, &hi); \
        CN_MONERO_V8_SHUFFLE_1(n, l0, idx1, ax0, bx0, bx1, lo, hi); \
        ah0 += lo; \
        al0 += hi; \
    } \
    if(ALGO == cryptonight_monero_v8 || ALGO == cryptonight_turtle){ \
        bx1 = bx0; \
        bx0 = cx; \
    } \
    ptr1[0] = al0; \
    if(PREFETCH) \
        _mm_prefetch((const char*)ptr1, _MM_HINT_T0)

#define CN_STEP4(n, monero_const, l0, ax0, bx0, ptr1, lo, cl, ch, al0, ah0) \
    if (ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_stellite || ALGO == cryptonight_masari || ALGO == cryptonight_bittube2){ \
        if (ALGO == cryptonight_ipbc || ALGO == cryptonight_bittube2) \
            ptr1[1] = ah0 ^ monero_const ^ ptr1[0]; \
        else \
            ptr1[1] = ah0 ^ monero_const; \
    }else{ \
        ptr1[1] = ah0; \
    } \
    al0 ^= cl; \
    ah0 ^= ch; \
    ax0 = _mm_set_epi64x(ah0, al0);

#define CN_STEP5(n, monero_const, l0, ax0, bx0, idx0, idx1, ptr0, al0) \
    if(ALGO == cryptonight_heavy || ALGO == cryptonight_bittube2){ \
        ptr0 = (__m128i *)&l0[idx1 & MASK]; \
        int64_t u  = ((int64_t*)ptr0)[0]; \
        int32_t d  = ((int32_t*)ptr0)[2]; \
        int64_t q = u / (d | 0x5); \
        \
        ((int64_t*)ptr0)[0] = u ^ q; \
        idx0 = d ^ q; \
    } else if(ALGO == cryptonight_haven || ALGO == cryptonight_superfast){ \
        ptr0 = (__m128i *)&l0[idx0 & MASK]; \
        int64_t u  = ((int64_t*)ptr0)[0]; \
        int32_t d  = ((int32_t*)ptr0)[2]; \
        int64_t q = u / (d | 0x5); \
        \
        ((int64_t*)ptr0)[0] = u ^ q; \
        idx0 = (~d) ^ q; \
    }else{ \
        idx0 = al0; \
    }

#define CN_FINALIZE(n) \
    /* Optim - 90% time boundary */ \
    if(SOFT_AES) \
        soft_cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[n]->long_state, (__m128i*)ctx[n]->hash_state); \
    else \
        cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[n]->long_state, (__m128i*)ctx[n]->hash_state); \
    /* Optim - 99% time boundary */ \
    keccakf_24((uint64_t*)ctx[n]->hash_state); \
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
#define CN_ENUM_13(n, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n, x10 ## n, x11 ## n, x12 ## n, x13 ## n
#define CN_ENUM_14(n, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n, x10 ## n, x11 ## n, x12 ## n, x13 ## n, x14 ## n
#define CN_ENUM_15(n, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n, x10 ## n, x11 ## n, x12 ## n, x13 ## n, x14 ## n, x15 ## n

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
struct Cryptonight_hash<1>{
    static constexpr size_t N = 1;

    template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
    TARGETS("avx,fma,bmi,sse4.1,sse3,default")
    OPTIMIZE("no-align-loops")
    ALIGN(64) static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx){
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        CN_INIT_SINGLE;
        REPEAT_1(13, CN_INIT, monero_const, l0, ax0, bx0, idx0, idx1, ptr0, ptr1, bx1, cx_64, sqrt_result, division_result_xmm, cl);

        // Optim - 90% time boundary
        for(size_t i = 0; i < ITERATIONS; i++){
            REPEAT_1(8, CN_STEP1, monero_const, l0, ax0, bx0, idx0, ptr0, cx, bx1);
            REPEAT_1(9, CN_STEP2, monero_const, l0, ax0, bx0, idx1, ptr0, ptr1, cx, cl);
            if(ALGO == cryptonight_monero_v8 || ALGO == cryptonight_turtle){
                CN_MONERO_V8_DIV(cx0, cx_640, sqrt_result0, division_result0, division_result_xmm0, cl0);
                CN_MONERO_V8_DIV_FIN(cx_640, sqrt_result0, division_result0);
            }
            REPEAT_1(15, CN_STEP3, monero_const, l0, ax0, bx0, idx1, ptr1, lo, cl, ch, al0, ah0, cx, bx1, sqrt_result, division_result_xmm);
            REPEAT_1(10, CN_STEP4, monero_const, l0, ax0, bx0, ptr1, lo, cl, ch, al0, ah0);
            REPEAT_1(8, CN_STEP5, monero_const, l0, ax0, bx0, idx0, idx1, ptr0, al0);
        }
        REPEAT_1(0, CN_FINALIZE);
    }
};

template< >
struct Cryptonight_hash<2>{
    static constexpr size_t N = 2;

    template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
    TARGETS("avx,fma,bmi,sse4.1,sse3,default")
    OPTIMIZE("no-align-loops")
    ALIGN(64) static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx){
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        CN_INIT_SINGLE;
        REPEAT_2(13, CN_INIT, monero_const, l0, ax0, bx0, idx0, idx1, ptr0, ptr1, bx1, cx_64, sqrt_result, division_result_xmm, cl);

        // Optim - 90% time boundary
        for(size_t i = 0; i < ITERATIONS; i++){
            REPEAT_2(8, CN_STEP1, monero_const, l0, ax0, bx0, idx0, ptr0, cx, bx1);
            REPEAT_2(9, CN_STEP2, monero_const, l0, ax0, bx0, idx1, ptr0, ptr1, cx, cl);
            if(ALGO == cryptonight_monero_v8 || ALGO == cryptonight_turtle){
                CN_MONERO_V8_DIV(cx0, cx_640, sqrt_result0, division_result0, division_result_xmm0, cl0);
                CN_MONERO_V8_DIV(cx1, cx_641, sqrt_result1, division_result1, division_result_xmm1, cl1);
                CN_MONERO_V8_DIV_FIN_DBL(cx_640, sqrt_result0, division_result0, cx_641, sqrt_result1, division_result1);
            }
            REPEAT_2(15, CN_STEP3, monero_const, l0, ax0, bx0, idx1, ptr1, lo, cl, ch, al0, ah0, cx, bx1, sqrt_result, division_result_xmm);
            REPEAT_2(10, CN_STEP4, monero_const, l0, ax0, bx0, ptr1, lo, cl, ch, al0, ah0);
            REPEAT_2(8, CN_STEP5, monero_const, l0, ax0, bx0, idx0, idx1, ptr0, al0);
        }
        REPEAT_2(0, CN_FINALIZE);
    }
};

template< >
struct Cryptonight_hash<3>{
    static constexpr size_t N = 3;

    template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
    TARGETS("avx,fma,bmi,sse4.1,sse3,default")
    OPTIMIZE("no-align-loops")
    ALIGN(64) static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx){
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        CN_INIT_SINGLE;
        REPEAT_3(13, CN_INIT, monero_const, l0, ax0, bx0, idx0, idx1, ptr0, ptr1, bx1, cx_64, sqrt_result, division_result_xmm, cl);

        // Optim - 90% time boundary
        for(size_t i = 0; i < ITERATIONS; i++){
            REPEAT_3(8, CN_STEP1, monero_const, l0, ax0, bx0, idx0, ptr0, cx, bx1);
            REPEAT_3(9, CN_STEP2, monero_const, l0, ax0, bx0, idx1, ptr0, ptr1, cx, cl);
            if(ALGO == cryptonight_monero_v8 || ALGO == cryptonight_turtle){
                CN_MONERO_V8_DIV(cx0, cx_640, sqrt_result0, division_result0, division_result_xmm0, cl0);
                CN_MONERO_V8_DIV(cx1, cx_641, sqrt_result1, division_result1, division_result_xmm1, cl1);
                CN_MONERO_V8_DIV(cx2, cx_642, sqrt_result2, division_result2, division_result_xmm2, cl2);
                CN_MONERO_V8_DIV_FIN_DBL(cx_640, sqrt_result0, division_result0, cx_641, sqrt_result1, division_result1);
                CN_MONERO_V8_DIV_FIN(cx_642, sqrt_result2, division_result2); \
            }
            REPEAT_3(15, CN_STEP3, monero_const, l0, ax0, bx0, idx1, ptr1, lo, cl, ch, al0, ah0, cx, bx1, sqrt_result, division_result_xmm);
            REPEAT_3(10, CN_STEP4, monero_const, l0, ax0, bx0, ptr1, lo, cl, ch, al0, ah0);
            REPEAT_3(8, CN_STEP5, monero_const, l0, ax0, bx0, idx0, idx1, ptr0, al0);
        }

        REPEAT_3(0, CN_FINALIZE);
    }
};

template< >
struct Cryptonight_hash<4>{
    static constexpr size_t N = 4;

    template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
    TARGETS("avx,fma,bmi,sse4.1,sse3,default")
    OPTIMIZE("no-align-loops")
    ALIGN(64) static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx){
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        CN_INIT_SINGLE;
        REPEAT_4(13, CN_INIT, monero_const, l0, ax0, bx0, idx0, idx1, ptr0, ptr1, bx1, cx_64, sqrt_result, division_result_xmm, cl);

        // Optim - 90% time boundary
        for(size_t i = 0; i < ITERATIONS; i++){
            REPEAT_4(8, CN_STEP1, monero_const, l0, ax0, bx0, idx0, ptr0, cx, bx1);
            REPEAT_4(9, CN_STEP2, monero_const, l0, ax0, bx0, idx1, ptr0, ptr1, cx, cl);
            if(ALGO == cryptonight_monero_v8 || ALGO == cryptonight_turtle){
                CN_MONERO_V8_DIV(cx0, cx_640, sqrt_result0, division_result0, division_result_xmm0, cl0);
                CN_MONERO_V8_DIV(cx1, cx_641, sqrt_result1, division_result1, division_result_xmm1, cl1);
                CN_MONERO_V8_DIV(cx2, cx_642, sqrt_result2, division_result2, division_result_xmm2, cl2);
                CN_MONERO_V8_DIV(cx3, cx_643, sqrt_result3, division_result3, division_result_xmm3, cl3);
                CN_MONERO_V8_DIV_FIN_DBL(cx_640, sqrt_result0, division_result0, cx_641, sqrt_result1, division_result1);
                CN_MONERO_V8_DIV_FIN_DBL(cx_642, sqrt_result2, division_result2, cx_643, sqrt_result3, division_result3);
            }
            REPEAT_4(15, CN_STEP3, monero_const, l0, ax0, bx0, idx1, ptr1, lo, cl, ch, al0, ah0, cx, bx1, sqrt_result, division_result_xmm);
            REPEAT_4(10, CN_STEP4, monero_const, l0, ax0, bx0, ptr1, lo, cl, ch, al0, ah0);
            REPEAT_4(8, CN_STEP5, monero_const, l0, ax0, bx0, idx0, idx1, ptr0, al0);
        }

        REPEAT_4(0, CN_FINALIZE);
    }
};

template< >
struct Cryptonight_hash<5>{
    static constexpr size_t N = 5;

    template<xmrstak_algo ALGO, bool SOFT_AES, bool PREFETCH>
    TARGETS("avx,fma,bmi,sse4.1,sse3,default")
    OPTIMIZE("no-align-loops")
    ALIGN(64) static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx){
        constexpr size_t MASK = cn_select_mask<ALGO>();
        constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
        constexpr size_t MEM = cn_select_memory<ALGO>();

        CN_INIT_SINGLE;
        REPEAT_5(13, CN_INIT, monero_const, l0, ax0, bx0, idx0, idx1, ptr0, ptr1, bx1, cx_64, sqrt_result, division_result_xmm, cl);

        // Optim - 90% time boundary
        for(size_t i = 0; i < ITERATIONS; i++) {
            REPEAT_5(8, CN_STEP1, monero_const, l0, ax0, bx0, idx0, ptr0, cx, bx1);
            REPEAT_5(9, CN_STEP2, monero_const, l0, ax0, bx0, idx1, ptr0, ptr1, cx, cl);
            if(ALGO == cryptonight_monero_v8 || ALGO == cryptonight_turtle){
                CN_MONERO_V8_DIV(cx0, cx_640, sqrt_result0, division_result0, division_result_xmm0, cl0);
                CN_MONERO_V8_DIV(cx1, cx_641, sqrt_result1, division_result1, division_result_xmm1, cl1);
                CN_MONERO_V8_DIV(cx2, cx_642, sqrt_result2, division_result2, division_result_xmm2, cl2);
                CN_MONERO_V8_DIV(cx3, cx_643, sqrt_result3, division_result3, division_result_xmm3, cl3);
                CN_MONERO_V8_DIV(cx4, cx_644, sqrt_result4, division_result4, division_result_xmm4, cl4);
                CN_MONERO_V8_DIV_FIN_DBL(cx_640, sqrt_result0, division_result0, cx_641, sqrt_result1, division_result1);
                CN_MONERO_V8_DIV_FIN_DBL(cx_642, sqrt_result2, division_result2, cx_643, sqrt_result3, division_result3);
                CN_MONERO_V8_DIV_FIN(cx_644, sqrt_result4, division_result4);
            }
            REPEAT_5(15, CN_STEP3, monero_const, l0, ax0, bx0, idx1, ptr1, lo, cl, ch, al0, ah0, cx, bx1, sqrt_result, division_result_xmm);
            REPEAT_5(10, CN_STEP4, monero_const, l0, ax0, bx0, ptr1, lo, cl, ch, al0, ah0);
            REPEAT_5(8, CN_STEP5, monero_const, l0, ax0, bx0, idx0, idx1, ptr0, al0);
        }

        REPEAT_5(0, CN_FINALIZE);
    }
};


template<size_t N, size_t asm_version>
struct Cryptonight_hash_asm;

template<size_t asm_version>
struct Cryptonight_hash_asm<1, asm_version>{
    static constexpr size_t N = 1;

    template<xmrstak_algo ALGO, bool PREFETCH>
    static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx){
        constexpr size_t MEM = cn_select_memory<ALGO>();

        keccak_200((const uint8_t *)input, len, ctx[0]->hash_state);
        cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[0]->hash_state, (__m128i*)ctx[0]->long_state);

        if (asm_version == 0)
            cryptonight_v8_mainloop_ivybridge_asm(ctx[0]);
        else if (asm_version == 1)
            cryptonight_v8_mainloop_ryzen_asm(ctx[0]);

        cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[0]->long_state, (__m128i*)ctx[0]->hash_state);
        keccakf_24((uint64_t*)ctx[0]->hash_state);
        extra_hashes[ctx[0]->hash_state[0] & 3](ctx[0]->hash_state, (char*)output);
    }
};

// double hash only for intel
template< >
struct Cryptonight_hash_asm<2, 0>{
    static constexpr size_t N = 2;
    template<xmrstak_algo ALGO, bool PREFETCH>
    static void hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx){
        constexpr size_t MEM = cn_select_memory<ALGO>();

        for(size_t i = 0; i < N; ++i){
            keccak_200((const uint8_t *)input + len * i, len, ctx[i]->hash_state);
            /* Optim - 99% time boundary */
            cn_explode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
        }

        cryptonight_v8_double_mainloop_sandybridge_asm(ctx[0], ctx[1]);

        for(size_t i = 0; i < N; ++i){
            /* Optim - 90% time boundary */
            cn_implode_scratchpad<ALGO, MEM, PREFETCH>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
            /* Optim - 99% time boundary */
            keccakf_24((uint64_t*)ctx[i]->hash_state);
            extra_hashes[ctx[i]->hash_state[0] & 3](ctx[i]->hash_state, (char*)output + 32 * i);
        }
    }
};
