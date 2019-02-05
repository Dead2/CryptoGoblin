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

#include "cryptonight_common_p.hpp"
#include "soft_aes.hpp"
#include "soft_aes_p.hpp"

__m128i soft_aesenc(__m128i in, __m128i key);
__m128i soft_aeskeygenassist(__m128i key, uint8_t rcon);

template<uint8_t rcon>
ALWAYS_INLINE FLATTEN static inline void soft_aes_genkey_sub(__m128i* xout0, __m128i* xout2){
    __m128i xout1 = soft_aeskeygenassist(*xout2, rcon);
    xout1 = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1 = soft_aeskeygenassist(*xout0, 0x00);
    xout1 = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}

FLATTEN static inline void soft_aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3,
    __m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
    __m128i xout0, xout2;

    xout0 = _mm_load_si128(memory);
    xout2 = _mm_load_si128(memory+1);
    *k0 = xout0;
    *k1 = xout2;

    soft_aes_genkey_sub<0x01>(&xout0, &xout2);
    *k2 = xout0;
    *k3 = xout2;

    soft_aes_genkey_sub<0x02>(&xout0, &xout2);
    *k4 = xout0;
    *k5 = xout2;

    soft_aes_genkey_sub<0x04>(&xout0, &xout2);
    *k6 = xout0;
    *k7 = xout2;

    soft_aes_genkey_sub<0x08>(&xout0, &xout2);
    *k8 = xout0;
    *k9 = xout2;
}

template<xmrstak_algo_id ALGO, bool PREFETCH>
TARGETS("sse4.1,ssse3,default")
ALIGN(64) FLATTEN2 void soft_cn_explode_scratchpad(const __m128i* input, __m128i* output, const xmrstak_algo& algo){
    constexpr bool HEAVY_MIX = ALGO == cryptonight_heavy || ALGO == cryptonight_haven || ALGO == cryptonight_bittube2 || ALGO == cryptonight_superfast;

    // This is more than we have registers, compiler will assign 2 keys on the stack
    __m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    if(PREFETCH){
        _mm_prefetch((const char*)input + 0, _MM_HINT_T0);
        _mm_prefetch((const char*)input + 4, _MM_HINT_T0);
        _mm_prefetch((const char*)input + 8, _MM_HINT_T0);
    }

    soft_aes_genkey(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xin0 = _mm_load_si128(input + 4);
    xin1 = _mm_load_si128(input + 5);
    xin2 = _mm_load_si128(input + 6);
    xin3 = _mm_load_si128(input + 7);
    xin4 = _mm_load_si128(input + 8);
    xin5 = _mm_load_si128(input + 9);
    xin6 = _mm_load_si128(input + 10);
    xin7 = _mm_load_si128(input + 11);

    if(HEAVY_MIX){
        for(size_t i=0; i < 16; i++){
            soft_aes_4round(&k0, &xin0, &xin1, &xin2, &xin3);
            soft_aes_4round(&k1, &xin0, &xin1, &xin2, &xin3);
            soft_aes_4round(&k2, &xin0, &xin1, &xin2, &xin3);
            soft_aes_4round(&k3, &xin0, &xin1, &xin2, &xin3);
            soft_aes_4round(&k4, &xin0, &xin1, &xin2, &xin3);
            soft_aes_4round(&k5, &xin0, &xin1, &xin2, &xin3);
            soft_aes_4round(&k6, &xin0, &xin1, &xin2, &xin3);
            soft_aes_4round(&k7, &xin0, &xin1, &xin2, &xin3);
            soft_aes_4round(&k8, &xin0, &xin1, &xin2, &xin3);
            soft_aes_4round(&k9, &xin0, &xin1, &xin2, &xin3);

            soft_aes_4round(&k0, &xin4, &xin5, &xin6, &xin7);
            soft_aes_4round(&k1, &xin4, &xin5, &xin6, &xin7);
            soft_aes_4round(&k2, &xin4, &xin5, &xin6, &xin7);
            soft_aes_4round(&k3, &xin4, &xin5, &xin6, &xin7);
            soft_aes_4round(&k4, &xin4, &xin5, &xin6, &xin7);
            soft_aes_4round(&k5, &xin4, &xin5, &xin6, &xin7);
            soft_aes_4round(&k6, &xin4, &xin5, &xin6, &xin7);
            soft_aes_4round(&k7, &xin4, &xin5, &xin6, &xin7);
            soft_aes_4round(&k8, &xin4, &xin5, &xin6, &xin7);
            soft_aes_4round(&k9, &xin4, &xin5, &xin6, &xin7);

            mix_and_propagate(xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
        }
    }

    const size_t MEM = algo.Mem();
    for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8){
        soft_aes_4round(&k0, &xin0, &xin1, &xin2, &xin3);
        soft_aes_4round(&k1, &xin0, &xin1, &xin2, &xin3);
        soft_aes_4round(&k2, &xin0, &xin1, &xin2, &xin3);
        soft_aes_4round(&k3, &xin0, &xin1, &xin2, &xin3);
        soft_aes_4round(&k4, &xin0, &xin1, &xin2, &xin3);
        soft_aes_4round(&k5, &xin0, &xin1, &xin2, &xin3);
        soft_aes_4round(&k6, &xin0, &xin1, &xin2, &xin3);
        soft_aes_4round(&k7, &xin0, &xin1, &xin2, &xin3);
        soft_aes_4round(&k8, &xin0, &xin1, &xin2, &xin3);
        soft_aes_4round(&k9, &xin0, &xin1, &xin2, &xin3);

        _mm_store_si128(output + i + 0, xin0);
        _mm_store_si128(output + i + 1, xin1);
        _mm_store_si128(output + i + 2, xin2);
        _mm_store_si128(output + i + 3, xin3);
    }

    for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8){
        soft_aes_4round(&k0, &xin4, &xin5, &xin6, &xin7);
        soft_aes_4round(&k1, &xin4, &xin5, &xin6, &xin7);
        soft_aes_4round(&k2, &xin4, &xin5, &xin6, &xin7);
        soft_aes_4round(&k3, &xin4, &xin5, &xin6, &xin7);
        soft_aes_4round(&k4, &xin4, &xin5, &xin6, &xin7);
        soft_aes_4round(&k5, &xin4, &xin5, &xin6, &xin7);
        soft_aes_4round(&k6, &xin4, &xin5, &xin6, &xin7);
        soft_aes_4round(&k7, &xin4, &xin5, &xin6, &xin7);
        soft_aes_4round(&k8, &xin4, &xin5, &xin6, &xin7);
        soft_aes_4round(&k9, &xin4, &xin5, &xin6, &xin7);

        _mm_store_si128(output + i + 4, xin4);
        _mm_store_si128(output + i + 5, xin5);
        _mm_store_si128(output + i + 6, xin6);
        _mm_store_si128(output + i + 7, xin7);

        if(PREFETCH){
            _mm_prefetch((const char*)output + i + 0, _MM_HINT_T2);
            _mm_prefetch((const char*)output + i + 4, _MM_HINT_T2);
        }
    }
}

template<xmrstak_algo_id ALGO, bool PREFETCH>
TARGETS("sse4.1,ssse3,default")
ALIGN(64) FLATTEN2 void soft_cn_implode_scratchpad(const __m128i* input, __m128i* output, const xmrstak_algo& algo){
    constexpr bool HEAVY_MIX = ALGO == cryptonight_heavy || ALGO == cryptonight_haven || ALGO == cryptonight_bittube2 || ALGO == cryptonight_superfast;

    // This is more than we have registers, compiler will assign 2 keys on the stack
    __m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    if(PREFETCH){
        _mm_prefetch((const char*)output + 0, _MM_HINT_T0);
        _mm_prefetch((const char*)output + 4, _MM_HINT_T0);
        _mm_prefetch((const char*)output + 8, _MM_HINT_T0);
    }

    soft_aes_genkey(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    if(PREFETCH){
        _mm_prefetch((const char*)input + 0, _MM_HINT_NTA);
        _mm_prefetch((const char*)input + 4, _MM_HINT_NTA);
    }

    xout0 = _mm_load_si128(output + 4);
    xout1 = _mm_load_si128(output + 5);
    xout2 = _mm_load_si128(output + 6);
    xout3 = _mm_load_si128(output + 7);
    xout4 = _mm_load_si128(output + 8);
    xout5 = _mm_load_si128(output + 9);
    xout6 = _mm_load_si128(output + 10);
    xout7 = _mm_load_si128(output + 11);

    const size_t MEM = algo.Mem();
    for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8){
        xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
        xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
        xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
        xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);

        soft_aes_4round(&k0, &xout0, &xout1, &xout2, &xout3);
        soft_aes_4round(&k1, &xout0, &xout1, &xout2, &xout3);
        soft_aes_4round(&k2, &xout0, &xout1, &xout2, &xout3);
        soft_aes_4round(&k3, &xout0, &xout1, &xout2, &xout3);
        soft_aes_4round(&k4, &xout0, &xout1, &xout2, &xout3);
        soft_aes_4round(&k5, &xout0, &xout1, &xout2, &xout3);
        soft_aes_4round(&k6, &xout0, &xout1, &xout2, &xout3);
        soft_aes_4round(&k7, &xout0, &xout1, &xout2, &xout3);
        soft_aes_4round(&k8, &xout0, &xout1, &xout2, &xout3);
        soft_aes_4round(&k9, &xout0, &xout1, &xout2, &xout3);

        xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
        xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
        xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
        xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

        soft_aes_4round(&k0, &xout4, &xout5, &xout6, &xout7);
        soft_aes_4round(&k1, &xout4, &xout5, &xout6, &xout7);
        soft_aes_4round(&k2, &xout4, &xout5, &xout6, &xout7);
        soft_aes_4round(&k3, &xout4, &xout5, &xout6, &xout7);
        soft_aes_4round(&k4, &xout4, &xout5, &xout6, &xout7);
        soft_aes_4round(&k5, &xout4, &xout5, &xout6, &xout7);
        if(PREFETCH){
            _mm_prefetch((const char*)input + i +  8, _MM_HINT_NTA);
            _mm_prefetch((const char*)input + i + 12, _MM_HINT_NTA);
        }
        soft_aes_4round(&k6, &xout4, &xout5, &xout6, &xout7);
        soft_aes_4round(&k7, &xout4, &xout5, &xout6, &xout7);
        soft_aes_4round(&k8, &xout4, &xout5, &xout6, &xout7);
        soft_aes_4round(&k9, &xout4, &xout5, &xout6, &xout7);

        if(HEAVY_MIX)
            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
    }

    if(HEAVY_MIX){
        for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8){
            xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
            xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
            xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
            xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);

            soft_aes_4round(&k0, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k1, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k2, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k3, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k4, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k5, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k6, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k7, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k8, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k9, &xout0, &xout1, &xout2, &xout3);

            xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
            xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
            xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
            xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

            soft_aes_4round(&k0, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k1, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k2, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k3, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k4, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k5, &xout4, &xout5, &xout6, &xout7);
            if(PREFETCH){
                _mm_prefetch((const char*)input + i +  8, _MM_HINT_NTA);
                _mm_prefetch((const char*)input + i + 12, _MM_HINT_NTA);
            }
            soft_aes_4round(&k6, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k7, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k8, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k9, &xout4, &xout5, &xout6, &xout7);

            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }

        for(size_t i=0; i < 16; i++){
            soft_aes_4round(&k0, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k1, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k2, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k3, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k4, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k5, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k6, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k7, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k8, &xout0, &xout1, &xout2, &xout3);
            soft_aes_4round(&k9, &xout0, &xout1, &xout2, &xout3);

            soft_aes_4round(&k0, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k1, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k2, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k3, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k4, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k5, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k6, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k7, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k8, &xout4, &xout5, &xout6, &xout7);
            soft_aes_4round(&k9, &xout4, &xout5, &xout6, &xout7);

            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }
    }

    _mm_store_si128(output + 4, xout0);
    _mm_store_si128(output + 5, xout1);
    _mm_store_si128(output + 6, xout2);
    _mm_store_si128(output + 7, xout3);
    _mm_store_si128(output + 8, xout4);
    _mm_store_si128(output + 9, xout5);
    _mm_store_si128(output + 10, xout6);
    _mm_store_si128(output + 11, xout7);
}
