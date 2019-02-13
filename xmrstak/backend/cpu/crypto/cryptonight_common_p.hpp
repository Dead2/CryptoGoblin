#pragma once

#include <cfenv>
#include "soft_aes.hpp"

#if defined(__GNUC__)
ALWAYS_INLINE static inline uint64_t _xmr_umul128(uint64_t a, uint64_t b, uint64_t* hi){
    unsigned __int128 r = (unsigned __int128)a * (unsigned __int128)b;
    *hi = r >> 64;
    return (uint64_t)r;
}
#endif


inline __m128 _mm_set1_ps_epi32(uint32_t x)
{
    return _mm_castsi128_ps(_mm_set1_epi32(x));
}

// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
ALWAYS_INLINE FLATTEN static inline __m128i sl_xor(__m128i tmp1){
    __m128i tmp4;
    tmp4 = _mm_slli_si128(tmp1, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    return tmp1;
}

FLATTEN void mix_and_propagate(__m128i& x0, __m128i& x1, __m128i& x2, __m128i& x3, __m128i& x4, __m128i& x5, __m128i& x6, __m128i& x7){
    __m128i tmp0 = x0;
    x0 = _mm_xor_si128(x0, x1);
    x1 = _mm_xor_si128(x1, x2);
    x2 = _mm_xor_si128(x2, x3);
    x3 = _mm_xor_si128(x3, x4);
    x4 = _mm_xor_si128(x4, x5);
    x5 = _mm_xor_si128(x5, x6);
    x6 = _mm_xor_si128(x6, x7);
    x7 = _mm_xor_si128(x7, tmp0);
}

template<xmrstak_algo_id ALGO>
static void cryptonight_monero_tweak(uint64_t* mem_out, __m128i tmp){
    mem_out[0] = _mm_cvtsi128_si64(tmp);

    __m128i tmp2 = _mm_castps_si128(_mm_movehl_ps(_mm_castsi128_ps(tmp), _mm_castsi128_ps(tmp)));
    uint64_t vh = _mm_cvtsi128_si64(tmp2);

    //uint8_t x = vh >> 24;
    uint8_t x = uint8_t(vh / 16777216);
    static const uint16_t table = 0x7531;

    uint8_t index;
    if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc) {
        index = (((x >> 3) & 6) | (x & 1)) << 1;
    } else { // ALGO == cryptonight_stellite
        index = (((x >> 4) & 6) | (x & 1)) << 1;
    }
    vh ^= ((table >> index) & 0x3) << 28;
    mem_out[1] = vh;
}

template<xmrstak_algo_id ALGO>
ALWAYS_INLINE FLATTEN inline static void soft_cryptonight_monero_tweak(uint64_t* mem_out, __m128i tmp){
    mem_out[0] = _mm_cvtsi128_si64(tmp);

    __m128i tmp2 = _mm_castps_si128(_mm_movehl_ps(_mm_castsi128_ps(tmp), _mm_castsi128_ps(tmp)));
    uint64_t vh = _mm_cvtsi128_si64(tmp2);

    //uint8_t x = vh >> 24;
    uint8_t x = uint8_t(vh / 16777216);
    static const uint16_t table = 0x7531;

    uint8_t index;
    if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc) {
        index = (((x >> 3) & 6) | (x & 1)) << 1;
    } else { // ALGO == cryptonight_stellite
        index = (((x >> 4) & 6) | (x & 1)) << 1;
    }
    vh ^= ((table >> index) & 0x3) << 28;
    mem_out[1] = vh;
}

inline void cryptonight_conceal_tweak(__m128i& cx, __m128& conc_var)
{
    __m128 r = _mm_cvtepi32_ps(cx);
    __m128 c_old = conc_var;
    r = _mm_add_ps(r, conc_var);
    r = _mm_mul_ps(r, _mm_mul_ps(r, r));
    r = _mm_and_ps(_mm_set1_ps_epi32(0x807FFFFF), r);
    r = _mm_or_ps(_mm_set1_ps_epi32(0x40000000), r);
    conc_var = _mm_add_ps(conc_var, r);

    c_old = _mm_and_ps(_mm_set1_ps_epi32(0x807FFFFF), c_old);
    c_old = _mm_or_ps(_mm_set1_ps_epi32(0x40000000), c_old);
    __m128 nc = _mm_mul_ps(c_old, _mm_set1_ps(536870880.0f));
    cx = _mm_xor_si128(cx, _mm_cvttps_epi32(nc));
}

inline __m128i aes_round_bittube2(const __m128i& val, const __m128i& key){
    alignas(16) uint32_t k[4];
    alignas(16) uint32_t x[4];
    _mm_store_si128((__m128i*)k, key);
    _mm_store_si128((__m128i*)x, _mm_xor_si128(val, _mm_cmpeq_epi32(_mm_setzero_si128(), _mm_setzero_si128()))); // x = ~val
    #define BYTE(p, i) ((unsigned char*)&p)[i]
    k[0] ^= saes_table[0][BYTE(x[0], 0)] ^ saes_table[1][BYTE(x[1], 1)] ^ saes_table[2][BYTE(x[2], 2)] ^ saes_table[3][BYTE(x[3], 3)];
    x[0] ^= k[0];
    k[1] ^= saes_table[0][BYTE(x[1], 0)] ^ saes_table[1][BYTE(x[2], 1)] ^ saes_table[2][BYTE(x[3], 2)] ^ saes_table[3][BYTE(x[0], 3)];
    x[1] ^= k[1];
    k[2] ^= saes_table[0][BYTE(x[2], 0)] ^ saes_table[1][BYTE(x[3], 1)] ^ saes_table[2][BYTE(x[0], 2)] ^ saes_table[3][BYTE(x[1], 3)];
    x[2] ^= k[2];
    k[3] ^= saes_table[0][BYTE(x[3], 0)] ^ saes_table[1][BYTE(x[0], 1)] ^ saes_table[2][BYTE(x[1], 2)] ^ saes_table[3][BYTE(x[2], 3)];
    #undef BYTE
    return _mm_load_si128((__m128i*)k);
}

FLATTEN inline uint64_t int_sqrt33_1_double_precision(const uint64_t n0){
    __m128d x = _mm_castsi128_pd(_mm_add_epi64(_mm_cvtsi64_si128(n0 >> 12), _mm_set_epi64x(0, 1023ULL << 52)));
    x = _mm_sqrt_sd(_mm_setzero_pd(), x);
    uint64_t r = static_cast<uint64_t>(_mm_cvtsi128_si64(_mm_castpd_si128(x)));

    const uint64_t s = r >> 20;
    r >>= 19;

    uint64_t x2 = (s - (1022ULL << 32)) * (r - s - (1022ULL << 32) + 1);

#ifdef __INTEL_COMPILER
    _addcarry_u64(_subborrow_u64(0, x2, n0, (unsigned __int64*)&x2), r, 0, (unsigned __int64*)&r);
#elif defined(_MSC_VER) || (__GNUC__ >= 7)
    _addcarry_u64(_subborrow_u64(0, x2, n0, (unsigned long long int*)&x2), r, 0, (unsigned long long int*)&r);
#else
    // GCC versions prior to 7 don't generate correct assembly for _subborrow_u64 -> _addcarry_u64 sequence
    // Fallback to simpler code
    if (x2 < n0) ++r;
#endif
    return r;
}

FLATTEN inline uint64_t int_sqrt33_1_double_precision_dbl(const uint64_t n0A, const uint64_t n0B, uint64_t & retB){
    __m128d x = _mm_castsi128_pd(_mm_add_epi64(_mm_set_epi64x(n0B >> 12, n0A >> 12), _mm_set_epi64x(1023ULL << 52, 1023ULL << 52)));
    x = _mm_sqrt_pd(x);
    uint64_t rA = (uint64_t)_mm_cvtsi128_si64(_mm_castpd_si128(x));
    uint64_t rB = (uint64_t)_mm_cvtsi128_si64(_mm_castpd_si128(_mm_shuffle_pd(x,x,1)));

    const uint64_t sA = rA >> 20;
    rA >>= 19;
    const uint64_t sB = rB >> 20;
    rB >>= 19;

    uint64_t x2A = (sA - (1022ULL << 32)) * (rA - sA - (1022ULL << 32) + 1);
    uint64_t x2B = (sB - (1022ULL << 32)) * (rB - sB - (1022ULL << 32) + 1);

#ifdef __INTEL_COMPILER
    _addcarry_u64(_subborrow_u64(0, x2A, n0A, (unsigned __int64*)&x2A), rA, 0, (unsigned __int64*)&rA);
    _addcarry_u64(_subborrow_u64(0, x2B, n0B, (unsigned __int64*)&x2B), rB, 0, (unsigned __int64*)&rB);
#elif defined(_MSC_VER) || (__GNUC__ >= 7)
    _addcarry_u64(_subborrow_u64(0, x2A, n0A, (unsigned long long int*)&x2A), rA, 0, (unsigned long long int*)&rA);
    _addcarry_u64(_subborrow_u64(0, x2B, n0B, (unsigned long long int*)&x2B), rB, 0, (unsigned long long int*)&rB);
#else
    // GCC versions prior to 7 don't generate correct assembly for _subborrow_u64 -> _addcarry_u64 sequence
    // Fallback to simpler code
    if (x2A < n0A) ++rA;
    if (x2B < n0B) ++rB;
#endif
    retB = rB;
    return rA;
}

inline void set_float_rounding_mode(){
#ifdef _MSC_VER
    _control87(RC_DOWN, MCW_RC);
#else
    std::fesetround(FE_DOWNWARD);
#endif
}

inline void set_float_rounding_mode_conceal()
{
#ifdef _MSC_VER
    _control87(RC_NEAR, MCW_RC);
#else
    std::fesetround(FE_TONEAREST);
#endif
}

/** optimal type for sqrt
 *
 * Depending on the number of hashes calculated the optimal type for the sqrt value will be selected.
 *
 * @tparam N number of hashes per thread
 */
template<size_t N>
struct GetOptimalSqrtType{
    using type = __m128i;
};

template<>
struct GetOptimalSqrtType<1u>{
    using type = uint64_t;
};

template<size_t N>
using GetOptimalSqrtType_t = typename GetOptimalSqrtType<N>::type;

/** assign a value and convert if necessary
 *
 * @param output output type
 * @param input value which is assigned to output
 * @{
 */
inline void assign(__m128i& output, const uint64_t input){
    output = _mm_cvtsi64_si128(input);
}

inline void assign(uint64_t& output, const uint64_t input){
    output = input;
}

inline void assign(uint64_t& output, const __m128i& input){
    output = _mm_cvtsi128_si64(input);
}
/** @} */

