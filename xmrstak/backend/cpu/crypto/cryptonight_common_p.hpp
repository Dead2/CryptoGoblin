#pragma once

#if defined(__GNUC__)
ALWAYS_INLINE static inline uint64_t _xmr_umul128(uint64_t a, uint64_t b, uint64_t* hi){
    unsigned __int128 r = (unsigned __int128)a * (unsigned __int128)b;
    *hi = r >> 64;
    return (uint64_t)r;
}
#endif

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

FLATTEN void cryptonight_monero_tweak(uint64_t* mem_out, __m128i tmp){
    mem_out[0] = _mm_cvtsi128_si64(tmp);

    tmp = _mm_castps_si128(_mm_movehl_ps(_mm_castsi128_ps(tmp), _mm_castsi128_ps(tmp)));
    uint64_t vh = _mm_cvtsi128_si64(tmp);

    uint8_t x = vh >> 24;
    static const uint16_t table = 0x7531;
    const uint8_t index = (((x >> 3) & 6) | (x & 1)) << 1;
    vh ^= ((table >> index) & 0x3) << 28;

    mem_out[1] = vh;
}
