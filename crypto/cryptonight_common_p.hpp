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
ALWAYS_INLINE FLATTEN static inline __m128i sl_xor(__m128i tmp1)
{
    __m128i tmp4;
    tmp4 = _mm_slli_si128(tmp1, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    return tmp1;
}

