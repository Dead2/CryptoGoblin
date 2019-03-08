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
  * Additional permission under GNU GPL version 3 section 7
  *
  * If you modify this Program, or any covered work, by linking or combining
  * it with OpenSSL (or a modified version of that library), containing parts
  * covered by the terms of OpenSSL License and SSLeay License, the licensors
  * of this Program grant you additional permission to convey the resulting work.
  *
  */

/*
 * The orginal author of this AES implementation is Karl Malbrain.
 */

ALWAYS_INLINE FLATTEN static inline void soft_aes_4round(__m128i* __restrict__ key, __m128i* __restrict__ in1, __m128i* __restrict__ in2, __m128i* __restrict__ in3, __m128i* __restrict__ in4) {
    uint32_t a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3;

    a0 = _mm_cvtsi128_si32(*in1);
    a1 = _mm_cvtsi128_si32(_mm_shuffle_epi32(*in1, 0x55));
    a2 = _mm_cvtsi128_si32(_mm_shuffle_epi32(*in1, 0xAA));
    a3 = _mm_cvtsi128_si32(_mm_shuffle_epi32(*in1, 0xFF));

    b0 = _mm_cvtsi128_si32(*in2);
    b1 = _mm_cvtsi128_si32(_mm_shuffle_epi32(*in2, 0x55));
    b2 = _mm_cvtsi128_si32(_mm_shuffle_epi32(*in2, 0xAA));
    b3 = _mm_cvtsi128_si32(_mm_shuffle_epi32(*in2, 0xFF));

    __m128i out1 = _mm_set_epi32(
        (saes_table[0][a3 & 0xff] ^ saes_table[1][(a0 >> 8) & 0xff] ^ saes_table[2][(a1 >> 16) & 0xff] ^ saes_table[3][a2 >> 24]),
        (saes_table[0][a2 & 0xff] ^ saes_table[1][(a3 >> 8) & 0xff] ^ saes_table[2][(a0 >> 16) & 0xff] ^ saes_table[3][a1 >> 24]),
        (saes_table[0][a1 & 0xff] ^ saes_table[1][(a2 >> 8) & 0xff] ^ saes_table[2][(a3 >> 16) & 0xff] ^ saes_table[3][a0 >> 24]),
        (saes_table[0][a0 & 0xff] ^ saes_table[1][(a1 >> 8) & 0xff] ^ saes_table[2][(a2 >> 16) & 0xff] ^ saes_table[3][a3 >> 24]));

    c0 = _mm_cvtsi128_si32(*in3);
    c1 = _mm_cvtsi128_si32(_mm_shuffle_epi32(*in3, 0x55));
    c2 = _mm_cvtsi128_si32(_mm_shuffle_epi32(*in3, 0xAA));
    c3 = _mm_cvtsi128_si32(_mm_shuffle_epi32(*in3, 0xFF));

    *in1 = _mm_xor_si128(out1, *key);

    __m128i out2 = _mm_set_epi32(
        (saes_table[0][b3 & 0xff] ^ saes_table[1][(b0 >> 8) & 0xff] ^ saes_table[2][(b1 >> 16) & 0xff] ^ saes_table[3][b2 >> 24]),
        (saes_table[0][b2 & 0xff] ^ saes_table[1][(b3 >> 8) & 0xff] ^ saes_table[2][(b0 >> 16) & 0xff] ^ saes_table[3][b1 >> 24]),
        (saes_table[0][b1 & 0xff] ^ saes_table[1][(b2 >> 8) & 0xff] ^ saes_table[2][(b3 >> 16) & 0xff] ^ saes_table[3][b0 >> 24]),
        (saes_table[0][b0 & 0xff] ^ saes_table[1][(b1 >> 8) & 0xff] ^ saes_table[2][(b2 >> 16) & 0xff] ^ saes_table[3][b3 >> 24]));

    d0 = _mm_cvtsi128_si32(*in4);
    d1 = _mm_cvtsi128_si32(_mm_shuffle_epi32(*in4, 0x55));
    d2 = _mm_cvtsi128_si32(_mm_shuffle_epi32(*in4, 0xAA));
    d3 = _mm_cvtsi128_si32(_mm_shuffle_epi32(*in4, 0xFF));

    *in2 = _mm_xor_si128(out2, *key);

    __m128i out3 = _mm_set_epi32(
        (saes_table[0][c3 & 0xff] ^ saes_table[1][(c0 >> 8) & 0xff] ^ saes_table[2][(c1 >> 16) & 0xff] ^ saes_table[3][c2 >> 24]),
        (saes_table[0][c2 & 0xff] ^ saes_table[1][(c3 >> 8) & 0xff] ^ saes_table[2][(c0 >> 16) & 0xff] ^ saes_table[3][c1 >> 24]),
        (saes_table[0][c1 & 0xff] ^ saes_table[1][(c2 >> 8) & 0xff] ^ saes_table[2][(c3 >> 16) & 0xff] ^ saes_table[3][c0 >> 24]),
        (saes_table[0][c0 & 0xff] ^ saes_table[1][(c1 >> 8) & 0xff] ^ saes_table[2][(c2 >> 16) & 0xff] ^ saes_table[3][c3 >> 24]));

    __m128i out4 = _mm_set_epi32(
        (saes_table[0][d3 & 0xff] ^ saes_table[1][(d0 >> 8) & 0xff] ^ saes_table[2][(d1 >> 16) & 0xff] ^ saes_table[3][d2 >> 24]),
        (saes_table[0][d2 & 0xff] ^ saes_table[1][(d3 >> 8) & 0xff] ^ saes_table[2][(d0 >> 16) & 0xff] ^ saes_table[3][d1 >> 24]),
        (saes_table[0][d1 & 0xff] ^ saes_table[1][(d2 >> 8) & 0xff] ^ saes_table[2][(d3 >> 16) & 0xff] ^ saes_table[3][d0 >> 24]),
        (saes_table[0][d0 & 0xff] ^ saes_table[1][(d1 >> 8) & 0xff] ^ saes_table[2][(d2 >> 16) & 0xff] ^ saes_table[3][d3 >> 24]));


    *in3 = _mm_xor_si128(out3, *key);
    *in4 = _mm_xor_si128(out4, *key);
}

ALWAYS_INLINE FLATTEN static inline __m128i soft_aesenc(__m128i in, __m128i key) {
    uint32_t x0, x1, x2, x3;
    x0 = _mm_cvtsi128_si32(in);
    x1 = _mm_cvtsi128_si32(_mm_shuffle_epi32(in, 0x55));
    x2 = _mm_cvtsi128_si32(_mm_shuffle_epi32(in, 0xAA));
    x3 = _mm_cvtsi128_si32(_mm_shuffle_epi32(in, 0xFF));

    __m128i out = _mm_set_epi32(
        (saes_table[0][x3 & 0xff] ^ saes_table[1][(x0 >> 8) & 0xff] ^ saes_table[2][(x1 >> 16) & 0xff] ^ saes_table[3][x2 >> 24]),
        (saes_table[0][x2 & 0xff] ^ saes_table[1][(x3 >> 8) & 0xff] ^ saes_table[2][(x0 >> 16) & 0xff] ^ saes_table[3][x1 >> 24]),
        (saes_table[0][x1 & 0xff] ^ saes_table[1][(x2 >> 8) & 0xff] ^ saes_table[2][(x3 >> 16) & 0xff] ^ saes_table[3][x0 >> 24]),
        (saes_table[0][x0 & 0xff] ^ saes_table[1][(x1 >> 8) & 0xff] ^ saes_table[2][(x2 >> 16) & 0xff] ^ saes_table[3][x3 >> 24]));

    return _mm_xor_si128(out, key);
}

static inline uint32_t sub_word(uint32_t key){
    return (saes_sbox[key >> 24 ] << 24)          |
           (saes_sbox[(key >> 16) & 0xff] << 16 ) |
           (saes_sbox[(key >> 8)  & 0xff] << 8  ) |
            saes_sbox[key & 0xff];
}

#ifdef __clang__
static inline uint32_t _rotr(uint32_t value, uint32_t amount)
{
    return (value >> amount) | (value << ((32 - amount) & 31));
}
#endif

__m128i soft_aeskeygenassist(__m128i key, uint8_t rcon)
{
    uint32_t X1 = sub_word(_mm_cvtsi128_si32(_mm_shuffle_epi32(key, 0x55)));
    uint32_t X3 = sub_word(_mm_cvtsi128_si32(_mm_shuffle_epi32(key, 0xFF)));
    return _mm_set_epi32(_rotr(X3, 8) ^ rcon, X3,_rotr(X1, 8) ^ rcon, X1);
}
