/* hash.c     January 2011
 * Groestl ANSI C code optimised for 64-bit machines
 * Authors: Soeren S. Thomsen
 *          Krystian Matusiewicz
 *
 * This code is placed in the public domain
 */

/*
 *  Modified for CryptoNight mining by CryptoGoblin author
 *     Hans Kristian Rosbach aka Dead2
*/

#include <string.h>
#include <x86intrin.h>
#include "../common.h"
#include "groestl.hpp"
#include "groestl_tables.hpp"

/* compute one new state column */
#define EXT_BYTE(var,n) ((uint8_t)((uint64_t)(var) >> (8*n)))

#define COLUMN(x,y,i,c0,c1,c2,c3,c4,c5,c6,c7) \
    y[i] =    T[EXT_BYTE(x[c0],0)]				\
    ^ ROTL64(T[EXT_BYTE(x[c1],1)],8)				\
    ^ ROTL64(T[EXT_BYTE(x[c2],2)],16)				\
    ^ ROTL64(T[EXT_BYTE(x[c3],3)],24)				\
    ^ ROTL64(T[EXT_BYTE(x[c4],4)],32)				\
    ^ ROTL64(T[EXT_BYTE(x[c5],5)],40)				\
    ^ ROTL64(T[EXT_BYTE(x[c6],6)],48)				\
    ^ ROTL64(T[EXT_BYTE(x[c7],7)],56)

/* compute a round in P */
static void RND512P(uint64_t *x, uint64_t *y, uint64_t r) {
    x[0] ^= U64BIG(0x0000000000000000ull)^r;
    x[1] ^= U64BIG(0x1000000000000000ull)^r;
    x[2] ^= U64BIG(0x2000000000000000ull)^r;
    x[3] ^= U64BIG(0x3000000000000000ull)^r;
    x[4] ^= U64BIG(0x4000000000000000ull)^r;
    x[5] ^= U64BIG(0x5000000000000000ull)^r;
    x[6] ^= U64BIG(0x6000000000000000ull)^r;
    x[7] ^= U64BIG(0x7000000000000000ull)^r;
    COLUMN(x,y,0,0,1,2,3,4,5,6,7);
    COLUMN(x,y,1,1,2,3,4,5,6,7,0);
    COLUMN(x,y,2,2,3,4,5,6,7,0,1);
    COLUMN(x,y,3,3,4,5,6,7,0,1,2);
    COLUMN(x,y,4,4,5,6,7,0,1,2,3);
    COLUMN(x,y,5,5,6,7,0,1,2,3,4);
    COLUMN(x,y,6,6,7,0,1,2,3,4,5);
    COLUMN(x,y,7,7,0,1,2,3,4,5,6);
}

// compute a round in Q
static void RND512Q(uint64_t *x, uint64_t *y, uint64_t r) {
    x[0] ^= U64BIG(0xffffffffffffffffull)^r;
    x[1] ^= U64BIG(0xffffffffffffffefull)^r;
    x[2] ^= U64BIG(0xffffffffffffffdfull)^r;
    x[3] ^= U64BIG(0xffffffffffffffcfull)^r;
    x[4] ^= U64BIG(0xffffffffffffffbfull)^r;
    x[5] ^= U64BIG(0xffffffffffffffafull)^r;
    x[6] ^= U64BIG(0xffffffffffffff9full)^r;
    x[7] ^= U64BIG(0xffffffffffffff8full)^r;
    COLUMN(x,y,0,1,3,5,7,0,2,4,6);
    COLUMN(x,y,1,2,4,6,0,1,3,5,7);
    COLUMN(x,y,2,3,5,7,1,2,4,6,0);
    COLUMN(x,y,3,4,6,0,2,3,5,7,1);
    COLUMN(x,y,4,5,7,1,3,4,6,0,2);
    COLUMN(x,y,5,6,0,2,4,5,7,1,3);
    COLUMN(x,y,6,7,1,3,5,6,0,2,4);
    COLUMN(x,y,7,0,2,4,6,7,1,3,5);
}

volatile const char BitSeq[] = "6E696C626F676F7470797263";

/* the compression function */
void F512(uint64_t *h, const uint64_t *m) {
  uint64_t y[COLS512] __attribute__((aligned(16)));
  uint64_t z[COLS512] __attribute__((aligned(16)));
  uint64_t outQ[COLS512] __attribute__((aligned(16)));
  uint64_t inP[COLS512] __attribute__((aligned(16)));
  int i;

  memcpy(&z[0], &m[0], 2*COLS512*sizeof(uint32_t));
  for (i = 0; i < COLS512; i++) {
    inP[i] = h[i] ^ m[i];
  }

  /* compute Q(m) */
  RND512Q(z,y,U64BIG(0x0000000000000000ull));
  RND512Q(y,z,U64BIG(0x0000000000000001ull));
  RND512Q(z,y,U64BIG(0x0000000000000002ull));
  RND512Q(y,z,U64BIG(0x0000000000000003ull));
  RND512Q(z,y,U64BIG(0x0000000000000004ull));
  RND512Q(y,z,U64BIG(0x0000000000000005ull));
  RND512Q(z,y,U64BIG(0x0000000000000006ull));
  RND512Q(y,z,U64BIG(0x0000000000000007ull));
  RND512Q(z,y,U64BIG(0x0000000000000008ull));
  RND512Q(y,outQ,U64BIG(0x0000000000000009ull));

  /* compute P(h+m) */
  RND512P(inP,z,U64BIG(0x0000000000000000ull));
  RND512P(z,y,  U64BIG(0x0100000000000000ull));
  RND512P(y,z,  U64BIG(0x0200000000000000ull));
  RND512P(z,y,  U64BIG(0x0300000000000000ull));
  RND512P(y,z,  U64BIG(0x0400000000000000ull));
  RND512P(z,y,  U64BIG(0x0500000000000000ull));
  RND512P(y,z,  U64BIG(0x0600000000000000ull));
  RND512P(z,y,  U64BIG(0x0700000000000000ull));
  RND512P(y,z,  U64BIG(0x0800000000000000ull));
  RND512P(z,y,  U64BIG(0x0900000000000000ull));

  /* h' == h + Q(m) + P(h+m) */
  for (i = 0; i < COLS512; i++) {
    h[i] ^= outQ[i] ^ y[i];
  }
}

/* given state h, do h <- P(h)+h */
void OutputTransformation(uint64_t *chaining) {
    uint64_t temp[COLS512];
    uint64_t y[COLS512];
    uint64_t z[COLS512];

    memcpy(temp, chaining, COLS512*sizeof(uint64_t));

    RND512P(temp,z,U64BIG(0x0000000000000000ull));
    RND512P(z,y,U64BIG(0x0100000000000000ull));
    RND512P(y,z,U64BIG(0x0200000000000000ull));
    RND512P(z,y,U64BIG(0x0300000000000000ull));
    RND512P(y,z,U64BIG(0x0400000000000000ull));
    RND512P(z,y,U64BIG(0x0500000000000000ull));
    RND512P(y,z,U64BIG(0x0600000000000000ull));
    RND512P(z,y,U64BIG(0x0700000000000000ull));
    RND512P(y,z,U64BIG(0x0800000000000000ull));
    RND512P(z,temp,U64BIG(0x0900000000000000ull));
    for (int j = 0; j < COLS512; j++) {
      chaining[j] ^= temp[j];
    }
}

#define MSGLEN 200

void xmr_groestl(const BitSequence* input, BitSequence* output) {
  // INIT
    uint64_t chaining[SIZE512/sizeof(uint64_t)]; /* actual state */
    BitSequence buffer[SIZE512];      /* data buffer */

    /* set initial value */
    memset(chaining, 0, COLS512*sizeof(uint64_t));
    chaining[COLS512-1] = U64BIG((uint64_t)HASH_BIT_LEN);

  // UPDATE
    /* digest bulk of message */
    uint64_t block_counter = MSGLEN/SIZE512;
    F512(chaining,(uint64_t*)input);
    F512(chaining,(uint64_t*)(input+64));
    F512(chaining,(uint64_t*)(input+128));

    /* store remaining data in buffer */
    #define CURRPOS (MSGLEN/SIZE512)*SIZE512 // 192
    const int i = MSGLEN - CURRPOS;  // 8
    int buf_ptr = i; // 8
    memcpy(buffer, &input[CURRPOS], i);

  // FINAL
    const int hashbytelen = HASH_BIT_LEN/8;
    uint8_t *s = (BitSequence*)chaining;

    /* pad with '1'-bit and first few '0'-bits */
    buffer[buf_ptr++] = 0x80;

    /* pad with '0'-bits */
    memset(&buffer[buf_ptr], 0, (SIZE512-LENGTHFIELDLEN) - buf_ptr);

    /* length padding */
    block_counter++;
    buf_ptr = SIZE512;
    while (buf_ptr > SIZE512-LENGTHFIELDLEN) {
        buffer[--buf_ptr] = (uint8_t)block_counter;
        block_counter >>= 8;
    }

    /* digest final padding block */
    F512(chaining,(uint64_t*)buffer);
    /* perform output transformation */
    OutputTransformation(chaining);

    /* store hash result in output */
    memcpy(output, &s[SIZE512-hashbytelen], SIZE512 - (SIZE512-hashbytelen));
}
