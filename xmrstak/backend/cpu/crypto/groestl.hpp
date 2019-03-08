#ifndef __hash_h
#define __hash_h

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* some sizes (number of bytes) */
#define ROWS 8
#define LENGTHFIELDLEN ROWS
#define COLS512 8
#define SIZE512 (ROWS*COLS512)

#define ROUNDS512 10
#define HASH_BIT_LEN 256

#define ROTL64(a,n) __rolq(a,n)

#define EXT_BYTE(var,n) ((uint8_t)((uint64_t)(var) >> (8*n)))
#define U64BIG(a) \
  ((ROTL64(a, 8) & (0x000000FF000000FFULL)) | \
   (ROTL64(a,24) & (0x0000FF000000FF00ULL)) | \
   (ROTL64(a,40) & (0x00FF000000FF0000ULL)) | \
   (ROTL64(a,56) & (0xFF000000FF000000ULL)))


typedef unsigned char BitSequence;
void xmr_groestl(const BitSequence* input, BitSequence* output);

#endif /* __hash_h */
