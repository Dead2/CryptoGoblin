#pragma once
#include "../common.h"

// update the state
template<int rounds> void keccakf(uint64_t st[25]);

// compute a keccak hash (md) of given byte length from "in"
template<int mdlen> void keccak(const uint8_t *in, int inlen, uint8_t *md);

