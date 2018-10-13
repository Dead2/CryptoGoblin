#pragma once
#include "../common.h"

// update the state
void keccakf_24(uint64_t st[25]);

// compute a keccak hash (md) of given byte length from "in"
void keccak_200(const uint8_t *in, int inlen, uint8_t *md);

