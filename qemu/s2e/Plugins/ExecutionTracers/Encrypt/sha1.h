/* public api for steve reid's public domain SHA-1 implementation */
/* this file is in the public domain */

#pragma once

#include "Platform.h"

struct SHA1_CTX
{
    uint32_t state[5];
    uint32_t count[2];
    uint8_t  buffer[64];
};

#define SHA1_DIGEST_SIZE 20

struct ShaDigest {
  uint8_t bytes[SHA1_DIGEST_SIZE];
};

void SHA1_Init(SHA1_CTX* context);
void SHA1_Update(SHA1_CTX* context, const uint8_t* data, const size_t len);
void SHA1_Final(SHA1_CTX* context, ShaDigest digest);

// digest1 = digest1 XOR digest2
void SHA1_xhash(ShaDigest digest1, const ShaDigest digest2);
void SHA1_initXHash(ShaDigest digest);

void digest_to_hex(const ShaDigest digest, char *output);
