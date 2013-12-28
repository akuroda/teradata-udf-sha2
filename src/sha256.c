#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

static void sha256_block(uint32_t h[], const uint32_t blk[]);

#define BLOCK_SIZE 64
#define FINAL_BLOCK_SIZE (BLOCK_SIZE - 8)
#define SHA256_ROUNDS 64

/* K(t) */
static uint32_t K[] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* H */
static uint32_t H[] = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

#define LROT(x, s) (((x) << (s)) | ((x) >> (32 - (s))))
#define RROT(x, s) (((x) >> (s)) | ((x) << (32 - (s))))

#define B(v, i) ((v) & (0xFF << (i) * 8))

static uint32_t reverse_endian(uint32_t w)
{
    return (B(w, 0) << 24) | (B(w, 1) << 8) | (B(w, 2) >> 8) | (B(w, 3) >> 24);
}

/* sha256 compression functions */
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define CH(x, y, z) (((x) & (y)) ^ ((~x) & (z)))

static uint32_t s0(uint32_t w)
{
    return RROT(w, 7) ^ RROT(w, 18) ^ (w >> 3);
}

static uint32_t s1(uint32_t w)
{
    return RROT(w, 17) ^ RROT(w, 19) ^ (w >> 10);
}

static uint32_t S1(uint32_t x)
{
    return RROT(x, 6) ^ RROT(x, 11) ^ RROT(x, 25);
}

static uint32_t S0(uint32_t x)
{
    return RROT(x, 2) ^ RROT(x, 13) ^ RROT(x, 22);
}


void sha256(const unsigned char message[], int len, unsigned char result[])
{
    int pos = 0;
    int remain = 0;
    int padded = 0;
    int i, j;

    uint32_t X[BLOCK_SIZE / sizeof(int)]; /* 512bit block = 32bit * 16 */
    const unsigned char pad = 1 << 7; // first byte of padding
    uint32_t la[2];
    unsigned char buf[BLOCK_SIZE]; // for last/carry block
    uint32_t h[] = { H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7] };

    memset(buf, 0, sizeof(buf));

    while (len - pos >= BLOCK_SIZE) {
        memcpy(X, &message[pos], sizeof(X));
        sha256_block(h, X);
        pos += BLOCK_SIZE;
    }

    remain = len - pos;
    if (remain > 0) {
        memcpy(buf, &message[pos], remain);
    }

    // cannot put length field in final block
    if (remain > FINAL_BLOCK_SIZE - 1) {
        buf[remain] = pad;
        memcpy(X, buf, sizeof(buf));
        sha256_block(h, X);
        padded = 1;
        memset(buf, 0, sizeof(buf));
    }

    // step1: padding
    if (!padded)
        buf[remain] = pad;

    // step2: append length
    la[1] = reverse_endian(len << 3); // byte to int
    la[0] = 0; // assuming length < 4Gb
    memcpy(buf + FINAL_BLOCK_SIZE, la, sizeof(la));
    
    // run final block
    memcpy(X, buf, sizeof(buf));
    sha256_block(h, X);

    for (i = 0; i < 8; i++) {
        h[i] = reverse_endian(h[i]);
    }
    memcpy(result, h, sizeof(h));
}


static void sha256_block(uint32_t hash[], const uint32_t blk[])
{
    uint32_t a = hash[0];
    uint32_t b = hash[1];
    uint32_t c = hash[2];
    uint32_t d = hash[3];
    uint32_t e = hash[4];
    uint32_t f = hash[5];
    uint32_t g = hash[6];
    uint32_t h = hash[7];
    
    uint32_t W[SHA256_ROUNDS];

    int i;
    
    for (i = 0; i < 16; i++) {
        W[i] = reverse_endian(blk[i]);
    }

    for (i = 16; i < SHA256_ROUNDS; i++) {
        W[i] = W[i-16] + s0(W[i-15]) + W[i-7] + s1(W[i-2]);
    }

#ifdef DEBUG
    printf("sha256_block <\n");
    for (i = 0; i < 16; i++) {
        printf(" %08x", W[i]);
        if (i > 0 && (i + 1) % 8 == 0)
            printf("\n");
    }
    printf("\n");
    printf("init: %x %x %x %x %x %x %x %x\n",
           a, b, c, d, e, f, g, h);
#endif

    for (i = 0; i < SHA256_ROUNDS; i++) {
        uint32_t t1 = h + S1(e) + CH(e, f, g) + K[i] + W[i];
        uint32_t t2 = S0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;

#ifdef DEBUG
    printf("[%2d]: %08x %08x %08x %08x %08x %08x %08x %08x\n",
           i, a, b, c, d, e, f, g, h);
#endif
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;

#ifdef DEBUG
    printf("sha256_block > : %08x %08x %08x %08x %08x %08x %08x %08x\n",
           hash[0], hash[1], hash[2], hash[3],
           hash[4], hash[5], hash[6], hash[7]);
#endif
}
