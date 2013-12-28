#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#define BLOCK_SIZE 128 // byte 
#define FINAL_BLOCK_SIZE (BLOCK_SIZE - 16)
#define SHA512_ROUNDS 80
#define DIGEST_LEN_SHA512 512 / 8 // byte

static void sha512_block(uint64_t h[], const uint64_t blk[]);


/* K(t) */
static uint64_t K[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

/* H */
static uint64_t H[] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

#define LROT(x, s) (((x) << (s)) | ((x) >> (64 - (s))))
#define RROT(x, s) (((x) >> (s)) | ((x) << (64 - (s))))

#define B(v, i) ((v) & (0xFF << (i) * 8))

static uint32_t reverse_endian32(uint32_t w)
{
    return (B(w, 0) << 24) | (B(w, 1) << 8) | (B(w, 2) >> 8) | (B(w, 3) >> 24);
}

static uint64_t reverse_endian64(uint64_t w)
{
    return ((uint64_t)reverse_endian32(w & 0xFFFFFFFFll) << 32) |
        reverse_endian32(w >> 32);
}

/* sha512 compression functions */
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define CH(x, y, z) (((x) & (y)) ^ ((~x) & (z)))

static uint64_t s0(uint64_t w)
{
    return RROT(w, 1) ^ RROT(w, 8) ^ (w >> 7);
}

static uint64_t s1(uint64_t w)
{
    return RROT(w, 19) ^ RROT(w, 61) ^ (w >> 6);
}

static uint64_t S0(uint64_t x)
{
    return RROT(x, 28) ^ RROT(x, 34) ^ RROT(x, 39);
}

static uint64_t S1(uint64_t x)
{
    return RROT(x, 14) ^ RROT(x, 18) ^ RROT(x, 41);
}


void sha512(const unsigned char message[], int len, unsigned char result[])
{
    int pos = 0;
    int remain = 0;
    int padded = 0;
    int i, j;

    const unsigned char pad = 1 << 7; // first byte of padding
    uint64_t X[BLOCK_SIZE / sizeof(uint64_t)]; /* 1024bit block = 64bit * 16 */
    uint64_t la[2];
    unsigned char buf[BLOCK_SIZE]; // for last/carry block
    uint64_t h[] = { H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7] };

    memset(buf, 0, sizeof(buf));

    while (len - pos >= BLOCK_SIZE) {
        memcpy(X, &message[pos], sizeof(X));
        sha512_block(h, X);
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
        sha512_block(h, X);
        padded = 1;
        memset(buf, 0, sizeof(buf));
    }

    // step1: padding
    if (!padded)
        buf[remain] = pad;

    // step2: append length
    la[1] = reverse_endian64(len << 3); // byte to int
    la[0] = 0; // assuming length < 4Gb
    memcpy(buf + FINAL_BLOCK_SIZE, la, sizeof(la));
    
    // run final block
    memcpy(X, buf, sizeof(buf));
    sha512_block(h, X);


    for (i = 0; i < 8; i++) {
        h[i] = reverse_endian64(h[i]);
    }
    memcpy(result, h, sizeof(h));

    /* clear h to maintain security */
    memset(h, 0, sizeof(h));
}


static void sha512_block(uint64_t hash[], const uint64_t blk[])
{
    uint64_t a = hash[0];
    uint64_t b = hash[1];
    uint64_t c = hash[2];
    uint64_t d = hash[3];
    uint64_t e = hash[4];
    uint64_t f = hash[5];
    uint64_t g = hash[6];
    uint64_t h = hash[7];
    
    uint64_t W[SHA512_ROUNDS];

    int i;
    
    for (i = 0; i < 16; i++) {
        W[i] = reverse_endian64(blk[i]);
    }

    for (i = 16; i < SHA512_ROUNDS; i++) {
        W[i] = W[i-16] + s0(W[i-15]) + W[i-7] + s1(W[i-2]);
    }

#ifdef DEBUG
    printf("sha512_block <\n");
    for (i = 0; i < 16; i++) {
        printf(" %016"PRIx64, W[i]);
        if (i > 0 && (i + 1) % 8 == 0)
            printf("\n");
    }
    printf("\n");
    printf("init: %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64"\n",
           a, b, c, d, e, f, g, h);
#endif

    for (i = 0; i < SHA512_ROUNDS; i++) {
        uint64_t t1 = h + S1(e) + CH(e, f, g) + K[i] + W[i];
        uint64_t t2 = S0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;

#ifdef DEBUG
    printf("[%2d]: %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64"\n",
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
    printf("sha512_block > : %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64"\n",
           hash[0], hash[1], hash[2], hash[3],
           hash[4], hash[5], hash[6], hash[7]);
#endif
}
