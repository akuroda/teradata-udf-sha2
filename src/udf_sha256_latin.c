#define SQL_TEXT Latin_Text
#include "sqltypes_td.h"
#include <stdlib.h>
#include <string.h>

#define DIGEST_LEN_SHA256 32
#define UDF_OK "00000"

void sha256(const unsigned char message[], int len, unsigned char result[]);

void sha256_latin(VARCHAR_LATIN *arg, CHARACTER_LATIN *result,
 char sqlstate[])
{
    int i;
    unsigned char outbuf[DIGEST_LEN_SHA256];

    sha256((unsigned char *)arg, strlen((char *)arg), outbuf);

    for (i = 0; i < DIGEST_LEN_SHA256; i++) {
        sprintf(result + i*2, "%02x", outbuf[i]);
    }

    sprintf(sqlstate, UDF_OK);
}
