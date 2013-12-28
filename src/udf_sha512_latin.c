#define SQL_TEXT Latin_Text
#include "sqltypes_td.h"
#include <stdlib.h>
#include <string.h>

#define DIGEST_LEN_SHA512 64
#define UDF_OK "00000"

void sha512(const unsigned char message[], int len, unsigned char result[]);

void sha512_latin(VARCHAR_LATIN *arg, CHARACTER_LATIN *result,
 char sqlstate[])
{
    int i;
    unsigned char outbuf[DIGEST_LEN_SHA512];

    sha512((unsigned char *)arg, strlen((char *)arg), outbuf);

    for (i = 0; i < DIGEST_LEN_SHA512; i++) {
        sprintf(result + i*2, "%02x", outbuf[i]);
    }

    sprintf(sqlstate, UDF_OK);
}
