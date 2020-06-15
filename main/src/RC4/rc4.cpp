#include <string.h>
#include "rc4.h"



void arc4_init( arc4_context *ctx )
{
    memset( ctx, 0, sizeof( arc4_context ) );
}


/*
 * ARC4 key schedule
 */
void arc4_setup( arc4_context *ctx, const unsigned char *key,
                 unsigned int keylen )
{
    int i, j, a;
    unsigned int k;
    unsigned char *m;

    ctx->x = 0;
    ctx->y = 0;
    m = ctx->m;

    for( i = 0; i < 256; i++ )
        m[i] = (unsigned char) i;

    j = k = 0;

    for( i = 0; i < 256; i++, k++ )
    {
        if( k >= keylen ) k = 0;

        a = m[i];
        j = ( j + a + key[k] ) & 0xFF;
        m[i] = m[j];
        m[j] = (unsigned char) a;
    }
}


/*
 * ARC4 cipher function
 */
int arc4_crypt( arc4_context *ctx, unsigned int length, const unsigned char *input,
                unsigned char *output )
{
    int x, y, a, b;
    unsigned int i;
    unsigned char *m;

    x = ctx->x;
    y = ctx->y;
    m = ctx->m;

    for( i = 0; i < length; i++ )
    {
        x = ( x + 1 ) & 0xFF; a = m[x];
        y = ( y + a ) & 0xFF; b = m[y];

        m[x] = (unsigned char) b;
        m[y] = (unsigned char) a;

        output[i] = (unsigned char)
            ( input[i] ^ m[(unsigned char)( a + b )] );
    }

    ctx->x = x;
    ctx->y = y;

    return( 0 );
}
