/****************************************************************************
Classification: U//FOUO
*//**
	@file   Aes.c
	@brief  Handles AES computation.
	@author Andrew Gorczyca
	@date   2012/5/25

	Based on axtls implementation, by Cameron Rich. Improvements made mostly
	to cbc handling, reducing unnecessary copying and intermediary buffers.
	Added code to generate both Rijndael S-box lookups in memory. Reduced
	Round constants to ones actally used. mul2 from Dr. Gladman. I've only
	personally tested this on little Endian machines, but it might
	*possibly* work on a big endian platform.
****************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"

#define AES_MAXROUNDS   14  /**< @brief max potential rounds */
#define AES_BLOCKSIZE   16  /**< @brief Blocksize of aes encryption - 128bit */

/** @brief Specifies keylength */
typedef enum
{
    AES_MODE_128,
    AES_MODE_256
} AES_MODE;

/** @brief This structure holds the AES key context */
typedef struct aes_key_st
{
    uint16_t rounds;                    /**< @brief # of rounds - based on keysize */
    uint16_t key_size;                  /**< @brief keysize int bits */
    uint32_t ks[(AES_MAXROUNDS+1)*8];   /**< @brief hold the different keystates */
} AES_CTX;

/****************************************************************************
AES_set_key
*//**
    @brief  Setup the AES key context

    @param[in]  ctx     AES context structure
    @param[in]  key     The buffer containing the key to set
    @param[in]  mode 	Enum of supported AES keysizes
****************************************************************************/
void AES_set_key(AES_CTX *ctx, const uint8_t *key, AES_MODE mode);

/****************************************************************************
AES_convert_key
*//**
    @brief  Converts the AES key context from encryption to decryption

    @param[in]  ctx     AES context structure
****************************************************************************/
void AES_convert_key(AES_CTX *ctx);

#ifndef htons
#define htons(A) ((((uint16_t)(A) & 0xff00) >> 8) | \
(((uint16_t)(A) & 0x00ff) << 8))
#define htonl(A) ((((uint32_t)(A) & 0xff000000) >> 24) | \
(((uint32_t)(A) & 0x00ff0000) >> 8) | \
(((uint32_t)(A) & 0x0000ff00) << 8) | \
(((uint32_t)(A) & 0x000000ff) << 24))
#define ntohs htons
#define ntohl htonl
#endif

#define rot1(x) (((x) << 24) | ((x) >> 8))
#define rot2(x) (((x) << 16) | ((x) >> 16))
#define rot3(x) (((x) <<  8) | ((x) >> 24))

#define mt  0x80808080
#define mh  0xfefefefe
#define mm  0x1b1b1b1b
#define mul2(x,t)	((t)=((x)&mt), ((((x)+(x))&mh)^(((t)-((t)>>7))&mm)))

#define inv_mix_col(x,f2,f4,f8,f9) (\
			(f2)=mul2(x,f2), \
			(f4)=mul2(f2,f4), \
			(f8)=mul2(f4,f8), \
			(f9)=(x)^(f8), \
			(f8)=((f2)^(f4)^(f8)), \
			(f2)^=(f9), \
			(f4)^=(f9), \
			(f8)^=rot3(f2), \
			(f8)^=rot2(f4), \
			(f8)^rot1(f9))

static uint8_t aes_sbox[256];		/** AES S-box  */
static uint8_t aes_isbox[256];	/** AES iS-box */

/** AES round constants */
static const uint8_t Rcon[]=
{
	0x01,0x02,0x04,0x08,0x10,0x20,
	0x40,0x80,0x1b,0x36,0x6c,0xd8
};

/* ----- static functions ----- */
static void AES_encrypt(const AES_CTX *ctx, uint32_t *data);
static void AES_decrypt(const AES_CTX *ctx, uint32_t *data);
static void AES_hncpy32(uint32_t * dst, uint32_t * src);
static uint8_t AES_xtime(uint32_t x);
static void AES_generateSBox(void);

/* Perform doubling in Galois Field GF(2^8) using the irreducible polynomial
   x^8+x^4+x^3+x+1 */
static uint8_t AES_xtime(uint32_t x)
{
	return (x&0x80) ? (x<<1)^0x1b : x<<1;
}

/** Set up AES with the key/iv and cipher size. */
void AES_set_key(AES_CTX *ctx, const uint8_t *key, AES_MODE mode)
{
	int i, words;
	uint32_t tmp, tmp2;
	const uint8_t * rtmp = Rcon;

	switch (mode)
	{
	case AES_MODE_128:
		ctx->rounds = 10;
		words = 4;
		break;
	case AES_MODE_256:
		ctx->rounds = 14;
		words = 8;
		AES_hncpy32((uint32_t *)((ctx->ks)+4), (uint32_t *)(key + AES_BLOCKSIZE));
		break;
	default:        /* fail silently */
		return;
	}

	AES_hncpy32((uint32_t *)(ctx->ks), (uint32_t *)key);
	ctx->key_size = words;
	for (i = words; i <  4 * (ctx->rounds+1); i++)
	{
		tmp = ctx->ks[i-1];

		if ((i % words) == 0)
		{
			tmp2 =(uint32_t)aes_sbox[(tmp    )&0xff]<< 8;
			tmp2|=(uint32_t)aes_sbox[(tmp>> 8)&0xff]<<16;
			tmp2|=(uint32_t)aes_sbox[(tmp>>16)&0xff]<<24;
			tmp2|=(uint32_t)aes_sbox[(tmp>>24)     ];
			tmp=tmp2^(((uint32_t)*rtmp)<<24);
			rtmp++;
		}

		if ((words == 8) && ((i % words) == 4))
		{
			tmp2 =(uint32_t)aes_sbox[(tmp    )&0xff]    ;
			tmp2|=(uint32_t)aes_sbox[(tmp>> 8)&0xff]<< 8;
			tmp2|=(uint32_t)aes_sbox[(tmp>>16)&0xff]<<16;
			tmp2|=(uint32_t)aes_sbox[(tmp>>24)     ]<<24;
			tmp=tmp2;
		}

		ctx->ks[i]=ctx->ks[i-words]^tmp;
	}
}

/** Change a key for decryption. */
void AES_convert_key(AES_CTX *ctx)
{
	int i;
	uint32_t *k,w,t1,t2,t3,t4;

	k = ctx->ks;
	k += 4;

	for (i= ctx->rounds*4; i > 4; i--)
	{
		w= *k;
		w = inv_mix_col(w,t1,t2,t3,t4);
		*k++ =w;
	}
}

static void AES_hncpy32(uint32_t * dst, uint32_t * src)
{
	dst[0] = htonl(src[0]);
	dst[1] = htonl(src[1]);
	dst[2] = htonl(src[2]);
	dst[3] = htonl(src[3]);
}

/** Encrypt a single block (16 bytes) of data */
static void AES_encrypt(const AES_CTX *ctx, uint32_t *data)
{
    /* To make this code smaller, generate the sbox entries on the fly.
     * This will have a really heavy effect upon performance.
     */
    uint32_t tmp[4];
    uint32_t tmp1, old_a0, a0, a1, a2, a3, row;
    int curr_rnd;
    int rounds = ctx->rounds;
    const uint32_t *k = ctx->ks;

    /* Pre-round key addition */
    for (row = 0; row < 4; row++)
        data[row] ^= *(k++);

    /* Encrypt one block. */
    for (curr_rnd = 0; curr_rnd < rounds; curr_rnd++)
    {
        /* Perform ByteSub and ShiftRow operations together */
        for (row = 0; row < 4; row++)
        {
            a0 = (uint32_t)aes_sbox[(data[row%4]>>24)&0xFF];
            a1 = (uint32_t)aes_sbox[(data[(row+1)%4]>>16)&0xFF];
            a2 = (uint32_t)aes_sbox[(data[(row+2)%4]>>8)&0xFF];
            a3 = (uint32_t)aes_sbox[(data[(row+3)%4])&0xFF];

            /* Perform MixColumn iff not last round */
            if (curr_rnd < (rounds - 1))
            {
                tmp1 = a0 ^ a1 ^ a2 ^ a3;
                old_a0 = a0;
                a0 ^= tmp1 ^ AES_xtime(a0 ^ a1);
                a1 ^= tmp1 ^ AES_xtime(a1 ^ a2);
                a2 ^= tmp1 ^ AES_xtime(a2 ^ a3);
                a3 ^= tmp1 ^ AES_xtime(a3 ^ old_a0);
            }

            tmp[row] = ((a0 << 24) | (a1 << 16) | (a2 << 8) | a3);
        }

        /* KeyAddition - note that it is vital that this loop is separate from
           the MixColumn operation, which must be atomic...*/
        for (row = 0; row < 4; row++)
            data[row] = tmp[row] ^ *(k++);
    }
}

/** Decrypt a single block (16 bytes) of data */
static void AES_decrypt(const AES_CTX *ctx, uint32_t *data)
{
    uint32_t tmp[4];
    uint32_t xt0,xt1,xt2,xt3,xt4,xt5,xt6;
    uint32_t a0, a1, a2, a3, row;
    int curr_rnd;
    int rounds = ctx->rounds;
    const uint32_t *k = ctx->ks + ((rounds+1)*4);

    /* pre-round key addition */
    for (row=4; row > 0;row--)
        data[row-1] ^= *(--k);

    /* Decrypt one block */
	for (curr_rnd = 0; curr_rnd < rounds; curr_rnd++)
	{
		/* Perform ByteSub and ShiftRow operations together */
		for (row = 4; row > 0; row--)
		{
			a0 = aes_isbox[(data[(row+3)%4]>>24)&0xFF];
			a1 = aes_isbox[(data[(row+2)%4]>>16)&0xFF];
			a2 = aes_isbox[(data[(row+1)%4]>>8)&0xFF];
			a3 = aes_isbox[(data[row%4])&0xFF];

			/* Perform MixColumn iff not last round */
			if (curr_rnd<(rounds-1))
			{
				/* The MDS cofefficients (0x09, 0x0B, 0x0D, 0x0E)
					are quite large compared to encryption; this
					operation slows decryption down noticeably. */
				xt0 = AES_xtime(a0^a1);
				xt1 = AES_xtime(a1^a2);
				xt2 = AES_xtime(a2^a3);
				xt3 = AES_xtime(a3^a0);
				xt4 = AES_xtime(xt0^xt1);
				xt5 = AES_xtime(xt1^xt2);
				xt6 = AES_xtime(xt4^xt5);

				xt0 ^= a1^a2^a3^xt4^xt6;
				xt1 ^= a0^a2^a3^xt5^xt6;
				xt2 ^= a0^a1^a3^xt4^xt6;
				xt3 ^= a0^a1^a2^xt5^xt6;
				tmp[row-1] = ((xt0<<24)|(xt1<<16)|(xt2<<8)|xt3);
			}
			else
				tmp[row-1] = ((a0<<24)|(a1<<16)|(a2<<8)|a3);
		}
		for (row = 4; row > 0; row--)
			data[row-1] = tmp[row-1] ^ *(--k);
	}
}

void AES_Encrypt(unsigned char *data, unsigned char *key)
{
	AES_CTX	ctx;
	uint32_t buf[4];

    buf[0] = ntohl(((uint32_t *)data)[0]);
    buf[1] = ntohl(((uint32_t *)data)[1]);
    buf[2] = ntohl(((uint32_t *)data)[2]);
    buf[3] = ntohl(((uint32_t *)data)[3]);

	AES_generateSBox();
	AES_set_key(&ctx, key, AES_MODE_128);

    AES_encrypt(&ctx, buf);

    AES_hncpy32((uint32_t *)data,buf);
}

void AES_Decrypt(unsigned char *data, unsigned char *key)
{
	AES_CTX	ctx;
	uint32_t buf[4];

    AES_hncpy32(buf,(uint32_t *)data);

	AES_generateSBox();
	AES_set_key(&ctx, key, AES_MODE_128);
	AES_convert_key(&ctx);

    AES_decrypt(&ctx, buf);

    ((uint32_t *)data)[0] = htonl(buf[0]);
    ((uint32_t *)data)[1] = htonl(buf[1]);
    ((uint32_t *)data)[2] = htonl(buf[2]);
    ((uint32_t *)data)[3] = htonl(buf[3]);
}

void AES_generateSBox(void)
{
	uint32_t t[256], i;
	uint32_t x;
	for (i = 0, x = 1; i < 256; i ++)
	{
		t[i] = x;
		x ^= (x << 1) ^ ((x >> 7) * 0x11B);
	}

	aes_sbox[0]	= 0x63;
	for (i = 0; i < 255; i ++)
	{
		x = t[255 - i];
		x |= x << 8;
		x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7);
		aes_sbox[t[i]] = (x ^ 0x63) & 0xFF;
	}
	for (i = 0; i < 256;i++)
	{
		aes_isbox[aes_sbox[i]]=i;
	}
}
