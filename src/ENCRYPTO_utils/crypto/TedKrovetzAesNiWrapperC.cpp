
#include "TedKrovetzAesNiWrapperC.h"
#ifdef USE_PIPELINED_AES_NI

#ifdef _WIN32
#include "StdAfx.h"
#endif

void AES_128_Key_Expansion(const unsigned char *userkey, AES_KEY *aesKey)
{
    block x0,x1,x2;
    //block *kp = (block *)&aesKey;
	aesKey->rd_key[0] = x0 = _mm_loadu_si128((block*)userkey);
    x2 = _mm_setzero_si128();
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 1);   aesKey->rd_key[1] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 2);   aesKey->rd_key[2] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 4);   aesKey->rd_key[3] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 8);   aesKey->rd_key[4] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 16);  aesKey->rd_key[5] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 32);  aesKey->rd_key[6] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 64);  aesKey->rd_key[7] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 128); aesKey->rd_key[8] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 27);  aesKey->rd_key[9] = x0;
	EXPAND_ASSIST(x0, x1, x2, x0, 255, 54);  aesKey->rd_key[10] = x0;
}



void AES_192_Key_Expansion(const unsigned char *userkey, AES_KEY *aesKey)
{
    __m128i x0,x1,x2,x3,tmp,*kp = (block *)&aesKey;
    kp[0] = x0 = _mm_loadu_si128((block*)userkey);
    tmp = x3 = _mm_loadu_si128((block*)(userkey+16));
    x2 = _mm_setzero_si128();
    EXPAND192_STEP(1,1);
    EXPAND192_STEP(4,4);
    EXPAND192_STEP(7,16);
    EXPAND192_STEP(10,64);
}

void AES_256_Key_Expansion(const unsigned char *userkey, AES_KEY *aesKey)
{
	__m128i x0, x1, x2, x3;/* , *kp = (block *)&aesKey;*/
	aesKey->rd_key[0] = x0 = _mm_loadu_si128((block*)userkey);
	aesKey->rd_key[1] = x3 = _mm_loadu_si128((block*)(userkey + 16));
    x2 = _mm_setzero_si128();
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 1);  aesKey->rd_key[2] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 1);  aesKey->rd_key[3] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 2);  aesKey->rd_key[4] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 2);  aesKey->rd_key[5] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 4);  aesKey->rd_key[6] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 4);  aesKey->rd_key[7] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 8);  aesKey->rd_key[8] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 8);  aesKey->rd_key[9] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 16); aesKey->rd_key[10] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 16); aesKey->rd_key[11] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 32); aesKey->rd_key[12] = x0;
	EXPAND_ASSIST(x3, x1, x2, x0, 170, 32); aesKey->rd_key[13] = x3;
	EXPAND_ASSIST(x0, x1, x2, x3, 255, 64); aesKey->rd_key[14] = x0;
}

void AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *aesKey)
{
    if (bits == 128) {
		AES_128_Key_Expansion(userKey, aesKey);
    } else if (bits == 192) {
		AES_192_Key_Expansion(userKey, aesKey);
    } else if (bits == 256) {
		AES_256_Key_Expansion(userKey, aesKey);
    }

	aesKey->rounds = 6 + bits / 32;
}

void AES_encryptC(block *in, block *out,  AES_KEY *aesKey)
{
	int j, rnds = ROUNDS(aesKey);
	const __m128i *sched = ((__m128i *)(aesKey->rd_key));
	__m128i tmp = _mm_load_si128((__m128i*)in);
	tmp = _mm_xor_si128(tmp, sched[0]);
	for (j = 1; j<rnds; j++)  tmp = _mm_aesenc_si128(tmp, sched[j]);
	tmp = _mm_aesenclast_si128(tmp, sched[j]);
	_mm_store_si128((__m128i*)out, tmp);
}


void AES_ecb_encrypt(block *blk,  AES_KEY *aesKey) {
	unsigned j, rnds = ROUNDS(aesKey);
	const block *sched = ((block *)(aesKey->rd_key));

	*blk = _mm_xor_si128(*blk, sched[0]);
	for (j = 1; j<rnds; ++j)
		*blk = _mm_aesenc_si128(*blk, sched[j]);
	*blk = _mm_aesenclast_si128(*blk, sched[j]);
}

void AES_ecb_encrypt_blks(block *blks, unsigned nblks,  AES_KEY *aesKey) {
    unsigned i,j,rnds=ROUNDS(aesKey);