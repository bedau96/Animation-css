/**
 \file 		crypto.cpp
 \author 	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 ENCRYPTO Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Lesser General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			ABY is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Lesser General Public License for more details.
			You should have received a copy of the GNU Lesser General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Implementation of crypto primitive class
 */

#include "crypto.h"
#include "../socket.h"
#include <openssl/sha.h>
#include <openssl/des.h>
#include "ecc-pk-crypto.h"
#include "gmp-pk-crypto.h"
#include <cstring>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <utility>

crypto::crypto(uint32_t symsecbits, uint8_t* seed) {
	init(symsecbits, seed);
}

crypto::crypto(uint32_t symsecbits) {
	uint8_t* seed = (uint8_t*) malloc(sizeof(uint8_t) * AES_BYTES);
	gen_secure_random(seed, AES_BYTES);

	init(symsecbits, seed);
	free(seed);
}

crypto::~crypto() {
	free_prf_state(&global_prf_state);
	free(aes_hash_in_buf);
	free(aes_hash_out_buf);
	free(sha_hash_buf);
	free(aes_hash_buf_y1);
	free(aes_hash_buf_y2);

#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	clean_aes_key(&aes_hash_key);
	clean_aes_key(&aes_enc_key);
	clean_aes_key(&aes_dec_key);
#endif
}

void crypto::init(uint32_t symsecbits, uint8_t* seed) {
	secparam = get_sec_lvl(symsecbits);

#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	aes_hash_key = EVP_CIPHER_CTX_new();
	aes_enc_key = EVP_CIPHER_CTX_new();
	aes_dec_key = EVP_CIPHER_CTX_new();
#endif

	init_prf_state(&global_prf_state, seed);

	aes_hash_in_buf = (uint8_t*) malloc(AES_BYTES);
	aes_hash_out_buf = (uint8_t*) malloc(AES_BYTES);
	aes_hash_buf_y1 = (uint8_t*) malloc(AES_BYTES);
	aes_hash_buf_y2 = (uint8_t*) malloc(AES_BYTES);

	if (secparam.symbits == ST.symbits) {
		hash_routine = &sha1_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA1_OUT_BYTES);
	} else if (secparam.symbits == MT.symbits) {
		hash_routine = &sha256_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA256_OUT_BYTES);
	} else if (secparam.symbits == LT.symbits) {
		hash_routine = &sha256_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA256_OUT_BYTES);
	} else if (secparam.symbits == XLT.symbits) {
		hash_routine = &sha512_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA512_OUT_BYTES);
	} else if (secparam.symbits == XXLT.symbits) {
		hash_routine = &sha512_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA512_OUT_BYTES);
	} else {
		hash_routine = &sha256_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA256_OUT_BYTES);
	}
}

pk_crypto* crypto::gen_field(field_type ftype) {
	uint8_t* pkseed = (uint8_t*) malloc(sizeof(uint8_t) * (secparam.symbits >> 3));
	gen_rnd(pkseed, secparam.symbits >> 3);
	pk_crypto* ret;
	if (ftype == P_FIELD)
		ret = new prime_field(secparam, pkseed);
	else
		ret = new ecc_field(secparam, pkseed);
	free(pkseed);
	return ret;
}

void gen_rnd_bytes(prf_state_ctx* prf_state, uint8_t* resbuf, uint32_t nbytes) {
	AES_KEY_CTX* aes_key;
	uint64_t* rndctr;
	uint8_t* tmpbuf;
	uint32_t i, size;
	int32_t dummy;

	aes_key = &(prf_state->aes_key);
	rndctr = prf_state->ctr;
	size = ceil_divide(nbytes, AES_BYTES);
	tmpbuf = (uint8_t*) malloc(sizeof(uint8_t) * size * AES_BYTES);

	//TODO it might be better to store the result directly in resbuf but this would require the invoking routine to pad it to a multiple of AES_BYTES
	for (i = 0; i < size; i++, rndctr[0]++) {
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
		EVP_EncryptUpdate(*aes_key, tmpbuf + i * AES_BYTES, &dummy, (uint8_t*) rndctr, AES_BYTES);
#else
		EVP_EncryptUpdate(aes_key, tmpbuf + i * AES_BYTES, &dummy, (uint8_t*) rndctr, AES_BYTES);
#endif
	}
	memcpy(resbuf, tmpbuf, nbytes);

	free(tmpbuf);
}

void crypto::gen_rnd(uint8_t* resbuf, uint32_t nbytes) {
	std::lock_guard<std::mutex> lock(global_prf_state_mutex);
	gen_rnd_bytes(&global_prf_state, resbuf, nbytes);
}

void crypto::gen_rnd_uniform(uint32_t* res, uint32_t mod) {
	//pad to multiple of 4 bytes for uint32_t length
	uint32_t nrndbytes = PadToMultiple(bits_in_bytes(secparam.symbits) + ceil_log2(mod), sizeof(uint32_t));
	uint64_t bitsint = (8*sizeof(uint32_t));
	uint32_t rnditers = ceil_divide(nrndbytes * 8, bitsint);

	uint32_t* rndbuf = (uint32_t*) malloc(nrndbytes);
	gen_rnd((uint8_t*) rndbuf, nrndbytes);

	uint64_t tmpval = 0, tmpmod = mod;

	for(uint32_t i = 0; i < rnditers; i++) {
		tmpval = (((uint64_t) (tmpval << bitsint)) | ((uint64_t)rndbuf[i]));
		tmpval %= tmpmod;
	}
	*res = (uint32_t) tmpval;
	free(rndbuf);
}
void crypto::gen_rnd_from_seed(uint8_t* resbuf, uint32_t resbytes, uint8_t* seed) {
	prf_state_ctx tmpstate;
	init_prf_state(&tmpstate, seed);
	gen_rnd_bytes(&tmpstate, resbuf, resbytes);
	free_prf_state(&tmpstate);
}

void crypto::encrypt(AES_KEY_CTX* enc_key, uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	int32_t dummy;
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_EncryptUpdate(*enc_key, resbuf, &dummy, inbuf, ninbytes);
#else
	EVP_EncryptUpdate(enc_key, resbuf, &dummy, inbuf, ninbytes);
#endif
	//EVP_EncryptFinal_ex(enc_key, resbuf, &dummy);
}
void crypto::decrypt(AES_KEY_CTX* dec_key, uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	int32_t dummy;
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_DecryptUpdate(*dec_key, resbuf, &dummy, inbuf, ninbytes);
#else
	EVP_DecryptUpdate(dec_key, resbuf, &dummy, inbuf, ninbytes);
#endif
	//EVP_DecryptFinal_ex(dec_key, resbuf, &dummy);
}

void crypto::encrypt(uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	encrypt(&aes_enc_key, resbuf, inbuf, ninbytes);
}

void crypto::decrypt(uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	decrypt(&aes_dec_key, resbuf, inbuf, ninbytes);
}

void crypto::seed_aes_hash(uint8_t* seed, bc_mode mode, const uint8_t* iv) {
	seed_aes_key(&aes_hash_key, seed, mode, iv);
}

void crypto::seed_aes_enc(uint8_t* seed, bc_mode mode, const uint8_t* iv) {
	seed_aes_key(&aes_enc_key, seed, mode, iv, true);
	seed_aes_key(&aes_dec_key, seed, mode, iv, false);
}

void crypto::init_aes_key(AES_KEY_CTX* aes_key, uint8_t* seed, bc_mode mode, const uint8_t* iv) {
	seed_aes_key(aes_key, seed, mode, iv);
}

void crypto::init_aes_key(AES_KEY_CTX* aes_key, uint32_t symbits, uint8_t* seed, bc_mode mode, const uint8_t* iv, bool encrypt) {
	seed_aes_key(aes_key, symbits, seed, mode, iv, encrypt);
}

void crypto::seed_aes_key(AES_KEY_CTX* aeskey, uint8_t* seed, bc_mode mode, const uint8_t* iv, bool encrypt) {
	seed_aes_key(aeskey, secparam.symbits, seed, mode, iv, encrypt);
}

void crypto::clean_aes_key(AES_KEY_CTX* aeskey) {
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_CIPHER_CTX_free(*aeskey);
#else
	EVP_CIPHER_CTX_cleanup(aeskey);
#endif
}

void crypto::seed_aes_key(AES_KEY_CTX* aeskey, uint32_t symbits, uint8_t* seed, bc_mode mode, const uint8_t* iv, bool encrypt) {
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	*aeskey = EVP_CIPHER_CTX_new();
	AES_KEY_CTX aes_key_tmp = *aeskey;
#else
	EVP_CIPHER_CTX_init(aeskey);
	AES_KEY_CTX* aes_key_tmp = aeskey;
#endif
	int (*initfct)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*);

	if (encrypt)
		initfct = EVP_EncryptInit_ex;
	else
		initfct = EVP_DecryptInit_ex;

	switch (mode) {
	case ECB:
		if (symbits <= 128) {
			initfct(aes_key_tmp, EVP_aes_128_ecb(), NULL, seed, iv);
		} else if(symbits == 192) {
			initfct(aes_key_tmp, EVP_aes_192_ecb(), NULL, seed, iv);
		} else {
			initfct(aes_key_tmp, EVP_aes_256_ecb(), NULL, seed, iv);
		}
		break;
	case CBC:
		if (symbits <= 128) {
			initfct(aes_key_tmp, EVP_aes_128_cbc(), NULL, seed, iv);
		} else if(symbits == 192) {
			initfct(aes_key_tmp, EVP_aes_192_cbc(), NULL, seed, iv);
		} else {
			initfct(aes_key_tmp, EVP_aes_256_cbc(), NULL, seed, iv);
		}
		break;
	default:
		if (symbits <= 128) {
			initfct(aes_key_tmp, EVP_aes_128_ecb(), NULL, seed, iv);
		} else if(symbits == 192) {
			initfct(aes_key_tmp, EVP_aes_192_ecb(), NULL, seed, iv);
		} else {
			initfct(aes_key_tmp, EVP_aes_256_ecb(), NULL, seed, iv);
		}
		break;
	}
}

void crypto::hash_ctr(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint64_t ctr) {
	uint8_t* tmpbuf = (uint8_t*) malloc(ninbytes + sizeof(uint64_t));
	memcpy(tmpbuf, &ctr, sizeof(uint64_t));
	memcpy(tmpbuf + sizeof(uint64_t), inbuf, ninbytes);
	hash_routine(resbuf, noutbytes, tmpbuf, ninbytes+sizeof(uint64_t), sha_hash_buf);
	free(tmpbuf);
}

void crypto::hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes) {
	uint8_t* hash_buf = (uint8_t*) malloc(get_hash_bytes());
	hash_routine(resbuf, noutbytes, inbuf, ninbytes, hash_buf);
	free(hash_buf);
}

void crypto::hash_buf(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* buf) {
	hash_routine(resbuf, noutbytes, inbuf, ninbytes, buf);
}

void crypto::hash_non_threadsafe(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes) {
	hash_routine(resbuf, noutbytes, inbuf, ninbytes, sha_hash_buf);
}

//A fixed-key hashing scheme that uses AES, should not be used fo