/**
 \file 		crypto.h
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
 \brief		Crypto primitive class
 */

#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <openssl/evp.h>
#include "../constants.h"
#include <mutex>

// forward declarations
class pk_crypto;
class CSocket;

const uint8_t ZERO_IV[AES_BYTES] = { 0 };

const uint8_t const_seed[2][16] = {{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
		{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 } };

enum bc_mode {
	ECB, CBC
};

//Check for the OpenSSL version number, since the EVP_CIPHER_CTX has become opaque from >= 1.1.0
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	#define OPENSSL_OPAQUE_EVP_CIPHER_CTX
#endif

#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
typedef EVP_CIPHER_CTX* AES_KEY_CTX;
#else
typedef EVP_CIPHER_CTX AES_KEY_CTX;
#endif

/* Predefined security levels,
 * ST (SHORTTERM) = 1024/160/163 bit public key, 80 bit private key
 * MT (MEDIUMTERM) = 2048/192/233 bit public key, 112 bit private key
 * LT (LONGTERM) = 3072/256/283 bit public key, 128 bit private key
 * XLT (EXTRA LONGTERM) = 7680/384/409 bit public key, 192 bit private key
 * XXLT (EXTRA EXTRA LONGTERM) = 15360/512/571 bit public key, 256 bit private key
 */

struct prf_state_ctx {
	A