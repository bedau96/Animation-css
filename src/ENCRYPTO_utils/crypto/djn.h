/**
 \file 		djn.h
 \author 	Daniel Demmler
 \copyright Copyright (C) 2019 ENCRYPTO Group, TU Darmstadt
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

 \brief
 libdjn - v0.9
 A library implementing the Damgaard Jurik Nielsen cryptosystem with s=1 (~Paillier).
 based on:
 libpaillier - A library implementing the Paillier cryptosystem.
 (http://hms.isi.jhu.edu/acsc/libpaillier/)
 */

#ifndef _DJN_H_
#define _DJN_H_
#include <gmp.h>

/*
 On memory handling:

 At no point is any special effort made to securely "shred" sensitive
 memory or prevent it from being paged out to disk. This means that
 it is important that functions dealing with private keys and
 plaintexts (e.g., djn_keygen and djn_enc) only be run on
 trusted machines. The resulting ciphertexts and public keys,
 however, may of course be handled in an untrusted manner.

 */

/******
 TYPES
 *******/

/*
 This represents a public key, which is the modulus n plus a generator h.
 */
struct djn_pubkey_t {
	int bits; /* e.g., 1024 */
	int rbits; /* e.g., 512 */
	mpz_t n; /* public modulus n = p q */
	mpz_t n_squared; /* cached to avoid recomputing */
	mpz_t h; /* generator h = -x^2 mod n */
	mpz_t h_s; /* h_s = h^n mod n^2 */
};

/*
 This represents a Paillier private key; it needs to be used with a
 djn_pubkey_t to be meaningful. It includes the Carmichael
 function (lambda) of the modulus. The other value is kept for
 efficiency and should be considered private.
 */
struct djn_prvkey_t {
	mpz_t lambda; /* lambda(n), i.e., lcm(p-1,q-1) */
	mpz_t lambda_inverse; /* inverse of lambda (mod n)*/
	mpz_t p; /* cached to avoid recomputing */
	mpz_t q; /* cached to avoid recomputing */
	mpz_t q_inverse; /* inverse of q (mod p) */
	mpz_t q_squared_inverse; /* inverse of q^2 (mod p^2) */
	mpz_t p_minusone; /* cached to avoid recomputing */
	mpz_t q_minusone; /* cached to avoid recomputing */
	mpz_t p_squared; /* cached to avoid recomputing */
	mpz_t q_squared; /* cached to avoid recomputing */
	mpz_t ordpsq; /* p^2-p */
	mpz_t ordqsq; /* q^2-q */
};

/*
 This is the type of the callback functions used to obtain the
 randomness needed by the probabilistic algorithms. The functions
 djn_get_rand_devrandom and djn_get_rand_devurandom
 (documented later) may be passed to any library function requiring a
 djn_get_rand_t, or you may implement your own. If you implement
 your own such function, it should fill in "len" random bytes in the
 array "buf".
 */
typedef void (*djn_get_rand_t)(void* buf, int len);

/*****************
 BASIC OPERATIONS
 *****************/

/*
 Generate a keypair of length modulusbits using randomness from the
 provided get_rand function. Space will be allocated for each of the
 keys, and the given pointers will be set to point to the new
 djn_pubkey_t and djn_prvkey_t structures. The functions
 djn_get_rand_devrandom and djn_get_rand_devurandom may be
 passed as the final argument.
 */
void djn_keygen(unsigned int modulusbits, djn_pubkey_t** pub, djn_prvkey_t** prv);

/*
 Encrypt the given plaintext with the given public key using
 randomness from get_rand for blinding. If res is not null, its
 contents will be overwritten with the result. Otherwise, a new
 djn_ciphertext_t will be allocated and returned.
 */
void djn_encrypt(mpz_t res, djn_pubkey_t* pub, mpz_t pt);

/*
 Encrypt the given plaintext with t