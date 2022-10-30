
/**
 \file 		dgk.cpp
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

 \brief		 libdgk - v0.9
 A library implementing the DGK crypto system with full decryption
 Thanks to Marina Blanton for sharing her Miracl DGK implementation from
 M. Blanton and P. Gasti, "Secure and efficient protocols for iris and fingerprint identification" (ESORICS’11)
 with us. We used it as a template for this GMP version.

 The implementation structure was inspired by
 libpailler - A library implementing the Paillier crypto system. (http://hms.isi.jhu.edu/acsc/libpaillier/)
 */

#include "dgk.h"
#include "../powmod.h"
#include "../utils.h"
#include <cstdlib>
#include <cstring>

#define DGK_CHECKSIZE 0

// number of test encryptions and decryptions that are performed to verify a generated key. This will take time, but more are better.
#define KEYTEST_ITERATIONS 1000

//array holding the powers of two
mpz_t* powtwo;

//array for holding temporary values
mpz_t* gvpvqp;

void dgk_complete_pubkey(unsigned int modulusbits, unsigned int lbits, dgk_pubkey_t** pub, mpz_t n, mpz_t g, mpz_t h) {
	*pub = (dgk_pubkey_t*) malloc(sizeof(dgk_pubkey_t));

	mpz_init((*pub)->n);
	mpz_init((*pub)->u);
	mpz_init((*pub)->h);
	mpz_init((*pub)->g);

	mpz_set((*pub)->n, n);
	mpz_setbit((*pub)->u, 2 * lbits + 2);
	mpz_set((*pub)->g, g);
	mpz_set((*pub)->h, h);

	(*pub)->bits = modulusbits;
	(*pub)->lbits = 2 * lbits + 2;
}

void dgk_keygen(unsigned int modulusbits, unsigned int lbits, dgk_pubkey_t** pub, dgk_prvkey_t** prv) {
	mpz_t tmp, tmp2, f1, f2, exp1, exp2, exp3, xp, xq;

	unsigned int found = 0, i;

	//printf("Keygen %u %u\n", modulusbits, lbits);

	/* allocate the new key structures */
	*pub = (dgk_pubkey_t*) malloc(sizeof(dgk_pubkey_t));
	*prv = (dgk_prvkey_t*) malloc(sizeof(dgk_prvkey_t));

	/* initialize our integers */
	mpz_init((*pub)->n);
	mpz_init((*pub)->u);
	mpz_init((*pub)->h);
	mpz_init((*pub)->g);

	mpz_init((*prv)->vp);
	mpz_init((*prv)->vq);
	mpz_init((*prv)->p);
	mpz_init((*prv)->q);
	mpz_init((*prv)->p_minusone);
	mpz_init((*prv)->q_minusone);
	mpz_init((*prv)->pinv);
	mpz_init((*prv)->qinv);

	mpz_inits(tmp, tmp2, f1, f2, exp1, exp2, exp3, xp, xq, NULL);

	lbits = lbits * 2 + 2; // plaintext space needs to 2l+2 in our use case. probably not needed for general use, but four our MT generation.

	(*pub)->bits = modulusbits;
	(*pub)->lbits = lbits;

	// vp and vq are primes
	aby_prng((*prv)->vp, 160);
	mpz_nextprime((*prv)->vp, (*prv)->vp);

	aby_prng((*prv)->vq, 160);
	do {
		mpz_nextprime((*prv)->vq, (*prv)->vq);
	} while (mpz_cmp((*prv)->vp, (*prv)->vq) == 0);

	// u = 2^lbits. u is NOT a prime (different from original DGK to allow full and easy decryption. See Blanton/Gasti Paper for details).
	mpz_setbit((*pub)->u, lbits);

	// p
	while (!found) {
		aby_prng(f1, modulusbits / 2 - 160 - lbits);
		mpz_nextprime(f1, f1);

		mpz_mul((*prv)->p, (*pub)->u, (*prv)->vp);
		mpz_mul((*prv)->p, f1, (*prv)->p);
		mpz_add_ui((*prv)->p, (*prv)->p, 1);
		found = mpz_probab_prime_p((*prv)->p, 50);
	}
	found = 0;

	// q
	while (!found) {
		aby_prng(f2, modulusbits / 2 - 159 - lbits);
		mpz_nextprime(f2, f2);

		mpz_mul((*prv)->q, (*pub)->u, (*prv)->vq);
		mpz_mul((*prv)->q, f2, (*prv)->q);
		mpz_add_ui((*prv)->q, (*prv)->q, 1);
		found = mpz_probab_prime_p((*prv)->q, 50);
	}
	found = 0;

	// p-1, q-1 - this is currently not used
	mpz_sub_ui((*prv)->p_minusone, (*prv)->p, 1);
	mpz_sub_ui((*prv)->q_minusone, (*prv)->q, 1);

	// n = pq
	mpz_mul((*pub)->n, (*prv)->p, (*prv)->q);

	mpz_setbit(exp1, lbits - 1);

	mpz_mul(exp1, (*prv)->vp, exp1);
	mpz_mul(exp1, f1, exp1);
	mpz_mul(exp2, (*prv)->vp, (*pub)->u);
	mpz_mul(exp3, f1, (*pub)->u);

	// xp
	while (!found) {
		aby_prng(xp, mpz_sizeinbase((*prv)->p, 2) + 128);
		mpz_mod(xp, xp, (*prv)->p);

		mpz_powm(tmp, xp, exp1, (*prv)->p);
		if (mpz_cmp_ui(tmp, 1) != 0) {
			mpz_powm(tmp, xp, exp2, (*prv)->p);
			if (mpz_cmp_ui(tmp, 1) != 0) {
				mpz_powm(tmp, xp, exp3, (*prv)->p);
				if (mpz_cmp_ui(tmp, 1) != 0) {
					found = 1;
				}
			}
		}
	}
	found = 0;

	mpz_setbit(exp1, lbits - 1);

	mpz_mul(exp1, (*prv)->vq, exp1);
	mpz_mul(exp1, f2, exp1);
	mpz_mul(exp2, (*prv)->vq, (*pub)->u);
	mpz_mul(exp3, f2, (*pub)->u);

	// xq
	while (!found) {
		aby_prng(xq, mpz_sizeinbase((*prv)->q, 2) + 128);
		mpz_mod(xq, xq, (*prv)->q);

		mpz_powm(tmp, xq, exp1, (*prv)->q);
		if (mpz_cmp_ui(tmp, 1) != 0) {
			mpz_powm(tmp, xq, exp2, (*prv)->q);
			if (mpz_cmp_ui(tmp, 1) != 0) {
				mpz_powm(tmp, xq, exp3, (*prv)->q);
				if (mpz_cmp_ui(tmp, 1) != 0) {
					found = 1;
				}
			}
		}
	}

	// compute CRT: g = xp*q*(q^{-1} mod p) + xq*p*(p^{-1} mod q) mod n
	mpz_invert(tmp, (*prv)->q, (*prv)->p); // tmp = 1/q % p
	mpz_set((*prv)->qinv, tmp);
	mpz_mul(tmp, tmp, (*prv)->q); // tmp = tmp * q

	// tmp = xp*tmp % n
	mpz_mul(tmp, xp, tmp);
	mpz_mod(tmp, tmp, (*pub)->n);

	mpz_invert(tmp2, (*prv)->p, (*prv)->q); // tmp1 = 1/p % q
	mpz_set((*prv)->pinv, tmp2);
	mpz_mul(tmp2, tmp2, (*prv)->p); // tmp1 = tmp1*p

	// tmp1 = xq*tmp1 % n
	mpz_mul(tmp2, xq, tmp2);
	mpz_mod(tmp2, tmp2, (*pub)->n);

	// g = xp + xq % n
	mpz_add((*pub)->g, xq, xp);
	mpz_mod((*pub)->g, (*pub)->g, (*pub)->n);

	mpz_mul(tmp, f1, f2); // tmp = f1*f2
	mpz_powm((*pub)->g, (*pub)->g, tmp, (*pub)->n); // g = g^tmp % n

	aby_prng((*pub)->h, mpz_sizeinbase((*pub)->n, 2) + 128);
	mpz_mod((*pub)->h, (*pub)->h, (*pub)->n);

	mpz_mul(tmp, tmp, (*pub)->u);
	mpz_powm((*pub)->h, (*pub)->h, tmp, (*pub)->n); // h = h^tmp % n

	powtwo = (mpz_t*) malloc(sizeof(mpz_t) * lbits);
	gvpvqp = (mpz_t*) malloc(sizeof(mpz_t) * lbits);

	// array holding powers of two
	for (i = 0; i < lbits; i++) {
		mpz_init(powtwo[i]);
		mpz_setbit(powtwo[i], i);
	}

	mpz_powm(f1, (*pub)->g, (*prv)->vp, (*prv)->p); // gvpvq

	mpz_sub_ui(tmp2, (*pub)->u, 1); // tmp1 = u - 1

	for (i = 0; i < lbits; i++) {
		mpz_init(gvpvqp[i]);
		mpz_powm(gvpvqp[i], f1, powtwo[i], (*prv)->p);
		mpz_powm(gvpvqp[i], gvpvqp[i], tmp2, (*prv)->p);
	}

	/* clear temporary integers */
	mpz_clears(tmp, tmp2, f1, f2, exp1, exp2, exp3, xp, xq, NULL);
}

void dgk_encrypt_db(mpz_t res, dgk_pubkey_t* pub, mpz_t plaintext) {
	mpz_t r;
	mpz_init(r);

#if DGK_CHECKSIZE
	mpz_setbit(r, (pub->lbits-2)/2);
	if (mpz_cmp(plaintext, r) >= 0) {
		gmp_printf("m: %Zd\nmax:%Zd\n", plaintext, r);
		printf("DGK WARNING: m too big!\n");
	}
#endif

	/* pick random blinding factor r */
	aby_prng(r, 400); // 2.5 * 160 = 400 bit

	dbpowmod(res, pub->h, r, pub->g, plaintext, pub->n);

	mpz_clear(r);
}

void dgk_encrypt_fb(mpz_t res, dgk_pubkey_t* pub, mpz_t plaintext) {
	mpz_t r;
	mpz_init(r);

#if DGK_CHECKSIZE
	mpz_setbit(r, (pub->lbits-2)/2);
	if (mpz_cmp(plaintext, r) >= 0) {
		gmp_printf("m: %Zd\nmax:%Zd\n", plaintext, r);
		printf("DGK WARNING: m too big!\n");
	}
#endif

	/* pick random blinding factor r */