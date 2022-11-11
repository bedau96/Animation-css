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
	mpz_t n_squared; /* cached to avoid reco