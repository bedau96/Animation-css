
/**
 \file 		djn.cpp
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

#include "djn.h"
#include "../powmod.h"
#include "../utils.h"
#include <cstdlib>

#define DJN_DEBUG 0
#define DJN_CHECKSIZE 0

void djn_complete_pubkey(unsigned int modulusbits, djn_pubkey_t** pub, mpz_t n, mpz_t h) {
	*pub = (djn_pubkey_t*) malloc(sizeof(djn_pubkey_t));

	/* initialize our integers */
	mpz_init((*pub)->n);
	mpz_init((*pub)->n_squared);
	mpz_init((*pub)->h);
	mpz_init((*pub)->h_s);

	mpz_set((*pub)->n, n);
	mpz_set((*pub)->h, h);
	mpz_mul((*pub)->n_squared, n, n);
	mpz_powm((*pub)->h_s, h, n, (*pub)->n_squared);
	(*pub)->bits = modulusbits;
	(*pub)->rbits = modulusbits % 2 ? modulusbits / 2 + 1 : modulusbits / 2; // rbits = ceil(bits/2)