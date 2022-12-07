
/**
 \file 		gmp-pk-crypto.h
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
 \brief		Class with finite-field-cryptography operations (using the GMP library)
 */

#ifndef GMP_PK_CRYPTO_H_
#define GMP_PK_CRYPTO_H_

#include "pk-crypto.h"
#include "../utils.h"
#include <gmp.h>

class prime_field;
class gmp_fe;
class gmp_num;
class gmp_brickexp;

#define fe2mpz(fieldele) (((gmp_fe*) (fieldele))->get_val())
#define num2mpz(number) (((gmp_num*) (number))->get_val())

class prime_field: public pk_crypto {
public:
	prime_field(seclvl sp, uint8_t* seed) :
			pk_crypto(sp) {
		init(sp, seed);
	}
	;
	~prime_field();

	num* get_num();
	num* get_rnd_num(uint32_t bitlen = 0);