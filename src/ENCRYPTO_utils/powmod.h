/**
 \file 		powmod.h
 \author 	daniel.demmler@ec-spride.de
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
 \brief		Powmod Implementation
 */

#ifndef _POWMOD_H_
#define _POWMOD_H_

#include <gmp.h>

extern mpz_t* m_table_g;
extern mpz_t* m_table_h;
extern mpz_t* m_prod;
extern mpz_t m_mod;
extern size_t m_numberOfElements_g;
extern size_t m_numberOfElements_h;

/**
 * initialize fixed base multiplication for a given base and a desired exponent bit size
 * identical functionality for either g or h
 */
void fbpowmod_init_g(const mpz_t base, const mpz_t mod, size_t bitsize);
void fbpowmod_init_h(const mpz_t base, const mpz_t mod, size_t bitsize);

/**
 * fixed-base