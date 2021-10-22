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

crypto::crypt