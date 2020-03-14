/**
 \file 		cbitvector.cpp
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
 \brief		CBitVector Implementation
 */

#include "cbitvector.h"
#include "crypto/crypto.h"
#include "utils.h"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <cstring>


namespace {

/** Array which stores the bytes which are reversed. For example, the hexadecimal 0x01 is when reversed becomes 0x80.  */
constexpr BYTE REVERSE_BYTE_ORDER[256] = { 0x00, 0x80, 0x40, 0xC0, 0x