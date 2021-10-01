/**
 \file 		constants.h
 \author	michael.zohner@ec-spride.de, daniel.demmler@crisp-da.de
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
 \brief		File containing all crypto and networking constants used throughout the source
 */

#ifndef _CONSTANTS_H_
#define _CONSTANTS_H_

#include "typedefs.h"
#include <cstdint>
#include <cmake_constants.h>

#define BATCH
//#define FIXED_KEY_AES_HASHING
//#define USE_PIPELINED_AES_NI
//#define SIMPLE_TRANSPOSE //activate the simple transpose, only required for benchmarking, not recommended

#define AES_KEY_BITS			128
#define AES_KEY_BYTES			16
#define AES_BITS				128
#define AES_BYTES				16
#define LOG2_AES_BITS			ceil_log2(AES_BITS)

#define SHA1_OUT_BYTES 20
#define SHA256_OUT_BYTES 32
#define SHA512_OUT_BYTES 64

#define MAX_NUM_COMM_CHANNELS 256
#define ADMIN_CHANNEL MAX_NUM_COMM_CHANNELS-1

enum fi