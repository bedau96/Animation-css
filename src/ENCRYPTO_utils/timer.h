
/**
 \file 		timer.h
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
 \brief		timer Implementation
 */

#ifndef __TIMER_H__
#define __TIMER_H__

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class CSocket;

//Note do not change P_FIRST and P_LAST and keep them pointing to the first and last element in the enum
enum ABYPHASE {
	P_TOTAL, P_INIT, P_CIRCUIT, P_NETWORK, P_BASE_OT, P_SETUP, P_OT_EXT, P_GARBLE, P_ONLINE, P_FIRST = P_TOTAL, P_LAST = P_ONLINE
};

// Structure for measuring runtime
struct aby_timings {
	double timing;
	timespec tbegin;
	timespec tend;
};

// Structure for counting communication
struct aby_comm {
	uint64_t totalcomm;