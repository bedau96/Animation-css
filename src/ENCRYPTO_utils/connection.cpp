/**
 \file 		connection.cpp
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
 \brief		Connection Implementation
 */

#include "connection.h"
#include "constants.h"
#include "socket.h"
#include "utils.h"
#include <cassert>
#include <iostream>
#include <limits>

bool Connect(const std::string& address, uint16_t port,
		std::vector<std::unique_ptr<CSocket>> &sockets, uint32_t id) {
#ifndef BATCH
	std::cout << "Connecting party "<< id <<": " << address << ", " << port << std::endl;
#endif
	assert(sockets.size() <= std::numeric_limits<uint32_t>::max());
	for (size_t j = 0; j < sockets.size(); j++) {
		sockets[j] = Connect(address, port);
		if (sockets[j]) {
			// handshake
			sockets[j]->Send(&id, sizeof(id));
			uint32_t index = static_cast<uint32_t>(j);
			sockets[j]->Send(&index, sizeof(index));
		}
		else {
			return false;
		}
	}
	return true;
}

bool Listen(const std::strin