/**
 \file 		rcvthread.h
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
 \brief		Receiver Thread Implementation
 */

#ifndef RCV_THREAD_H_
#define RCV_THREAD_H_

#include "constants.h"
#include "thread.h"
#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>

class CSocket;

struct rcv_ctx {
	uint8_t *buf;
	uint64_t rcvbytes;
};



class RcvThread: public CThread {
public:
	RcvThread(CSocket* sock, CLock* glock);
	~RcvThread();

	CLock* getlock() const;

    void setlock(CLock *glock);

	void flush_queue(uint8_t channelid);

	void remove_listener(uint8_t channelid);

	std::queue<rcv_ctx*>*