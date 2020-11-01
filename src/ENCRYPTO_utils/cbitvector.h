/**
 \file 		cbitvector.h
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

#ifndef CBITVECTOR_H_
#define CBITVECTOR_H_

#include "typedefs.h"
#include <cassert>
#include <cstddef>

// forward declarations
class crypto;

/** Class which defines the functionality of storing C-based Bits in vector type format.*/
class CBitVector {
public:

	//Constructor code begins here...

	/** Constructor which initializes the member variables bit pointer and size to NULL and zero respectively. */
	CBitVector();

	/**
	 	 Overloaded constructor of class \link CBitVector \endlink which calls internally \link Create(std::size_t bits) \endlink
	 	 \param  bits	 - It is the number of bits which will be used to allocate the CBitVector with. For more info on how these bits are allocated refer to \link Create(std::size_t bits) \endlink
	 */
	CBitVector(std::size_t bits);

	/**
	 	Overloaded constructor of class \link CBitVector \endlink which calls internally \link Create(std::size_t bits,crypto* crypt) \endlink
	 	\param  bits	 - It is the number of bits which will be used to allocate the CBitVector with. For more info on how these bits are allocated refer to \link Create(std::size_t bits,crypto* crypt) \endlink
	 	\param  crypt 	 - This ob