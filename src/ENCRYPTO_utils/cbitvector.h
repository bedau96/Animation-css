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
	 	\param  crypt 	 - This object from crypto class is used to generate pseudo random values for the cbitvector.
	 */
	CBitVector(std::size_t bits, crypto* crypt);

	//Constructor code ends here...

	//Basic Primitive function of allocation and deallocation begins here.
	/**
	 	 Function which gets called initially when the cbitvector object is created. This method is mostly called from constructor of CBitVector class.
	 	 The method sets bit pointer and size to NULL and zero respectively.
	*/
	void Init();

	/**
			Destructor which internally calls the delCBitVector for deallocating the space. This method internally calls
			\link delCBitVector() \endlink.
	*/
	~CBitVector();

	/**
		This method is used to deallocate the bit pointer and size explicitly. This method needs to be called by the programmer explicitly.
	*/
	void delCBitVector();
	//Basic Primitive function of allocation and deallocation ends here.


	//Create function supported by CBitVector starts here...
	/**
		This method generates random values and assigns it to the bitvector using crypto object. If the bits provided in the params are greater
		than the bit size of the bitvector, then the bit vector is recreated with new bit size and filled in with random values.

		\param  bits	 - It is the number of bits which will be used to allocate and assign random values of the CBitVector with. For more info