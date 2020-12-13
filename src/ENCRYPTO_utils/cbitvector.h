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

		\param  bits	 - It is the number of bits which will be used to allocate and assign random values of the CBitVector with. For more info on how these bits are allocated refer to \link Create(std::size_t bits) \endlink
		\param	crypt	 - It is the crypto class object which is used to generate random values for the bit size.
	*/
	void FillRand(std::size_t bits, crypto* crypt);



	/* Create in bits and bytes */
	
	/**
		This method is used to create the CBitVector with the provided bits. The method creates a bit vector of exactly ceil_divide(bits) size.
		For example, if bit size provided is 3 after this method is called it will be 8 bits = 1 byte.

		\param  bits	 - It is the number of bits which will be used to allocate the CBitVector with.
	*/
	void CreateExact(std::size_t bits);

	/**
		This method is used to create the CBitVector with the provided bits. The method creates a bit vector with a size close to AES Bitsize.
		For example, if bit size provided is 110. After this method is called it will be 128 bits. It will perform a ceil of provided_bit_size
		to AES bit size and multiply that ceiled value with AES bits size. (For reference, AES Bit size is taken as 128 bits)

		\param  bits	 - It is the number of bits which will be used to allocate the CBitVector with.
	*/
	void Create(std::size_t bits);


	/**
		This method is used to create the CBitVector with the provided byte size. The method creates a bit vector with a size close to AES Bytesize.
		For example, if byte size provided is 9. After this method is called it will be 16 bytes. It will perform a ceil of provided_byte_size
		to AES byte size and multiply that ceiled value with AES byte size. (For reference, AES Byte size is taken as 16 bytes). Internally, this method
		calls \link Create(std::size_t bits) \endlink. Therefore, for further info please refer to the internal method provided.

		\param  bytes	 - It is the number of bytes which will be used to allocate the CBitVector with.
	*/
	void CreateBytes(std::size_t bytes);

	/**
		This method is used to create the CBitVector with the provided byte size and fills it with random data from the crypt object. The method creates a
		bit vector with a size close to AES Bytesize. For example, if byte size provided is 9. After this method is called it will be 16 bytes. It will perform a ceil of provided_byte_size
		to AES byte size and multiply that ceiled value with AES byte size. (For reference, AES Byte size is taken as 16 bytes). Internally, this method
		calls \link Create(std::size_t bits, crypto* crypt) \endlink. Therefore, for further info please refer to the internal method provided.

		\param  bytes	 - It is the number of bytes which will be used to allocate the CBitVector with.
		\param  crypt	 - Reference to a crypto object from which fresh randomness is sampled
	*/
	void CreateBytes(std::size_t bytes, crypto* crypt);

	/**
		This method is used to create the CBitVector with the provided bits and set them to value zero. The method creates a bit vector with a size close to AES Bitsize.
		And performs an assignment of zero to each bit being allocated. Internally, this method calls \link Create(std::size_t bits) \endlink. Therefore, for further info
		please refer to the internal method provided.

		\param  bits	 - It is the number of bits which will be used to allocate and assign zero values of the CBitVector with.
	*/
	void CreateZeros(std::size_t bits);

	/**
		This method is used to create the CBitVector with the provided bits and set them to some random values. The method creates a bit vector with a size close to AES Bitsize.
		And performs an assignment of random values to each bit being allocated. Internally, this method calls \link Create(std::size_t bits) \endlink and
		\link FillRand(std::size_t bits, crypto* crypt) \endlink. Therefore, for further info please refer to the internal method provided.

		\param  bits	 - It is the number of bits which will be used to allocate and assign random values of the CBitVector with.
		\param	crypt	 - It is the crypto class object which is used to generate random values for the bit size.
	*/
	void Create(std::size_t bits, crypto* crypt);


	/**
		This method is used create the CBitVector with the provided number of elements and element length. This method basically creates a 1-dimensional array/vector with the provided
		element size and number of elements. This method internally calls \link Create(std::size_t bits) \endlink with arguments as elementlength*numelements.
		\param numelements		- The number of elements in the 1-dimensional array/vector which gets created.
		\param elementlength	- The size of element in the provided cbitvector.
	*/
	void Create(std::size_t numelements, std::size_t elementlength);

	/**
		This method is used create the CBitVector with the provided number of elements and element length and then assign random values to them. This method basically creates
		a 1-dimensional array/vector with the provided element size and number of elements and assign some random values based on crypt object provided. This method internally
		calls \link Create(std::size_t bits, crypto* crypt) \endlink for creation of 1-d vector.
		\param numelements		- The number of elements in the 1-dimensional array/vector which gets created.
		\param elementlength	- The size of element in the provided cbitvector.
		\param crypt			- It is the crypto class object which is used to generate random values for the provided bit size.
	*/
	void Create(std::size_t numelements, std::size_t elementlength, crypto* crypt);

	/**
		This method is used create the CBitVector with the provided number of elements of 2 dimensions and element length. This method basically creates a 2-dimensional array/vector
		with the provided element size and number of elements in two dimensions. This method internally calls \link Create(std::size_t bits) \endlink with arguments as
		elementlength*numelementsDimA*numelementsDimB.
		\param numelementsDimA		- The number of elements in the 1st-dimension of the 2d array/vector which gets created.
		\param numelementsDimB		- The number of elements in the 2nd-dimension of the 2d array/vector which gets created.
		\param elementlength		- The size of element in the provided cbitvector.
	*/
	void Create(std::size_t numelementsDimA, std::size_t numelementsDimB, std::size_t elementlength);
	/**
		This method is used create the CBitVector with the provided number of elements of 2 dimensions and element length, and then assign random values to them. This method basically
		creates a 2-dimensional array/vector with the provided element size and number of elements in two dimensions  and assign some random values based on crypt object provided.
		This method internally calls \link Create(std::size_t bits, crypto* crypt) \endlink.
		\param numelementsDimA		- The number of elements in the 1st-dimension of the 2d array/vector which gets created.
		\param numelementsDimB		- The number of elements in the 2nd-dimension of the 2d array/vector which gets created.
		\param elementlength		- The size of element in the provided cbitvector.
		\param crypt				- It is the crypto class object which is used to generate random values for the provided bit size.
	*/
	void Create(std::size_t numelementsDimA, std::size_t numelementsDimB, std::size_t elementlength, crypto* crypt);
	//Create function supported by CBitVector ends here...



	/*
	 * Management operations
	 */

	/**
		This method is used to resize the bytes allocated to CBitVector with newly provided size. And also accommodate the data from previous allocation to new one.
		\param newSizeBytes		-	This variable provides the new size to which the cbitvector needs to be modified to user's needs.
	*/
	void ResizeinBytes(std::size_t newSizeBytes);

	/**
		This method is used to reset the values in the given CBitVector. This method sets all bit values to zeros. This is a slight variant of the method
		\link CreateZeros(std::size_t bits) \endlink. The create method mentioned above allocates and sets value to zero. Whereas the provided method only
		sets the value to zero.
	*/
	void Reset();

	/**
		This method is used to reset the values in the given CBitVector for specific byte range.
		\param 	frombyte	-	The source byte position from which the values needs to be reset.
		\param 	tobyte		-	The destination byte position until which the values needs to be reset to.
	*/
	void ResetFromTo(std::size_t frombyte, std::size_t tobyte);

	/**
		This method sets all bit position values in a CBitVector to One.
	*/
	void SetToOne();

	/**
		This method sets all bits in the CBitVector to the inverse
	*/
	void Invert();


	/**
		This is a getter method which returns the size of the CBitVector in bytes.
		\return the byte size of CBitVector.
	*/
	std::size_t GetSize() const;

	/**
		This method checks if two CBitVectors are 