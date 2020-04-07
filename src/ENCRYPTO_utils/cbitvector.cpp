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
constexpr BYTE REVERSE_BYTE_ORDER[256] = { 0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0, 0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8,
		0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8, 0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4, 0x0C, 0x8C,
		0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC, 0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2,
		0x72, 0xF2, 0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA, 0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96,
		0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6, 0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE, 0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1,
		0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1, 0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9, 0x05, 0x85,
		0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5, 0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD,
		0x7D, 0xFD, 0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3, 0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B,
		0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB, 0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7, 0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF,
		0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF };

/**
	This array is used by \link XORBits(BYTE* p, int pos, int len) \endlink and \link SetBits(BYTE* p, uint64_t pos, uint64_t len) \endlink
    method for lower bit mask.
*/
constexpr BYTE RESET_BIT_POSITIONS[9] = { 0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF };
/**
	This array is used by \link XORBits(BYTE* p, int pos, int len) \endlink and \link SetBits(BYTE* p, uint64_t pos, uint64_t len) \endlink
    method for upper bit mask.
*/
constexpr BYTE RESET_BIT_POSITIONS_INV[9] = { 0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF };

/** This array is used by \link GetBits(BYTE* p, int pos, int len) \endlink method for lower bit mask. */
constexpr BYTE GET_BIT_POSITIONS[9] = { 0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80, 0x00 };

/** This array is used by \link GetBits(BYTE* p, int pos, int len) \endlink method for upper bit mask. */
constexpr BYTE GET_BIT_POSITIONS_INV[9] = { 0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01, 0x00 };

/**
	This array is used for masking bits and extracting a particular positional bit from the provided byte array.
	This array is used by \link GetBit(int idx) \endlink method.
*/
constexpr BYTE MASK_BIT[8] = { 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 };

/**
	This array is used for extracting a particular positional bit from the provided byte array without masking.
	This array is used by \link GetBitNoMask(int idx) \endlink method.
*/
static constexpr BYTE BIT[8] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80 };

/**
	This array is used for masking bits and setting a particular positional bit from the provided byte array in the CBitVector.
	This array is used by \link SetBit(int idx, BYTE b) \endlink and \link ANDBit(int idx, BYTE b) \endlink methods.
*/
constexpr BYTE CMASK_BIT[8] = { 0x7f, 0xbf, 0xdf, 0xef, 0xf7, 0xfb, 0xfd, 0xfe };

/**
	This array is used for setting a particular positional bit from the provided byte array without masking in the CBitVector.
	This array is used by \link SetBitNoMask(int idx, BYTE b) \endlink and \link ANDBitNoMask(int idx, BYTE b) \endlink methods.
*/
constexpr BYTE C_BIT[8] = { 0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x7F };

/**
	This array is used for masking bits and setting a particular positional bit from the provided byte array in the CBitVector.
	This array is used by \link SetBit(int idx, BYTE b) \endlink and \link XORBit(int idx, BYTE b) \endlink methods.
*/
constexpr BYTE MASK_SET_BIT_C[2][8] = { { 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 }, { 0, 0, 0, 0, 0, 0, 0, 0 } };

/**
	This array is used for setting a particular positional bit from the provided byte array without masking in the CBitVector.
	This array is used by \link SetBitNoMask(int idx, BYTE b) \endlink and \link XORBitNoMask(int idx, BYTE b) \endlink methods.
*/
constexpr BYTE SET_BIT_C[2][8] = { { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80 }, { 0, 0, 0, 0, 0, 0, 0, 0 } };

const BYTE SELECT_BIT_POSITIONS[9] = { 0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF };

#if (__WORDSIZE==32)
constexpr REGISTER_SIZE TRANSPOSITION_MASKS[6] =
{	0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF, 0x0000FFFF};
constexpr REGISTER_SIZE TRANSPOSITION_MASKS_INV[6] =
{	0xAAAAAAAA, 0xCCCCCCCC, 0xF0F0F0F0, 0xFF00FF00, 0xFFFF0000};
#else
#if (__WORDSIZE==64)
/** Transposition mask used for Eklund Bit Matrix Transposition.*/
constexpr REGISTER_SIZE TRANSPOSITION_MASKS[6] = { 0x5555555555555555, 0x3333333333333333, 0x0F0F0F0F0F0F0F0F, 0x00FF00FF00FF00FF, 0x0000FFFF0000FFFF, 0x00000000FFFFFFFF };
constexpr REGISTER_SIZE TRANSPOSITION_MASKS_INV[6] = { 0xAAAAAAAAAAAAAAAA, 0xCCCCCCCCCCCCCCCC, 0xF0F0F0F0F0F0F0F0, 0xFF00FF00FF00FF00, 0xFFFF0000FFFF0000, 0xFFFFFFFF00000000 };
#else
#endif
#endif

constexpr size_t SHIFTVAL = 3;


template<class T> void GetBytes(T* dst, const T* src, const T* lim) {
	while (dst != lim) {
		*dst++ = *src++;
	}
}

template<class T> void SetBytes(T* dst, const T* src, const T* lim) {
	while (dst < lim) {
		*dst++ = *src++;
	}
}

//Generic bytewise XOR operation
template<class T> void XORBytes(T* dst, const T* src, const T* lim) {
	while (dst != lim) {
		*dst++ ^= *src++;
	}
}

template<class T> void ANDBytes(T* dst, const T* src, const T* lim) {
	while (dst != lim) {
		*dst++ &= *src++;
	}
}

constexpr BYTE GetArrayBit(const BYTE* p, size_t idx) {
	return 0 != (p[idx >> 3] & BIT[idx & 0x7]);
}

} // namespace


CBitVector::CBitVector() {
	Init();
}

CBitVector::CBitVector(std::size_t bits) {
	Init();
	Create(bits);
}

CBitVector::CBitVector(std::size_t bits, crypto* crypt) {
	Init();
	Create(bits, crypt);
}

void CBitVector::Init() {
	m_pBits = NULL;
	m_nByteSize = 0;
}

CBitVector::~CBitVector(){
	delCBitVector();
};

void CBitVector::delCBitVector() {
	if (( m_nByteSize > 0 )&& (m_pBits != NULL)) {
		free(m_pBits);
	}
	m_nByteSize = 0;
	m_pBits = NULL;
}

/* Fill random values using the pre-defined AES key */
void CBitVector::FillRand(std::size_t bits, crypto* crypt) {
	if (bits > m_nByteSize << 3)
		Create(bits);
	crypt->gen_rnd(m_pBits, cei