/*
 * -------------------------------------------------------------------------------
 * 
 * Copyright (C) 2013 - 2014 Andrew Ruddick
 * BSc Computer Science (Security & Resilience) Dissertation
 * University Of Newcastle Upon Tyne
 *
 * Distributed under the Boost Software License, Version 1.0.
 * (See accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 *
 * -------------------------------------------------------------------------------
 *
 * This file is part of The .NETCracker Suite, an OpenCL accelerated password 
 * cracking application.
 *
 * The .NETCracker Suite is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The .NETCracker Suite is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with The .NETCracker Suite.  If not, see <http://www.gnu.org/licenses/>.
 *
 * This program uses InfInt - Arbitrary-Precision Integer Arithmetic Library
 * which is Copyright (C) 2013 Sercan Tutar, as released under the LGPL.
 *
 * Additionally, the following C++ boost libraries have been used:
 *     boost.Thread
 *     boost.Serialization
 * 
 */

/*
	Code created by A.Ruddick for BSc Computer Science Dissertation
	University of Newcastle Upon Tyne, copyright 2014.

	OpenCL GPU Kernel adaptation of Password Based Key Derivation Function v2
	Based on HMAC-SHA1 as underlying PRF (as defined in RFC2898).

	Built from the following IETF RFC documents:
	
	IETF RFC2898: PKCS#5: Password-Based Cryptography Specification v2.0
	IETF RFC2104: HMAC: Keyed-Hashing for Message Authentication
	IETF RFC3174: US Secure Hash Algorithm 1 (SHA1)
 */

//Fixed Definitions:
#define saltLenDefine 16
#define passwordLen <<|psw|>> //Replaced by framework
#define wavefrontSize 64
#define hashLen 20   //20 bytes (160-bit) for SHA1. MD5 = 16.
#define dkLen 32 //derivedKeyLen
#define blocksize 64 //Bytes
#define HMACSHA1Len (blocksize + hashLen)//passwordLen) //TODO - Change to hashLen for PBKDF2!!!!!!!
#define PBKDF2Iterations 1000

//Pad Bytes:
#define iPadByte 0x36
#define oPadByte 0x5c

//SHA1 Definitions:
#define MASK 0x0000000F

#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6

#define H0 0x67452301
#define H1 0xEFCDAB89
#define H2 0x98BADCFE
#define H3 0x10325476
#define H4 0xC3D2E1F0

/**********************************************
 *			PRE-PROCESSOR MACROS
 **********************************************/

/*
 * Define the SHA1 circular left shift macro
 * -Adapted from SHA1CircularShift as defined
 * in IETF RFC3174:
 */
#define ROTATE_LEFT(a,n) ((a << n) | (a >> (32 - n)))

/*
 * #define Wrapper to encapsulate the OpenCL bitSelect
 * command - a direct hardware-mapping replacement for
 * kernel branch predication:
 * i.e. bitselect(c, b, a) is equivalent to:
 * ((a & c) | ((~b) & c))
 */
#define OCL_BIT_SELECT(a,b,c)	bitselect(c, b, a)

#define SHA1FixedShift(word) rotate(word, (uint)30)

/*
 * Unrolling of W[i] initialisation (and shift):
 */
 #define INIT_W_BLOCK(W, T0, T1, T2, T3)			\
 {													\
	W  = T0 << 24;									\
    W |= T1 << 16;									\
    W |= T2 << 8;									\
    W |= T3;										\
 }

 #define INIT_W1()									\
 {													\
	INIT_W_BLOCK(W[0 ], paddedMessageBlock[0 ], 	\
						paddedMessageBlock[1 ], 	\
						paddedMessageBlock[2 ], 	\
						paddedMessageBlock[3 ])		\
	INIT_W_BLOCK(W[1 ], paddedMessageBlock[4 ], 	\
						paddedMessageBlock[5 ], 	\
						paddedMessageBlock[6 ], 	\
						paddedMessageBlock[7 ])		\
	INIT_W_BLOCK(W[2 ], paddedMessageBlock[8 ], 	\
						paddedMessageBlock[9 ], 	\
						paddedMessageBlock[10], 	\
						paddedMessageBlock[11])		\
	INIT_W_BLOCK(W[3 ], paddedMessageBlock[12], 	\
						paddedMessageBlock[13], 	\
						paddedMessageBlock[14], 	\
						paddedMessageBlock[15])		\
	INIT_W_BLOCK(W[4 ], paddedMessageBlock[16],		\
						paddedMessageBlock[17], 	\
						paddedMessageBlock[18], 	\
						paddedMessageBlock[19])		\
	INIT_W_BLOCK(W[5 ], paddedMessageBlock[20], 	\
						paddedMessageBlock[21], 	\
						paddedMessageBlock[22], 	\
						paddedMessageBlock[23])		\
	INIT_W_BLOCK(W[6 ], paddedMessageBlock[24], 	\
						paddedMessageBlock[25], 	\
						paddedMessageBlock[26], 	\
						paddedMessageBlock[27])		\
	INIT_W_BLOCK(W[7 ], paddedMessageBlock[28], 	\
						paddedMessageBlock[29], 	\
						paddedMessageBlock[30], 	\
						paddedMessageBlock[31])		\
	INIT_W_BLOCK(W[8 ], paddedMessageBlock[32], 	\
						paddedMessageBlock[33], 	\
						paddedMessageBlock[34], 	\
						paddedMessageBlock[35])		\
	INIT_W_BLOCK(W[9 ], paddedMessageBlock[36], 	\
						paddedMessageBlock[37], 	\
						paddedMessageBlock[38], 	\
						paddedMessageBlock[39])		\
	INIT_W_BLOCK(W[10], paddedMessageBlock[40], 	\
						paddedMessageBlock[41], 	\
						paddedMessageBlock[42], 	\
						paddedMessageBlock[43])		\
	INIT_W_BLOCK(W[11], paddedMessageBlock[44], 	\
						paddedMessageBlock[45], 	\
						paddedMessageBlock[46], 	\
						paddedMessageBlock[47])		\
	INIT_W_BLOCK(W[12], paddedMessageBlock[48], 	\
						paddedMessageBlock[49], 	\
						paddedMessageBlock[50], 	\
						paddedMessageBlock[51])		\
	INIT_W_BLOCK(W[13], paddedMessageBlock[52], 	\
						paddedMessageBlock[53], 	\
						paddedMessageBlock[54], 	\
						paddedMessageBlock[55])		\
	INIT_W_BLOCK(W[14], paddedMessageBlock[56], 	\
						paddedMessageBlock[57], 	\
						paddedMessageBlock[58], 	\
						paddedMessageBlock[59])		\
	INIT_W_BLOCK(W[15], paddedMessageBlock[60], 	\
						paddedMessageBlock[61], 	\
						paddedMessageBlock[62], 	\
						paddedMessageBlock[63])		\
 }

 #define W_SHIFT(W, W1, W2, W3, W4)					\
 {													\
	W = ROTATE_LEFT((uint)(W1 ^ W2 ^ W3 ^ W4), 1);	\
 }


/*
 * Provided to allow for manual loop unrolling of 
 * fixed shift stages of SHA1 calcs
 *
 * e.g. Stage 1, as defined in IETF RFC3174 is:
 *
 * 	for(t = 0; t < 20; t++)
 *  {
 *      temp =  ROTATE_LEFT(A,(uint)5) +
 *		OCL_BIT_SELECT(B,C,D) + E + W[t] + K0;
 *      E = D;
 *      D = C;
 *      C = ROTATE_LEFT(B,(uint)30);
 *      B = A;
 *      A = temp;
 *  }
 */
#define SHIFT(tmp, A, B, C, D, E)				\
{												\
    E = D;										\
    D = C;										\
    C = ROTATE_LEFT(B,30);						\
    B = A;										\
    A = tmp;									\
}

#define R1_F_BOX(A, B, C, D, E, W, tmp)			\
{												\
	tmp = (ROTATE_LEFT(A,5)						\
		+ OCL_BIT_SELECT(B,C,D) + E + W + K0);	\
}

#define R2_F_BOX(A, B, C, D, E, W, tmp)			\
{												\
	tmp = (ROTATE_LEFT(A,5)						\
		+ (B ^ C ^ D) + E + W + K1);			\
}

#define R3_F_BOX(A, B, C, D, E, W, tmp)			\
{												\
	tmp = (ROTATE_LEFT(A,5)						\
		+ ((B & C) | (B & D) | (C & D))			\
		+ E + W + K2);							\
}

#define R4_F_BOX(A, B, C, D, E, W, tmp)			\
{												\
	tmp = (ROTATE_LEFT(A,5)						\
		+ (B ^ C ^ D) + E + W + K3);			\
}

#define R1_SHIFT(A, B, C, D, E, W, temp)		\
{												\
	R1_F_BOX(A, B, C, D, E, W, temp);			\
	SHIFT(temp, A, B, C, D, E);					\
}

 /*
  * NIST FIPS 180-4 section 6.1.3
  * Allows redefinition of W[80] as W[16], where W operates
  * as a cyclic queue.
  *
  * Allows much higher throughput on GPU CU SM with low
  * memory register count:
  */
#define W(t)												\
{															\
	W[t & MASK] = ROTATE_LEFT((W[((t & MASK) + 13) & MASK] 	\
							 ^ W[((t & MASK) + 8 ) & MASK] 	\
							 ^ W[((t & MASK) + 2 ) & MASK] 	\
							 ^ W[t & MASK]					\
							 ),								\
							 1);							\
}

#define R1_CYCLIC(A, B, C, D, E, t, temp)		\
{												\
	W(t);										\
	R1_F_BOX(A, B, C, D, E, W[t & MASK], temp);	\
	SHIFT(temp, A, B, C, D, E);					\
}

#define R2_SHIFT(A, B, C, D, E, t, temp)		\
{												\
	W(t);										\
	R2_F_BOX(A, B, C, D, E, W[t & MASK], temp);	\
	SHIFT(temp, A, B, C, D, E);					\
}

#define R3_SHIFT(A, B, C, D, E, t, temp)		\
{												\
	W(t);										\
	R3_F_BOX(A, B, C, D, E, W[t & MASK], temp);	\
	SHIFT(temp, A, B, C, D, E);					\
}

#define R4_SHIFT(A, B, C, D, E, t, temp)		\
{												\
	W(t);										\
	R4_F_BOX(A, B, C, D, E, W[t & MASK], temp);	\
	SHIFT(temp, A, B, C, D, E);					\
}

//R1 Manually unrolled:
//(ROTATE_LEFT(A,5) + OCL_BIT_SELECT(B,C,D) + E + W[0] + K0); 
#define R1()									\
{												\
	R1_SHIFT(A, B, C, D, E, W[0] , temp);		\
	R1_SHIFT(A, B, C, D, E, W[1] , temp);		\
	R1_SHIFT(A, B, C, D, E, W[2] , temp);		\
	R1_SHIFT(A, B, C, D, E, W[3] , temp);		\
	R1_SHIFT(A, B, C, D, E, W[4] , temp);		\
	R1_SHIFT(A, B, C, D, E, W[5] , temp);		\
	R1_SHIFT(A, B, C, D, E, W[6] , temp);		\
	R1_SHIFT(A, B, C, D, E, W[7] , temp);		\
	R1_SHIFT(A, B, C, D, E, W[8] , temp);		\
	R1_SHIFT(A, B, C, D, E, W[9] , temp);		\
	R1_SHIFT(A, B, C, D, E, W[10], temp);		\
	R1_SHIFT(A, B, C, D, E, W[11], temp);		\
	R1_SHIFT(A, B, C, D, E, W[12], temp);		\
	R1_SHIFT(A, B, C, D, E, W[13], temp);		\
	R1_SHIFT(A, B, C, D, E, W[14], temp);		\
	R1_SHIFT(A, B, C, D, E, W[15], temp);		\
	R1_CYCLIC(A, B, C, D, E,  16 , temp);		\
	R1_CYCLIC(A, B, C, D, E,  17 , temp);		\
	R1_CYCLIC(A, B, C, D, E,  18 , temp);		\
	R1_CYCLIC(A, B, C, D, E,  19 , temp);		\
}

//R2 Manually unrolled:
#define R2()									\
{												\
	R2_SHIFT(A, B, C, D, E, 20, temp);			\
	R2_SHIFT(A, B, C, D, E, 21, temp);			\
	R2_SHIFT(A, B, C, D, E, 22, temp);			\
	R2_SHIFT(A, B, C, D, E, 23, temp);			\
	R2_SHIFT(A, B, C, D, E, 24, temp);			\
	R2_SHIFT(A, B, C, D, E, 25, temp);			\
	R2_SHIFT(A, B, C, D, E, 26, temp);			\
	R2_SHIFT(A, B, C, D, E, 27, temp);			\
	R2_SHIFT(A, B, C, D, E, 28, temp);			\
	R2_SHIFT(A, B, C, D, E, 29, temp);			\
	R2_SHIFT(A, B, C, D, E, 30, temp);			\
	R2_SHIFT(A, B, C, D, E, 31, temp);			\
	R2_SHIFT(A, B, C, D, E, 32, temp);			\
	R2_SHIFT(A, B, C, D, E, 33, temp);			\
	R2_SHIFT(A, B, C, D, E, 34, temp);			\
	R2_SHIFT(A, B, C, D, E, 35, temp);			\
	R2_SHIFT(A, B, C, D, E, 36, temp);			\
	R2_SHIFT(A, B, C, D, E, 37, temp);			\
	R2_SHIFT(A, B, C, D, E, 38, temp);			\
	R2_SHIFT(A, B, C, D, E, 39, temp);			\
}

//R3 Manually unrolled:
#define R3()									\
{												\
	R3_SHIFT(A, B, C, D, E, 40, temp);			\
	R3_SHIFT(A, B, C, D, E, 41, temp);			\
	R3_SHIFT(A, B, C, D, E, 42, temp);			\
	R3_SHIFT(A, B, C, D, E, 43, temp);			\
	R3_SHIFT(A, B, C, D, E, 44, temp);			\
	R3_SHIFT(A, B, C, D, E, 45, temp);			\
	R3_SHIFT(A, B, C, D, E, 46, temp);			\
	R3_SHIFT(A, B, C, D, E, 47, temp);			\
	R3_SHIFT(A, B, C, D, E, 48, temp);			\
	R3_SHIFT(A, B, C, D, E, 49, temp);			\
	R3_SHIFT(A, B, C, D, E, 50, temp);			\
	R3_SHIFT(A, B, C, D, E, 51, temp);			\
	R3_SHIFT(A, B, C, D, E, 52, temp);			\
	R3_SHIFT(A, B, C, D, E, 53, temp);			\
	R3_SHIFT(A, B, C, D, E, 54, temp);			\
	R3_SHIFT(A, B, C, D, E, 55, temp);			\
	R3_SHIFT(A, B, C, D, E, 56, temp);			\
	R3_SHIFT(A, B, C, D, E, 57, temp);			\
	R3_SHIFT(A, B, C, D, E, 58, temp);			\
	R3_SHIFT(A, B, C, D, E, 59, temp);			\
}

//R4 Manually unrolled:
#define R4()									\
{												\
	R4_SHIFT(A, B, C, D, E, 60, temp);			\
	R4_SHIFT(A, B, C, D, E, 61, temp);			\
	R4_SHIFT(A, B, C, D, E, 62, temp);			\
	R4_SHIFT(A, B, C, D, E, 63, temp);			\
	R4_SHIFT(A, B, C, D, E, 64, temp);			\
	R4_SHIFT(A, B, C, D, E, 65, temp);			\
	R4_SHIFT(A, B, C, D, E, 66, temp);			\
	R4_SHIFT(A, B, C, D, E, 67, temp);			\
	R4_SHIFT(A, B, C, D, E, 68, temp);			\
	R4_SHIFT(A, B, C, D, E, 69, temp);			\
	R4_SHIFT(A, B, C, D, E, 70, temp);			\
	R4_SHIFT(A, B, C, D, E, 71, temp);			\
	R4_SHIFT(A, B, C, D, E, 72, temp);			\
	R4_SHIFT(A, B, C, D, E, 73, temp);			\
	R4_SHIFT(A, B, C, D, E, 74, temp);			\
	R4_SHIFT(A, B, C, D, E, 75, temp);			\
	R4_SHIFT(A, B, C, D, E, 76, temp);			\
	R4_SHIFT(A, B, C, D, E, 77, temp);			\
	R4_SHIFT(A, B, C, D, E, 78, temp);			\
	R4_SHIFT(A, B, C, D, E, 79, temp);			\
}

#define SHA1_CONFUSION()						\
{												\
	R1()										\
	R2()										\
	R3()										\
	R4()										\
}

/*
 * Buffer Initialisation Macros:
 */
#define INIT_BUFFER()							\
{												\
	intermediateHashStorage[0] = H0;			\
	intermediateHashStorage[1] = H1;			\
	intermediateHashStorage[2] = H2;			\
	intermediateHashStorage[3] = H3;			\
	intermediateHashStorage[4] = H4;			\
}

#define INIT_CHUNK()							\
{												\
	A = H0;										\
	B = H1;										\
	C = H2;										\
	D = H3;										\
	E = H4;										\
}			

#define SET_CHUNK()								\
{												\
	A = intermediateHashStorage[0];				\
	B = intermediateHashStorage[1];				\
	C = intermediateHashStorage[2];				\
	D = intermediateHashStorage[3];				\
	E = intermediateHashStorage[4];				\
}


#define UPDATE_CHUNK()							\
{												\
	intermediateHashStorage[0] += A;			\
	intermediateHashStorage[1] += B;			\
	intermediateHashStorage[2] += C;			\
	intermediateHashStorage[3] += D;			\
	intermediateHashStorage[4] += E;			\
} 		 		 

/*
 * Check for Hash collision:
 */
#define CHECK_CRACK(M, C, T)									\
{																\
	M = (C == T);												\
}


#define CRACK(MR, MA, MB, MC, MD, ME)							\
{																\
	CHECK_CRACK(MA, intermediateHashStorage[0], targetHash[0])	\
	CHECK_CRACK(MB, intermediateHashStorage[1], targetHash[1])	\
	CHECK_CRACK(MC, intermediateHashStorage[2], targetHash[2])	\
	CHECK_CRACK(MD, intermediateHashStorage[3], targetHash[3])	\
	CHECK_CRACK(ME, intermediateHashStorage[4], targetHash[4])	\
	MR = (MA && MB && MC && MD && ME);							\
}

/*
 * SHA1 Macro Wrapper:
 *
 * INIT_CHUNK() - Set current chunk hash values:
 * UPDATE_CHUNK() - Update hash value for the next chunk:
 * CRACK() -Check for a hash collision:
 */
 
#define SHA1_HASH_A()											\
{																\
	INIT_BUFFER()												\
	INIT_W1()													\
	SET_CHUNK()													\
	SHA1_CONFUSION()											\
}
 
#define SHA1_HASH_B()											\
{																\
	INIT_W1()													\
	SET_CHUNK()													\
	SHA1_CONFUSION()											\
	UPDATE_CHUNK()												\
}

#define SHA1_HASH_C()											\
{																\
	SET_CHUNK()													\
	SHA1_CONFUSION()											\
	UPDATE_CHUNK()												\
}

/********************************************
 *			HMAC-SHA1 MACROS
 ********************************************/
#define INIT_PAD(I)												\
{																\
	innerHash[I] = k_ipad[I];									\
	outerHash[I] = k_opad[I];									\
}

#define PAD_BLOCK(I)											\
{																\
	k_ipad[I] = paddedKey[I] ^ iPadByte;						\
    k_opad[I] = paddedKey[I] ^ oPadByte;						\
}
//	INIT_PAD(I)													\

#define PAD_BLOCKS()											\
{																\
	PAD_BLOCK(0)												\
	PAD_BLOCK(1)												\
	PAD_BLOCK(2)												\
	PAD_BLOCK(3)												\
	PAD_BLOCK(4)												\
	PAD_BLOCK(5)												\
	PAD_BLOCK(6)												\
	PAD_BLOCK(7)												\
	PAD_BLOCK(8)												\
	PAD_BLOCK(9)												\
	PAD_BLOCK(10)												\
	PAD_BLOCK(11)												\
	PAD_BLOCK(12)												\
	PAD_BLOCK(13)												\
	PAD_BLOCK(14)												\
	PAD_BLOCK(15)												\
	PAD_BLOCK(16)												\
	PAD_BLOCK(17)												\
	PAD_BLOCK(18)												\
	PAD_BLOCK(19)												\
	PAD_BLOCK(20)												\
	PAD_BLOCK(21)												\
	PAD_BLOCK(22)												\
	PAD_BLOCK(23)												\
	PAD_BLOCK(24)												\
	PAD_BLOCK(25)												\
	PAD_BLOCK(26)												\
	PAD_BLOCK(27)												\
	PAD_BLOCK(28)												\
	PAD_BLOCK(29)												\
	PAD_BLOCK(30)												\
	PAD_BLOCK(31)												\
	PAD_BLOCK(32)												\
	PAD_BLOCK(33)												\
	PAD_BLOCK(34)												\
	PAD_BLOCK(35)												\
	PAD_BLOCK(36)												\
	PAD_BLOCK(37)												\
	PAD_BLOCK(38)												\
	PAD_BLOCK(39)												\
	PAD_BLOCK(40)												\
	PAD_BLOCK(41)												\
	PAD_BLOCK(42)												\
	PAD_BLOCK(43)												\
	PAD_BLOCK(44)												\
	PAD_BLOCK(45)												\
	PAD_BLOCK(46)												\
	PAD_BLOCK(47)												\
	PAD_BLOCK(48)												\
	PAD_BLOCK(49)												\
	PAD_BLOCK(50)												\
	PAD_BLOCK(51)												\
	PAD_BLOCK(52)												\
	PAD_BLOCK(53)												\
	PAD_BLOCK(54)												\
	PAD_BLOCK(55)												\
	PAD_BLOCK(56)												\
	PAD_BLOCK(57)												\
	PAD_BLOCK(58)												\
	PAD_BLOCK(59)												\
	PAD_BLOCK(60)												\
	PAD_BLOCK(61)												\
	PAD_BLOCK(62)												\
	PAD_BLOCK(63)												\
}


#define STORE_IPAD()											\
{																\
	intermediateHashStorage[0] = iPadHash[0];					\
	intermediateHashStorage[1] = iPadHash[1];					\
	intermediateHashStorage[2] = iPadHash[2];					\
	intermediateHashStorage[3] = iPadHash[3];					\
	intermediateHashStorage[4] = iPadHash[4];					\
}

#define STORE_OPAD()											\
{																\
	intermediateHashStorage[0] = oPadHash[0];					\
	intermediateHashStorage[1] = oPadHash[1];					\
	intermediateHashStorage[2] = oPadHash[2];					\
	intermediateHashStorage[3] = oPadHash[3];					\
	intermediateHashStorage[4] = oPadHash[4];					\
}

#define INNER_W()												\
{																\
	W[0 ] = outputHash[0];										\
	W[1 ] = outputHash[1];										\
	W[2 ] = outputHash[2];										\
	W[3 ] = outputHash[3];										\
	W[4 ] = outputHash[4];										\
}																

#define OUTER_W()												\
{																\
	W[0] = intermediateHashStorage[0];							\
	W[1] = intermediateHashStorage[1];							\
	W[2] = intermediateHashStorage[2];							\
	W[3] = intermediateHashStorage[3];							\
	W[4] = intermediateHashStorage[4];							\
}

#define PAD_W()													\
{																\
	W[5 ] = 0x80000000;											\
	W[6 ] = 0x00000000;											\
	W[7 ] = 0x00000000;											\
	W[8 ] = 0x00000000;											\
	W[9 ] = 0x00000000;											\
	W[10] = 0x00000000;											\
	W[11] = 0x00000000;											\
	W[12] = 0x00000000;											\
	W[13] = 0x00000000;											\
	W[14] = 0x00000000;											\
	W[15] = 0x000002A0;											\
}

#define OUTPUT_HMAC()											\
{																\
	outputHash[0] = intermediateHashStorage[0];					\
	outputHash[1] = intermediateHashStorage[1];					\
	outputHash[2] = intermediateHashStorage[2];					\
	outputHash[3] = intermediateHashStorage[3];					\
	outputHash[4] = intermediateHashStorage[4];					\
}

//Core HMAC Control Macros:

#define HMAC_INNER_SHA1()										\
{																\
	STORE_IPAD()												\
	INNER_W()													\
	PAD_W() 													\
	SHA1_HASH_C()												\
	OUTER_W()													\
}

#define HMAC_OUTER_SHA1()										\
{																\
	STORE_OPAD()												\
	PAD_W()														\
	SHA1_HASH_C()												\
}

#define HMAC()													\
{																\
	HMAC_INNER_SHA1()											\
	HMAC_OUTER_SHA1()											\
	OUTPUT_HMAC()												\
}

static void CreateHMAC(uchar* inputMem, uint* outputMem, uint* iPadPre, uint* oPadPre)
{
	int i;
	uchar outerHash[blocksize];

	//SHA1 Hashing variables:
	uint intermediateHashStorage[hashLen / 4];
	uchar paddedMessageBlock[blocksize];
	int pswByteLen = HMACSHA1Len * 8;
	uint temp, A, B, C, D, E;
    uint W[16];

	//***************************************
	//			HMAC SHA1 Processing:
	//***************************************

	/********************************************
	 *			Inner SHA1 Hash
	 ********************************************/

	//INIT_BUFFER()
	intermediateHashStorage[0] = iPadPre[0];
	intermediateHashStorage[1] = iPadPre[1];
	intermediateHashStorage[2] = iPadPre[2];
	intermediateHashStorage[3] = iPadPre[3];
	intermediateHashStorage[4] = iPadPre[4];

	//Init Message Output buffer:
	#pragma unroll
	for (i = 0; i < hashLen; i++)
	{
		paddedMessageBlock[i] = inputMem[i];
	}
	paddedMessageBlock[hashLen] = 0x80; //Append a 1 to message...

	#pragma unroll
	for (i = (hashLen + 1); i < 62; i++)
	{
		paddedMessageBlock[i] = 0x00;
	}
	//Set last 2 bytes to password length in bits:
	paddedMessageBlock[62] = (pswByteLen & 0x0000ff00) >>  8;
	paddedMessageBlock[63] = (pswByteLen & 0x000000ff);

	//1 Iteration with pre-computation (manually unrolled):
	SHA1_HASH_B()

	//Copy intermediate results to output:
	#pragma unroll
	for (i = 0; i < hashLen; i++)
	{
		outerHash[i] = intermediateHashStorage[i>>2] 
								>> 8 * ( 3 - ( i & 0x03 ));
	}
	
	/********************************************
	 *			Outer SHA1 Hash
	 ********************************************/
	i = 0;
	pswByteLen = HMACSHA1Len * 8;
	//INIT_BUFFER()
	intermediateHashStorage[0] = oPadPre[0];
	intermediateHashStorage[1] = oPadPre[1];
	intermediateHashStorage[2] = oPadPre[2];
	intermediateHashStorage[3] = oPadPre[3];
	intermediateHashStorage[4] = oPadPre[4];

	//Init Message Output buffer:
	#pragma unroll
	for (i = 0; i < hashLen; i++)
	{
		paddedMessageBlock[i] = outerHash[i]; // & 0xFF);
	}
	paddedMessageBlock[hashLen] = 0x80; //Append a 1 to message...

	#pragma unroll
	for (i = (hashLen + 1); i < 62; i++)
	{
		paddedMessageBlock[i] = 0x00;
	}

	//Set last 2 bytes to password length in bits:
	paddedMessageBlock[62] = (pswByteLen & 0x0000ff00) >>  8;
	paddedMessageBlock[63] = (pswByteLen & 0x000000ff);

	//1 Iteration with pre-computation (manually unrolled):
	SHA1_HASH_B()
	
	//Copy intermediate results to output:
	outputMem[0] = intermediateHashStorage[0];
	outputMem[1] = intermediateHashStorage[1];
	outputMem[2] = intermediateHashStorage[2];
	outputMem[3] = intermediateHashStorage[3];
	outputMem[4] = intermediateHashStorage[4];
}

static void F(uchar* password, unsigned char* salt, int saltLen, int blockId, uint* outputHash)
{
	uint intermediateResult[(hashLen / 4)];
	uchar initialSalt[saltLenDefine + 4];
	int i;

	for (i = 0; i < saltLen; i++)
	{
		initialSalt[i] = salt[i];
	}

	//Add blockId as Big Endian representation:
	//(Maybe worth using the same to shorten SHA1 memcopy?)
	initialSalt[saltLen]     = (unsigned char) (blockId >> 24);
	initialSalt[saltLen + 1] = (unsigned char) (blockId >> 16);
	initialSalt[saltLen + 2] = (unsigned char) (blockId >>  8);
	initialSalt[saltLen + 3] = (unsigned char) (blockId      );

	//HMAC iPad / oPad Pre-computation:
	
	//Padding Blocks:
	uchar k_ipad[blocksize];
    uchar k_opad[blocksize];
	//Key Padding:
	uchar paddedKey[blocksize];

	//if key is shorter than blocksize, zero pad:
	//if (passwordLen < blocksize)
	//{
		//Copy part of key assigned:
		#pragma unroll
		for (i = 0; i < passwordLen; i++)
		{
			paddedKey[i] = password[i];
		}
		//Zero pad remaining part of the key:
		#pragma unroll
		for (i = passwordLen; i < blocksize; i++)
		{
			paddedKey[i] = 0x00;
		}
	//}

	//Copy key into ipad and opad and XOR values, then
	//Concat k_ipad & message:
	//Concat k_opad & message:
	PAD_BLOCKS()

	//Set pointers:
	uchar* innerHash;
	uchar* outerHash;
	innerHash = k_ipad;
	outerHash = k_opad;

	//Pre-compute iPad & oPad Hashes:
	uint temp, A, B, C, D, E; //Could Save Storage Here...
    uint W[16];

	uint iPadHash[hashLen / 4];
	uint oPadHash[hashLen / 4];

	uchar* paddedMessageBlock;
	uint* intermediateHashStorage;
	uint ihs[hashLen / 4];
	uint* intermediateHashStorageInner;

	//Pre-compute iPad hash:
	paddedMessageBlock = k_ipad;
	intermediateHashStorage = iPadHash;
	SHA1_HASH_A()
	iPadHash[0] += A;
	iPadHash[1]	+= B;
	iPadHash[2]	+= C;
	iPadHash[3]	+= D;
	iPadHash[4]	+= E;

	//Pre-compute oPad hash:
	paddedMessageBlock = k_opad;
	intermediateHashStorage = oPadHash;
	SHA1_HASH_A()
	oPadHash[0] += A;
	oPadHash[1]	+= B;
	oPadHash[2]	+= C;
	oPadHash[3]	+= D;
	oPadHash[4]	+= E;

	intermediateHashStorageInner = iPadHash;

	//Continue PBKDF2 processing:
	
	CreateHMAC(initialSalt, outputHash, iPadHash, oPadHash); //OutputHash = U_1 // 5 = psw len
	
	intermediateResult[0]  = outputHash[0];
	intermediateResult[1]  = outputHash[1];
	intermediateResult[2]  = outputHash[2];
	intermediateResult[3]  = outputHash[3];
	intermediateResult[4]  = outputHash[4];

	intermediateHashStorage = ihs;
	
	#pragma unroll 2
	for (i = 1; i < PBKDF2Iterations; ++i)
	{
		//outputHash = U_(c - 1) IntermediateResult = U_C
		//CreateHMAC2(outputHash, outputHash, intermediateHashStorageInner, intermediateHashStorage);
		HMAC()

		//Update Result XORs:
		intermediateResult[0]  ^= outputHash[0];
		intermediateResult[1]  ^= outputHash[1];
		intermediateResult[2]  ^= outputHash[2];
		intermediateResult[3]  ^= outputHash[3];
		intermediateResult[4]  ^= outputHash[4];
	}

	outputHash[0]  = intermediateResult[0]; 
	outputHash[1]  = intermediateResult[1]; 
	outputHash[2]  = intermediateResult[2]; 
	outputHash[3]  = intermediateResult[3]; 
	outputHash[4]  = intermediateResult[4]; 
}

/*
 * US Secure Hash Algorithm 1, as per IETF RFC3174.
 */
__kernel void __attribute__(( work_group_size_hint(128, 1, 1) ))
				PBKDF2Rainbow(__global uchar* out, __global uchar* in, __constant int* passLen,
							  __constant uchar* salt, __constant uint* saltLen)
{
	//Copy global data into LDS memory:
	int keyLen;
	uchar* key;
	uchar keyStorage[blocksize];

	keyLen = *saltLen;
	key = keyStorage;

	//Setup wavefront LDS for execution run:
	__local int i;
	__local int c;
	//IO Mem:
	uchar inputMem[hashLen];
	uint outputMem[(hashLen / 4)];

	/*
	//Current data-block mapping:
	int id = get_global_id(0);
	int inputIndexStart = id * passwordLen;
	int outputIndexStart = id * dkLen;
	*/

	//Kernel Instance Global GPU Mem IO Mapping:
	__local int id;
	//__local int localId;
	//__local int localSize;
	//__local int offset;
	int inputIndexStart;
	int outputIndexStart;

	id = get_global_id(0);
	//localId = get_local_id(0);
	//localSize = get_local_size(0);
	//offset = get_global_offset(0);
	inputIndexStart = (id) * passwordLen;
	outputIndexStart = id * dkLen;

	//PBKDF2 Variables:
	//int l = 2; //Only ever 2 loops for .NET version
	__local int r;
	r = dkLen - hashLen;

	//HMAC SETUP

	//Init Mem:
	for (i = 0; i < keyLen; i++)
	{
		keyStorage[i] = salt[i];
	}
	
	for (i = keyLen; i < blocksize; i++)
	{
		keyStorage[i] = 0x00;
	}
	
	//Select Password input key space:
	for (i = 0; i < passwordLen; i++)
	{
		inputMem[i] = in[inputIndexStart + i];
	}

	//***************************************
	//			PBKDF2 Processing:
	//***************************************
	//Only ever 2 key derivation loops for .NET version

	//HMAC - Just adjust keyLen to match HMAC-SHA1:
	//CreateHMAC(inputMem, key, 16, outputMem); 

	//Round 1 Computation (1000 loops):
	F(inputMem, key, keyLen, 1, outputMem);
	//Set Output:
	#pragma unroll
	for(i = 0; i < hashLen; ++i)
    {
		out[outputIndexStart + i] = outputMem[i>>2] 
								>> 8 * ( 3 - ( i & 0x03 ));
    }
	
	//Round 2 Computation (1000 loops):
	F(inputMem, key, keyLen, 2, outputMem);
	//Set final output block:
	c = 0;
	#pragma unroll
	for(i = hashLen; i < (hashLen + r); ++i)
    {
		out[outputIndexStart + i] = outputMem[c>>2] 
								>> 8 * ( 3 - ( c & 0x03 ));
		c++;
    }
}