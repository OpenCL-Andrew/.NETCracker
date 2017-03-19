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

	OpenCL GPU Kernel adaptation of US Secure Hash Algorithm 1 (SHA1)

	Built from the IETF RFC3174.
 */

//Fixed Definitions:
#define passwordLen <<|psw|>> //Replaced by framework
#define wavefrontSize 64
#define hashLen 20 //SHA1HashSize

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

/*
 * Define the SHA1 circular left shift macro
 * -Adapted from SHA1CircularShift as defined
 * in IETF RFC3174:
 */
#define ROTATE_LEFT(a,n) ((a << n) | (a >> (32 - n)))
#define ROTATE_RIGHT(a,n) ((a >> n) | (a << (32 - n)))

/*
 * #define Wrapper to encapsulate the OpenCL bitSelect
 * command - a direct hardware-mapping replacement for
 * kernel branch predication:
 * i.e. bitselect(c, b, a) is equivalent to:
 * ((a & c) | ((~b) & c))
 */
#define OCL_BIT_SELECT(a,b,c)	bitselect(c, b, a)

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

 #define BUILD_W()									\
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

/*
 * Zero-based optimisation as per:  
 * https://hashcat.net/events/p13/js-ocohaaaa.pdf
 */
#define R1_0_F_BOX(A, B, C, D, E, W, tmp)		\
{												\
	tmp = (ROTATE_LEFT(A,5)						\
		+ OCL_BIT_SELECT(B,C,D) + E + K0);		\
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

#define R1_0_SHIFT(A, B, C, D, E, W, temp)		\
{												\
	R1_0_F_BOX(A, B, C, D, E, W, temp);			\
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
	R1_0_SHIFT(A, B, C, D, E, W[4] , temp);		\
	R1_0_SHIFT(A, B, C, D, E, W[5] , temp);		\
	R1_0_SHIFT(A, B, C, D, E, W[6] , temp);		\
	R1_0_SHIFT(A, B, C, D, E, W[7] , temp);		\
	R1_0_SHIFT(A, B, C, D, E, W[8] , temp);		\
	R1_0_SHIFT(A, B, C, D, E, W[9] , temp);		\
	R1_0_SHIFT(A, B, C, D, E, W[10], temp);		\
	R1_0_SHIFT(A, B, C, D, E, W[11], temp);		\
	R1_0_SHIFT(A, B, C, D, E, W[12], temp);		\
	R1_0_SHIFT(A, B, C, D, E, W[13], temp);		\
	R1_0_SHIFT(A, B, C, D, E, W[14], temp);		\
	R1_SHIFT(  A, B, C, D, E, W[15], temp);		\
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

/*
 * R4 Manually unrolled, with early exit optimisation
 * as per:
 * https://hashcat.net/events/p13/js-ocohaaaa.pdf
 */
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
	if (A != tgt) return -1;					\
	R4_SHIFT(A, B, C, D, E, 76, temp);			\
	R4_SHIFT(A, B, C, D, E, 77, temp);			\
	R4_SHIFT(A, B, C, D, E, 78, temp);			\
	R4_SHIFT(A, B, C, D, E, 79, temp);			\
}

/*
 * Includes initial-step optimisations, to remove some 
 * of the add / rotate functions as per:
 * https://hashcat.net/events/p13/js-ocohaaaa.pdf
 */
#define SHA1_CONFUSION()						\
{												\
	A = (0x9FB498B3 + W[0]);					\
	B = H0;										\
	C = 0x7BF36AE2;								\
	D = H2;										\
	E = H3;										\
												\
	E = H2;									    \
	D = 0x7BF36AE2;							    \
	C = 0x59D148C0;							    \
	B = A;									    \
	A = ROTATE_LEFT(B,5) + 0x66B0CD0D + W[1];	\
												\
	temp = ROTATE_LEFT(A,5) + 					\
		OCL_BIT_SELECT(B,C,D) + 0xF33D5697 + 	\
		W[2];									\
	E = 0x7BF36AE2;								\
	D = 0x59D148C0;								\
	C = ROTATE_LEFT(B,30);						\
	B = A;										\
	A = temp;									\
												\
	temp = ROTATE_LEFT(A,5) + 					\
		OCL_BIT_SELECT(B,C,D) + 0xD675E47B + 	\
		W[3];									\
	E = 0x59D148C0;								\
	D = C;										\
	C = ROTATE_LEFT(B,30);						\
	B = A;										\
	A = temp;									\
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

//Pre-computed values for the first round-stage 
//(Added to confusion box for now)
#define INIT_CHUNK()							\
{												\
	A = (0x9FB498B3 + W[0]);					\
	B = H0;										\
	C = 0x7BF36AE2;								\
	D = H2;										\
	E = H3;										\
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
#define SHA1()													\
{																\
	INIT_BUFFER()												\
	BUILD_W()													\
	SHA1_CONFUSION()											\
	UPDATE_CHUNK()												\
	CRACK(matchResult, matchA, matchB, matchC, matchD, matchE)	\
}

/*
 * US Secure Hash Algorithm 1, as per IETF RFC3174.
 */
__kernel void __attribute__(( work_group_size_hint(256, 1, 1) ))
		  sha1Crack(__global uchar* out, __global uchar* in, __constant int* passLen, 
						__constant int* targetHash, __global bool* collisionFound)
{
	//Local Workgroup Mem Instance Kernel Variables:
	uint tgt = ROTATE_RIGHT((targetHash[4] - H4), 30);
	uint A, B, C, D, E, temp;
    uint W[16];

	bool matchA, matchB, matchC, matchD, matchE, matchResult;

	uchar paddedMessageBlock[64];
	uint intermediateHashStorage[hashLen / 4];
	int i;
	int pswByteLen;

	pswByteLen = (passwordLen * 8);
	
	//Kernel Instance Global GPU Mem IO Mapping:
	int id = get_global_id(0);
	int localId = get_local_id(0);
	int inputIndexStart = id * passwordLen;
	
	//Coalesce read across Wavefront:
	__local uchar wavefrontInput[passwordLen * 256]; //Read block of 64 input values
	__local uchar* threadRead = (__local uchar*)&wavefrontInput[localId * passwordLen];
	
	//__local uchar inputMem[passwordLen * 256];
	//Cooperative coalesced read:
	#pragma unroll
	for (i = 0; i < passwordLen; i++)
	{
		threadRead[i] = in[id * passwordLen + i];
	}

	//barrier(CLK_LOCAL_MEM_FENCE);

	//***************************************
	//			SHA1 Processing:
	//***************************************
	//US Secure Hash Algorithm 1
	//Code built from IETF RFC3174, adapted and optimised for
	//GPU by A. Ruddick
	
	//As per IETF RFC3174, section 4:
	#pragma unroll
	for (i = 0; i < passwordLen; i++)
	{
		paddedMessageBlock[i] = threadRead[i];
	}

	paddedMessageBlock[passwordLen] = 0x80; //Append a 1 to message...
	
	#pragma unroll
	for (i = passwordLen + 1; i < 62; i++)
	{
		paddedMessageBlock[i] = 0x00;
	}

	//Set last 2 bytes to password length in bits:
	paddedMessageBlock[62] = (pswByteLen & 0x0000ff00) >>  8;
    paddedMessageBlock[63] = (pswByteLen & 0x000000ff);
	

	/*	
	W[0]  = ((uchar) threadRead[0 + 0 * 4]) << 24;
    W[0] |= ((uchar) threadRead[1 + 0 * 4 + 1]) << 16;
    W[0] |= ((uchar) threadRead[2 + 0 * 4 + 2]) << 8;
    W[0] |=  (uchar) threadRead[3 + 0 * 4 + 3];

	W[1]  = ((uchar) threadRead[0 + 1 * 4]) << 24;
    W[1] |=  0x800000;


	//W[1 ] = 0x00000000;
	W[2 ] = 0x00000000;
	W[3 ] = 0x00000000;
	W[4 ] = 0x00000000;
	W[5 ] = 0x00000000;
	W[6 ] = 0x00000000;
	W[7 ] = 0x00000000;
	W[8 ] = 0x00000000;
	W[9 ] = 0x00000000;
	W[10] = 0x00000000;
	W[11] = 0x00000000;
	W[12] = 0x00000000;
	W[13] = 0x00000000;
	W[14] = 0x00000000;
	W[15] = (passwordLen * 8) & 0xFFFFFFFF;
	*/
	
	/*
	int stop, mmod, t;

	W[2 ] = 0x00000000;
	W[3 ] = 0x00000000;
	W[4 ] = 0x00000000;
	W[5 ] = 0x00000000;
	W[6 ] = 0x00000000;
	W[7 ] = 0x00000000;
	W[8 ] = 0x00000000;
	W[9 ] = 0x00000000;
	W[10] = 0x00000000;
	W[11] = 0x00000000;
	W[12] = 0x00000000;
	W[13] = 0x00000000;
	W[14] = 0x00000000;

    stop = passwordLen / 4 ;

	#pragma unroll
    for (t = 0 ; t < stop ; t++){
        W[t] = ((uchar)  threadRead[t * 4]) << 24;
        W[t] |= ((uchar) threadRead[t * 4 + 1]) << 16;
        W[t] |= ((uchar) threadRead[t * 4 + 2]) << 8;
        W[t] |= (uchar)  threadRead[t * 4 + 3];
    }
    mmod = passwordLen % 4;
    if ( mmod == 3){
        W[t] = ((uchar)  threadRead[t * 4]) << 24;
        W[t] |= ((uchar) threadRead[t * 4 + 1]) << 16;
        W[t] |= ((uchar) threadRead[t * 4 + 2]) << 8;
        W[t] |=  ((uchar) 0x80) ;
    } else if (mmod == 2) {
        W[t] = ((uchar)  threadRead[t * 4]) << 24;
        W[t] |= ((uchar) threadRead[t * 4 + 1]) << 16;
        W[t] |=  0x8000 ;
    } else if (mmod == 1) {
        W[t] = ((uchar)  threadRead[t * 4]) << 24;
        W[t] |=  0x800000 ;
    } else {
        W[t] =  0x80000000 ;
    }
    W[15] =  (passwordLen * 8) & 0xFFFFFFFF;
	*/
	
	//Inline SHA1 Macro, completely unrolled:
	SHA1()

	//Check for hash collision (forces branch convergence :-/ ):
	if (matchResult)
	{
		//Output true & Hash result if so:
		collisionFound[0] = true;

		//Output target plaintext:
		#pragma unroll
		for(i = 0; i < passwordLen; ++i)
		{
			out[i] = threadRead[i];
		}
	}
}