/*
 * -------------------------------------------------------------------------------
 * 
 * Copyright (C) 2013 - 2015 Andrew Ruddick
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
#define HMACSHA1Len (blocksize + hashLen)
#define pswByteLen (HMACSHA1Len * 8)
#define PBKDF2Iterations 1000

//Pad Bytes:
#define iPadByte 0x36
#define oPadByte 0x5c
#define iPad32 0x36363636
#define oPad32 0x5c5c5c5c

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
#define ROT(a,n) rotate(a, (uint)n)

/*
 * #define Wrapper to encapsulate the OpenCL bitSelect
 * command - a direct hardware-mapping replacement for
 * kernel branch predication:
 * i.e. bitselect(c, b, a) is equivalent to:
 * ((a & c) | ((~b) & c))
 */
#define OCL_BIT_SELECT(a,b,c)	bitselect(c, b, a)

#define SHA1FixedShift(word) rotate(word, (uint)30)

 #define SET_EQUAL_5(A, B)							\
 {													\
	A[0] = B[0];									\
	A[1] = B[1];									\
	A[2] = B[2];									\
	A[3] = B[3];									\
	A[4] = B[4];									\
 }

 #define UINT32_TO_BYTES(b, i, u)					\
 {													\
    (b)[(i)    ] = (uchar) ( (u) >> 24 );			\
    (b)[(i) + 1] = (uchar) ( (u) >> 16 );			\
    (b)[(i) + 2] = (uchar) ( (u) >>  8 );			\
    (b)[(i) + 3] = (uchar) ( (u)       );			\
 }

/*
 * Unrolling of W[i] initialisation (and shift):
 */
 #define INIT_W_BLOCK(W, T, P)						\
 {													\
	W  = ( (T[P    ] << 24)							\
		 | (T[P + 1] << 16)							\
		 | (T[P + 2] << 8 )							\
		 | (T[P + 3]  	  ));						\
 }

 #define INIT_W1(W, PMB)							\
 {													\
	INIT_W_BLOCK(W[0 ], PMB, 0 ) 					\
	INIT_W_BLOCK(W[1 ], PMB, 4 )					\
	INIT_W_BLOCK(W[2 ], PMB, 8 ) 					\
	INIT_W_BLOCK(W[3 ], PMB, 12) 					\
	INIT_W_BLOCK(W[4 ], PMB, 16)					\
	INIT_W_BLOCK(W[5 ], PMB, 20) 					\
	INIT_W_BLOCK(W[6 ], PMB, 24) 					\
	INIT_W_BLOCK(W[7 ], PMB, 28) 					\
	INIT_W_BLOCK(W[8 ], PMB, 32) 					\
	INIT_W_BLOCK(W[9 ], PMB, 36) 					\
	INIT_W_BLOCK(W[10], PMB, 40) 					\
	INIT_W_BLOCK(W[11], PMB, 44) 					\
	INIT_W_BLOCK(W[12], PMB, 48) 					\
	INIT_W_BLOCK(W[13], PMB, 52) 					\
	INIT_W_BLOCK(W[14], PMB, 56) 					\
	INIT_W_BLOCK(W[15], PMB, 60) 					\
 }

 #define SHA1_PAD(i, src, PMB, IM)					\
 {													\
 	_Pragma("unroll")								\
	for (i = 0; i < hashLen; i++)					\
	{												\
		PMB[i] = IM[i];								\
	}												\
													\
	src[(hashLen / 4)] = 0x80;						\
													\
	_Pragma("unroll")								\
	for (i = (hashLen / 4) + 1; i < 16; ++i)		\
	{												\
		src[i] = 0x00000000;						\
	}												\
													\
	PMB[62] = (pswByteLen & 0x0000ff00) >>  8;		\
	PMB[63] = (pswByteLen & 0x000000ff);			\
}

 /*
  * NIST FIPS 180-4 section 6.1.3
  * Allows redefinition of W[80] as W[16], where W operates
  * as a cyclic queue.
  *
  * Allows much higher throughput on GPU CU SM with low
  * memory register count:
  */
#define W_CYCLIC(W, t)										\
{															\
	W[t & MASK] = ROTATE_LEFT((W[((t & MASK) + 13) & MASK] 	\
			 				 ^ W[((t & MASK) + 8 ) & MASK] 	\
							 ^ W[((t & MASK) + 2 ) & MASK] 	\
							 ^ W[  t & MASK]				\
							 ),								\
							 1);							\
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
 * Unused due to Rotations made in macro-call now.
 */
/*
#define SHIFT(tmp, A, B, C, D, E)				\
{												\
    E = D;										\
    D = C;										\
    C = ROTATE_LEFT(B,30);						\
    B = A;										\
    A = tmp;									\
}
*/

#define R1_F_BOX(A, B, C, D, E, W)				\
{												\
	E = (ROTATE_LEFT(A,5)						\
		+ OCL_BIT_SELECT(B,C,D) + E + W + K0);	\
	B = ROTATE_LEFT(B,30);						\
}

#define R1_F_BOX_CYCLIC(A, B, C, D, E, W, t)	\
{												\
	E = (ROTATE_LEFT(A,5)						\
		+ OCL_BIT_SELECT(B,C,D) + E				\
		+ (W_CYCLIC(W, t)) + K0);				\
	B = ROTATE_LEFT(B,30);						\
}

#define R1_F_BOX_SHORT(A, B, C, D, E)			\
{												\
	E = (ROTATE_LEFT(A,5)						\
		+ OCL_BIT_SELECT(B,C,D) + E + K0);		\
	B = ROTATE_LEFT(B,30);						\
}

#define R2_F_BOX(A, B, C, D, E, W)				\
{												\
	E = (ROTATE_LEFT(A,5)						\
		+ (B ^ C ^ D) + E + W + K1);			\
	B = ROTATE_LEFT(B,30);						\
}

#define R2_F_BOX_CYCLIC(A, B, C, D, E, W, t)	\
{												\
	E = (ROTATE_LEFT(A,5)						\
		+ (B ^ C ^ D) + E						\
		+ (W_CYCLIC(W, t)) + K1);				\
	B = ROTATE_LEFT(B,30);						\
}

#define R3_F_BOX_CYCLIC(A, B, C, D, E, W, t)	\
{												\
	E = (ROTATE_LEFT(A,5)						\
		+ ((B & C) | (B & D) | (C & D))			\
		+ E + (W_CYCLIC(W, t)) + K2);			\
	B = ROTATE_LEFT(B,30);						\
}

#define R4_F_BOX_CYCLIC(A, B, C, D, E, W, t)	\
{												\
	E = (ROTATE_LEFT(A,5)						\
		+ (B ^ C ^ D) + E						\
		+ (W_CYCLIC(W, t)) + K3);				\
	B = ROTATE_LEFT(B,30);						\
}

#define W16 (W[0 ] = ROTATE_LEFT((W[2 ] ^ W[0 ]		  ) , 1) )
#define W17 (W[1 ] = ROTATE_LEFT((W[3 ] ^ W[1 ]		  ) , 1) )
#define W18 (W[2 ] = ROTATE_LEFT((W[15] ^ W[4 ] ^ W[2 ]) , 1))
#define W19 (W[3 ] = ROTATE_LEFT((W[0 ] ^ W[5 ] ^ W[3 ]) , 1))
#define W20 (W[4 ] = ROTATE_LEFT((W[1 ] ^ W[4 ]		  ) , 1) )
#define W21 (W[5 ] = ROTATE_LEFT((W[2 ] ^ W[5 ]		  ) , 1) )
#define W22 (W[6 ] = ROTATE_LEFT((W[3 ]				  ) , 1) )
#define W23 (W[7 ] = ROTATE_LEFT((W[4 ] ^ W[15]		  ) , 1) )
#define W24 (W[8 ] = ROTATE_LEFT((W[5 ] ^ W[0 ]		  ) , 1) )
#define W25 (W[9 ] = ROTATE_LEFT((W[6 ] ^ W[1 ]		  ) , 1) )
#define W26 (W[10] = ROTATE_LEFT((W[7 ] ^ W[2 ]		  ) , 1) )
#define W27 (W[11] = ROTATE_LEFT((W[8 ] ^ W[3 ]		  ) , 1) )
#define W28 (W[12] = ROTATE_LEFT((W[9 ] ^ W[4 ]		  ) , 1) )
#define W29 (W[13] = ROTATE_LEFT((W[10] ^ W[5 ] ^ W[15]) , 1))
#define W30 (W[14] = ROTATE_LEFT((W[11] ^ W[6 ] ^ W[0 ]) , 1))

/*
 * With Custom ROTs, as per Jens Steube' paper: 
 * 'Exploiting a SHA1 Weakness in Password Cracking' 
 */
#define R1_R2_SHORT(A, B, C, D, E, W)			\
{												\
	R1_F_BOX	   (A, B, C, D, E, W[0 ]);		\
	R1_F_BOX	   (E, A, B, C, D, W[1 ]);		\
	R1_F_BOX	   (D, E, A, B, C, W[2 ]);		\
	R1_F_BOX	   (C, D, E, A, B, W[3 ]);		\
	R1_F_BOX	   (B, C, D, E, A, W[4 ]);		\
	R1_F_BOX	   (A, B, C, D, E, W[5 ]);		\
	R1_F_BOX_SHORT (E, A, B, C, D 	    );		\
	R1_F_BOX_SHORT (D, E, A, B, C 	    );		\
	R1_F_BOX_SHORT (C, D, E, A, B 	    );		\
	R1_F_BOX_SHORT (B, C, D, E, A 	    );		\
	R1_F_BOX_SHORT (A, B, C, D, E 	    );		\
	R1_F_BOX_SHORT (E, A, B, C, D 	    );		\
	R1_F_BOX_SHORT (D, E, A, B, C 	    );		\
	R1_F_BOX_SHORT (C, D, E, A, B 	    );		\
	R1_F_BOX_SHORT (B, C, D, E, A 	    );		\
	R1_F_BOX	   (A, B, C, D, E, W[15]);		\
	R1_F_BOX	   (E, A, B, C, D, W16  );		\
	R1_F_BOX	   (D, E, A, B, C, W17  );		\
	R1_F_BOX	   (C, D, E, A, B, W18  );		\
	R1_F_BOX	   (B, C, D, E, A, W19  );		\
	R2_F_BOX	   (A, B, C, D, E, W20  );		\
	R2_F_BOX	   (E, A, B, C, D, W21  );		\
	R2_F_BOX	   (D, E, A, B, C, W22  );		\
	R2_F_BOX	   (C, D, E, A, B, W23  );		\
	R2_F_BOX	   (B, C, D, E, A, W24  );		\
	R2_F_BOX	   (A, B, C, D, E, W25  );		\
	R2_F_BOX	   (E, A, B, C, D, W26  );		\
	R2_F_BOX	   (D, E, A, B, C, W27  );		\
	R2_F_BOX	   (C, D, E, A, B, W28  );		\
	R2_F_BOX	   (B, C, D, E, A, W29  );		\
	R2_F_BOX	   (A, B, C, D, E, W30  );		\
	R2_F_BOX_CYCLIC(E, A, B, C, D, W, 31);		\
	R2_F_BOX_CYCLIC(D, E, A, B, C, W, 32);		\
	R2_F_BOX_CYCLIC(C, D, E, A, B, W, 33);		\
	R2_F_BOX_CYCLIC(B, C, D, E, A, W, 34);		\
	R2_F_BOX_CYCLIC(A, B, C, D, E, W, 35);		\
	R2_F_BOX_CYCLIC(E, A, B, C, D, W, 36);		\
	R2_F_BOX_CYCLIC(D, E, A, B, C, W, 37);		\
	R2_F_BOX_CYCLIC(C, D, E, A, B, W, 38);		\
	R2_F_BOX_CYCLIC(B, C, D, E, A, W, 39);		\
}

//R1 Manually unrolled:
//(ROTATE_LEFT(A,5) + OCL_BIT_SELECT(B,C,D) + E + W[0] + K0); 
#define R1(A, B, C, D, E, W)					\
{												\
	R1_F_BOX	   (A, B, C, D, E, W[0 ]);		\
	R1_F_BOX	   (E, A, B, C, D, W[1 ]);		\
	R1_F_BOX	   (D, E, A, B, C, W[2 ]);		\
	R1_F_BOX	   (C, D, E, A, B, W[3 ]);		\
	R1_F_BOX	   (B, C, D, E, A, W[4 ]);		\
	R1_F_BOX	   (A, B, C, D, E, W[5 ]);		\
	R1_F_BOX	   (E, A, B, C, D, W[6 ]);		\
	R1_F_BOX	   (D, E, A, B, C, W[7 ]);		\
	R1_F_BOX	   (C, D, E, A, B, W[8 ]);		\
	R1_F_BOX	   (B, C, D, E, A, W[9 ]);		\
	R1_F_BOX	   (A, B, C, D, E, W[10]);		\
	R1_F_BOX	   (E, A, B, C, D, W[11]);		\
	R1_F_BOX	   (D, E, A, B, C, W[12]);		\
	R1_F_BOX	   (C, D, E, A, B, W[13]);		\
	R1_F_BOX	   (B, C, D, E, A, W[14]);		\
	R1_F_BOX	   (A, B, C, D, E, W[15]);		\
	R1_F_BOX_CYCLIC(E, A, B, C, D, W, 16);		\
	R1_F_BOX_CYCLIC(D, E, A, B, C, W, 17);		\
	R1_F_BOX_CYCLIC(C, D, E, A, B, W, 18);		\
	R1_F_BOX_CYCLIC(B, C, D, E, A, W, 19);		\
}

//R2 Manually unrolled:
#define R2(A, B, C, D, E, W)					\
{												\
	R2_F_BOX_CYCLIC(A, B, C, D, E, W, 20);		\
	R2_F_BOX_CYCLIC(E, A, B, C, D, W, 21);		\
	R2_F_BOX_CYCLIC(D, E, A, B, C, W, 22);		\
	R2_F_BOX_CYCLIC(C, D, E, A, B, W, 23);		\
	R2_F_BOX_CYCLIC(B, C, D, E, A, W, 24);		\
	R2_F_BOX_CYCLIC(A, B, C, D, E, W, 25);		\
	R2_F_BOX_CYCLIC(E, A, B, C, D, W, 26);		\
	R2_F_BOX_CYCLIC(D, E, A, B, C, W, 27);		\
	R2_F_BOX_CYCLIC(C, D, E, A, B, W, 28);		\
	R2_F_BOX_CYCLIC(B, C, D, E, A, W, 29);		\
	R2_F_BOX_CYCLIC(A, B, C, D, E, W, 30);		\
	R2_F_BOX_CYCLIC(E, A, B, C, D, W, 31);		\
	R2_F_BOX_CYCLIC(D, E, A, B, C, W, 32);		\
	R2_F_BOX_CYCLIC(C, D, E, A, B, W, 33);		\
	R2_F_BOX_CYCLIC(B, C, D, E, A, W, 34);		\
	R2_F_BOX_CYCLIC(A, B, C, D, E, W, 35);		\
	R2_F_BOX_CYCLIC(E, A, B, C, D, W, 36);		\
	R2_F_BOX_CYCLIC(D, E, A, B, C, W, 37);		\
	R2_F_BOX_CYCLIC(C, D, E, A, B, W, 38);		\
	R2_F_BOX_CYCLIC(B, C, D, E, A, W, 39);		\
}

//R3 Manually unrolled:
#define R3(A, B, C, D, E, W)					\
{												\
	R3_F_BOX_CYCLIC(A, B, C, D, E, W, 40);		\
	R3_F_BOX_CYCLIC(E, A, B, C, D, W, 41);		\
	R3_F_BOX_CYCLIC(D, E, A, B, C, W, 42);		\
	R3_F_BOX_CYCLIC(C, D, E, A, B, W, 43);		\
	R3_F_BOX_CYCLIC(B, C, D, E, A, W, 44);		\
	R3_F_BOX_CYCLIC(A, B, C, D, E, W, 45);		\
	R3_F_BOX_CYCLIC(E, A, B, C, D, W, 46);		\
	R3_F_BOX_CYCLIC(D, E, A, B, C, W, 47);		\
	R3_F_BOX_CYCLIC(C, D, E, A, B, W, 48);		\
	R3_F_BOX_CYCLIC(B, C, D, E, A, W, 49);		\
	R3_F_BOX_CYCLIC(A, B, C, D, E, W, 50);		\
	R3_F_BOX_CYCLIC(E, A, B, C, D, W, 51);		\
	R3_F_BOX_CYCLIC(D, E, A, B, C, W, 52);		\
	R3_F_BOX_CYCLIC(C, D, E, A, B, W, 53);		\
	R3_F_BOX_CYCLIC(B, C, D, E, A, W, 54);		\
	R3_F_BOX_CYCLIC(A, B, C, D, E, W, 55);		\
	R3_F_BOX_CYCLIC(E, A, B, C, D, W, 56);		\
	R3_F_BOX_CYCLIC(D, E, A, B, C, W, 57);		\
	R3_F_BOX_CYCLIC(C, D, E, A, B, W, 58);		\
	R3_F_BOX_CYCLIC(B, C, D, E, A, W, 59);		\
}

//R4 Manually unrolled:
#define R4(A, B, C, D, E, W)					\
{												\
	R4_F_BOX_CYCLIC(A, B, C, D, E, W, 60);		\
	R4_F_BOX_CYCLIC(E, A, B, C, D, W, 61);		\
	R4_F_BOX_CYCLIC(D, E, A, B, C, W, 62);		\
	R4_F_BOX_CYCLIC(C, D, E, A, B, W, 63);		\
	R4_F_BOX_CYCLIC(B, C, D, E, A, W, 64);		\
	R4_F_BOX_CYCLIC(A, B, C, D, E, W, 65);		\
	R4_F_BOX_CYCLIC(E, A, B, C, D, W, 66);		\
	R4_F_BOX_CYCLIC(D, E, A, B, C, W, 67);		\
	R4_F_BOX_CYCLIC(C, D, E, A, B, W, 68);		\
	R4_F_BOX_CYCLIC(B, C, D, E, A, W, 69);		\
	R4_F_BOX_CYCLIC(A, B, C, D, E, W, 70);		\
	R4_F_BOX_CYCLIC(E, A, B, C, D, W, 71);		\
	R4_F_BOX_CYCLIC(D, E, A, B, C, W, 72);		\
	R4_F_BOX_CYCLIC(C, D, E, A, B, W, 73);		\
	R4_F_BOX_CYCLIC(B, C, D, E, A, W, 74);		\
	R4_F_BOX_CYCLIC(A, B, C, D, E, W, 75);		\
	R4_F_BOX_CYCLIC(E, A, B, C, D, W, 76);		\
	R4_F_BOX_CYCLIC(D, E, A, B, C, W, 77);		\
	R4_F_BOX_CYCLIC(C, D, E, A, B, W, 78);		\
	R4_F_BOX_CYCLIC(B, C, D, E, A, W, 79);		\
}

#define SHA1_CONFUSION(A, B, C, D, E, W)		\
{												\
	R1(A, B, C, D, E, W)						\
	R2(A, B, C, D, E, W)						\
	R3(A, B, C, D, E, W)						\
	R4(A, B, C, D, E, W)						\
}		 

#define SHA1_CONFUSION_SHORT(A, B, C, D, E, W)	\
{												\
	R1_R2_SHORT(A, B, C, D, E, W)				\
	R3(A, B, C, D, E, W)						\
	R4(A, B, C, D, E, W)						\
}

/*
 * SHA1 Macro Wrapper:
 *
 * INIT_CHUNK() - Set current chunk hash values:
 * UPDATE_CHUNK() - Update hash value for the next chunk:
 * CRACK() -Check for a hash collision:
 */

#define SHA1_ROUND(A, B, C, D, E, W, IHS, PMB)	\
{												\
	IHS[0] = H0;								\
	IHS[1] = H1;								\
	IHS[2] = H2;								\
	IHS[3] = H3;								\
	IHS[4] = H4;								\
												\
	INIT_W1(W, PMB)								\
												\
	A = IHS[0];									\
	B = IHS[1];									\
	C = IHS[2];									\
	D = IHS[3];									\
	E = IHS[4];									\
												\
	SHA1_CONFUSION(A, B, C, D, E, W)			\
												\
	IHS[0] += A;								\
	IHS[1] += B;								\
	IHS[2] += C;								\
	IHS[3] += D;								\
	IHS[4] += E;								\
}

/********************************************
 *			HMAC-SHA1 MACROS
 ********************************************/

//Core HMAC Control Macros:

#define HMAC_SHA1_ROUND(A, B, C, D, E, W, PAD)				\
{															\
	W[5 ] = 0x80000000;										\
	W[15] = 0x000002A0;										\
															\
	A = PAD[0];												\
	B = PAD[1];												\
	C = PAD[2];												\
	D = PAD[3];												\
	E = PAD[4];												\
															\
	SHA1_CONFUSION_SHORT(A, B, C, D, E, W)					\
															\
	A += PAD[0];											\
	B += PAD[1];											\
	C += PAD[2];											\
	D += PAD[3];											\
	E += PAD[4];											\
															\
	W[0] = A;												\
	W[1] = B;												\
	W[2] = C;												\
	W[3] = D;												\
	W[4] = E;												\
}

/*
 * A = uint
 * B = uint
 * C = uint
 * D = uint
 * E = uint
 * temp = uint
 * W = Cyclic storage queue of length 16 uint
 * IHS = Itermediate Hash Storage of length 5 uint
 * IPAD = oPad buffer of length 5 uint
 * OPAD = iPad buffer of length 5 uint
 * O = Output buffer of length 5 uint
 */
#define HMAC(A, B, C, D, E, W, temp, IPAD, OPAD)			\
{															\
	HMAC_SHA1_ROUND(A, B, C, D, E, W, IPAD)					\
	HMAC_SHA1_ROUND(A, B, C, D, E, W, OPAD)					\
}

/*
 * Recycles k_ipad / k_opad buffers.
 * TODO - Can remove OH frp, UINT32_TO_BYTES and put A - E directly 
 * into PMB... Then SHA1_PAD can omit the first step in this case..
 */
#define INITIAL_HMAC(A, B, C, D, E, W, IPAD, OPAD, src, PMB, OH, in, out)	\
{																			\
	SHA1_PAD(i, src, PMB, in)												\
																			\
	INIT_W1(W, PMB)															\
																			\
	A = IPAD[0];															\
	B = IPAD[1];															\
	C = IPAD[2];															\
	D = IPAD[3];															\
	E = IPAD[4];															\
																			\
	SHA1_CONFUSION(A, B, C, D, E, W)										\
																			\
	A += IPAD[0];															\
	B += IPAD[1];															\
	C += IPAD[2];															\
	D += IPAD[3];															\
	E += IPAD[4];															\
																			\
	UINT32_TO_BYTES(OH, 0 , A)												\
	UINT32_TO_BYTES(OH, 4 , B)												\
	UINT32_TO_BYTES(OH, 8 , C)												\
	UINT32_TO_BYTES(OH, 12, D)												\
	UINT32_TO_BYTES(OH, 16, E)												\
																			\
	SHA1_PAD(i, src, PMB, OH)												\
																			\
	INIT_W1(W, PMB)															\
																			\
	A = OPAD[0];															\
	B = OPAD[1];															\
	C = OPAD[2];															\
	D = OPAD[3];															\
	E = OPAD[4];															\
																			\
	SHA1_CONFUSION_SHORT(A, B, C, D, E, W)									\
																			\
	A += OPAD[0];															\
	B += OPAD[1];															\
	C += OPAD[2];															\
	D += OPAD[3];															\
	E += OPAD[4];															\
																			\
	out[0] = A;																\
	out[1] = B;																\
	out[2] = C;																\
	out[3] = D;																\
	out[4] = E;																\
}

/*
 * Check for Hash collision:
 */
#define CHECK_CRACK(M, C, T)					\
{												\
	M = (C == T);								\
}

/* 
 * oh = OutputHash
 * th = TargetHash
 */
#define CRACK(a, b, c, d, e, r, oh, th)			\
{												\
	CHECK_CRACK(a, oh[0], th[0])				\
	CHECK_CRACK(b, oh[1], th[1])				\
	CHECK_CRACK(c, oh[2], th[2])				\
	CHECK_CRACK(d, oh[3], th[3])				\
	CHECK_CRACK(e, oh[4], th[4])				\
	r = (a && b && c && d && e);				\
}

#define CRACK2(a, b, c, r, oh, th)				\
{												\
	CHECK_CRACK(a, oh[0], th[5])				\
	CHECK_CRACK(b, oh[1], th[6])				\
	CHECK_CRACK(c, oh[2], th[7])				\
	matchResult = (a && b && c);				\
}


static void F(uchar* password, __constant uchar* salt, uint saltLen, int blockId, uint* outputHash)
{
	uint A, B, C, D, E;
    uint W[16];
	uchar initialSalt[saltLenDefine + 4];
	//Padding Blocks:
	uint iPadHash[hashLen / 4];
	uint oPadHash[hashLen / 4];
	uchar k_ipad[blocksize];
    uchar k_opad[blocksize];
	uint *isrc = (uint *) k_ipad;
	uint *osrc = (uint *) k_opad;
	int i;

	for (i = 0; i < saltLen; i++)
	{
		initialSalt[i] = salt[i];
	}

	//Add blockId as Big Endian representation:
	//(Maybe worth using the same to shorten SHA1 memcopy?)
	initialSalt[saltLen]     = (uchar) (blockId >> 24);
	initialSalt[saltLen + 1] = (uchar) (blockId >> 16);
	initialSalt[saltLen + 2] = (uchar) (blockId >>  8);
	initialSalt[saltLen + 3] = (uchar) (blockId      );

	//HMAC iPad / oPad Pre-computation:
	#pragma unroll
	for (i = 0; i < 16; ++i)
	{
		isrc[i] = iPad32;
		osrc[i] = oPad32;
	}
	
	//Copy part of key assigned:
	#pragma unroll
	for (i = 0; i < passwordLen; i++)
	{
		k_ipad[i] = password[i] ^ iPadByte;
		k_opad[i] = password[i] ^ oPadByte;
	}

	//Pre-compute iPad & oPad Hashes:
	SHA1_ROUND(A, B, C, D, E, W, iPadHash, k_ipad)
	SHA1_ROUND(A, B, C, D, E, W, oPadHash, k_opad)

	//Continue PBKDF2 processing:
	INITIAL_HMAC(A, B, C, D, E, W, iPadHash, oPadHash, 
				 osrc, k_opad, isrc, initialSalt, outputHash)

	W[0] = A;
	W[1] = B;
	W[2] = C;
	W[3] = D;
	W[4] = E;

	#pragma unroll 2
	for (i = 1; i < PBKDF2Iterations; ++i)
	{
		HMAC(A, B, C, D, E, W, temp, iPadHash, oPadHash)

		//Update Result XORs:
		outputHash[0]  ^= A;
		outputHash[1]  ^= B;
		outputHash[2]  ^= C;
		outputHash[3]  ^= D;
		outputHash[4]  ^= E;
	}
}

/*
 * US Secure Hash Algorithm 1, as per IETF RFC3174.
 */
__kernel void PBKDF2(__global uchar* out, __global uchar* in, __constant int* passLen,
					 __constant uchar* salt, __constant uint* saltLen,
					 __constant int* targetHash, __global bool* collisionFound,
					 __constant uint* iPadHash, __constant uint* oPadHash)
{
	//Setup wavefront LDS for execution run:
	__local int i;
	//IO Mem:
	uchar inputMem[hashLen]; //Need only be passwordLen.
	uint outputMem[(hashLen / 4)];

	//Kernel Instance Global GPU Mem IO Mapping:
	int inputIndexStart;

	inputIndexStart = get_global_id(0) * passwordLen;

	//HMAC SETUP
	
	//Select Password input key space:
	for (i = 0; i < passwordLen; i++)
	{
		inputMem[i] = in[inputIndexStart + i];
	}

	//***************************************
	//			PBKDF2 Processing:
	//***************************************
	//Only ever 2 key derivation loops for .NET version.
	//We'll check the first is a hit, before calculating the
	//second..

	//Round 1 Computation (1000 loops):
	F(inputMem, salt, *saltLen, 1, outputMem);

	//Check Round 1 crack:
	__local bool matchA;
	__local bool matchB;
	__local bool matchC;
	__local bool matchD;
	__local bool matchE;
	__local bool matchResult;

	CRACK(matchA, matchB, matchC, matchD, matchE, matchResult, outputMem, targetHash)

	//For now, first block match is sufficent:
	if (matchResult)
	{
		//Check Block 2:
		F(inputMem, salt, *saltLen, 2, outputMem);
		CRACK2(matchA, matchB, matchC, matchResult, outputMem, targetHash)
		//If Both Blocks Match:
		if (matchResult)
		{
			//Output true & Hash result if so:
			collisionFound[0] = true;

			//Output target plaintext:
			#pragma unroll
			for(i = 0; i < passwordLen; ++i)
			{
				out[i] = inputMem[i];
			}
		}
	}
}