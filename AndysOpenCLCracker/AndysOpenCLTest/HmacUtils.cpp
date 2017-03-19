#include "HmacUtils.h"
#include "Sha1Utils.h"

//Fixed Padding Bytes:
#define iPadByte 0x36
#define oPadByte 0x5c

//Public digest:
#define H0 0x67452301
#define H1 0xEFCDAB89
#define H2 0x98BADCFE
#define H3 0x10325476
#define H4 0xC3D2E1F0

/*
 *  Define the SHA1 circular left shift macro
 *  -Taken directly from IETF RFC3174:
 *
 *  Maybe use OCL vector swizzling instead later...
 */
#define SHA1CircularShift(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))

HmacUtils::HmacUtils(void)  { }
HmacUtils::~HmacUtils(void) { }

/*
 * Array input length must be 64 chars.
 * (Sha1 Blocksize)
 */
void HmacUtils::iPadKey(unsigned char* key, int keyLen)
{
	//XOR Key & FixedByte:
	for (int i = 0; i < keyLen; i++)
	{
		key[i] = key[i] ^ iPadByte;
	}

	for (int i = keyLen; i < 64; i++)
	{
		key[i] = iPadByte;
	}
}

/*
 * Array input length must be 64 chars.
 * (Sha1 Blocksize)
 */
void HmacUtils::oPadKey(unsigned char* key, int keyLen)
{
	//XOR Key & FixedByte:
	for (int i = 0; i < keyLen; i++)
	{
		key[i] = key[i] ^ oPadByte;
	}

	for (int i = keyLen; i < 64; i++)
	{
		key[i] = oPadByte;
	}
}

void HmacUtils::iPadSHA1Hash(unsigned char* key, int keyLen, unsigned int* outputMem)
{
	//Pad Input Block:
	unsigned char paddedMessageBlock[64];
	unsigned int intermediateHashStorage[5];

	//XOR Key & FixedByte:
	for (int i = 0; i < keyLen; i++)
	{
		paddedMessageBlock[i] = key[i] ^ iPadByte;
	}

	for (int i = keyLen; i < 64; i++)
	{
		paddedMessageBlock[i] = iPadByte;
	}

	//Init hash store:
	intermediateHashStorage[0] = H0;
	intermediateHashStorage[1] = H1;
	intermediateHashStorage[2] = H2;
	intermediateHashStorage[3] = H3;
	intermediateHashStorage[4] = H4;

	//SHA1:
	sha1Utils sha1;
	sha1.HashBlock(paddedMessageBlock, intermediateHashStorage);

	//Output:
	outputMem[0] = intermediateHashStorage[0];
	outputMem[1] = intermediateHashStorage[1];
	outputMem[2] = intermediateHashStorage[2];
	outputMem[3] = intermediateHashStorage[3];
	outputMem[4] = intermediateHashStorage[4];
}

void HmacUtils::oPadSHA1Hash(unsigned char* key, int keyLen, unsigned int* outputMem)
{
		//Pad Input Block:
	unsigned char paddedMessageBlock[64];
	unsigned int intermediateHashStorage[5];

	//XOR Key & FixedByte:
	for (int i = 0; i < keyLen; i++)
	{
		paddedMessageBlock[i] = key[i] ^ oPadByte;
	}

	for (int i = keyLen; i < 64; i++)
	{
		paddedMessageBlock[i] = oPadByte;
	}

	//Init hash store:
	intermediateHashStorage[0] = H0;
	intermediateHashStorage[1] = H1;
	intermediateHashStorage[2] = H2;
	intermediateHashStorage[3] = H3;
	intermediateHashStorage[4] = H4;

	//SHA1:
	sha1Utils sha1;
	sha1.HashBlock(paddedMessageBlock, intermediateHashStorage);

	//Output:
	outputMem[0] = intermediateHashStorage[0];
	outputMem[1] = intermediateHashStorage[1];
	outputMem[2] = intermediateHashStorage[2];
	outputMem[3] = intermediateHashStorage[3];
	outputMem[4] = intermediateHashStorage[4];
}
