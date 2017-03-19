#include "sha1Utils.h"

#define hashLen 20

//SHA1 Definitions:
#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6

//Replaced with public digest storage:
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

sha1Utils::sha1Utils(void)
{
	//init intermediate storage:
	intermediateHashStorage[0] = H0;
	intermediateHashStorage[1] = H1;
	intermediateHashStorage[2] = H2;
	intermediateHashStorage[3] = H3;
	intermediateHashStorage[4] = H4;
}


sha1Utils::~sha1Utils(void)
{
}

unsigned int* sha1Utils::GetHashStorage()
{
	return intermediateHashStorage;
}

/*
 * Array input length must be 64 chars.
 * (Sha1 Blocksize)
 */
void sha1Utils::PadMessage(unsigned char* msg, int msgLen)
{
	msg[msgLen] = 0x80; //Append a 1 to message...

	//Length Pad:
	for (int i = msgLen + 1; i < 64; i++)
	{
		msg[i] = 0x00;
	}

	//Set last 2 bytes to password length in bits:
	int pswByteLen = msgLen * 8;
	msg[62] = (pswByteLen & 0x0000ff00) >>  8;
    msg[63] = (pswByteLen & 0x000000ff);
}

void sha1Utils::PadandHashBlock(unsigned char* inputMem, int passLen, unsigned int* outputMem)
{
	//Pad Input Block:
	unsigned char paddedMessageBlock[64];

	//Init Message Output buffer:
	for (int i = 0; i < 64; i++)
	{
		paddedMessageBlock[i] = 0x00;
	}

	for (int i = 0; i < passLen; i++)
	{
		paddedMessageBlock[i] = inputMem[i]; // & 0xFF);
	}
	paddedMessageBlock[passLen] = 0x80; //Append a 1 to message...

	//Set last 2 bytes to password length in bits:
	int pswByteLen = passLen * 8;
	paddedMessageBlock[62] = (pswByteLen & 0x0000ff00) >>  8;
    paddedMessageBlock[63] = (pswByteLen & 0x000000ff);

	//SHA1 Hash:
	HashBlock(paddedMessageBlock);

	//Set Output:
	outputMem[0] = intermediateHashStorage[0];
	outputMem[1] = intermediateHashStorage[1];
	outputMem[2] = intermediateHashStorage[2];
	outputMem[3] = intermediateHashStorage[3];
	outputMem[4] = intermediateHashStorage[4];
}

/*
 * Uses provided state (digest storage):
 */
void sha1Utils::HashBlock(unsigned char* paddedMessageBlock, unsigned int* outputMem)
{
	int				  t; 
	unsigned int      temp;              /* Temporary word value        */
    unsigned int      W[80];             /* Word sequence               */
    unsigned int      A, B, C, D, E;     /* Word buffers                */
	
	/*
     *  Initialize the first 16 words in the array W
     */
    for(t = 0; t < 16; t++)
    {
        W[t]  = paddedMessageBlock[t * 4]     << 24;
        W[t] |= paddedMessageBlock[t * 4 + 1] << 16;
        W[t] |= paddedMessageBlock[t * 4 + 2] << 8;
        W[t] |= paddedMessageBlock[t * 4 + 3];
    }

	for(t = 16; t < 80; t++)
    {
       W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

	//Set current chunk hash values:
	A = outputMem[0];
	B = outputMem[1];
	C = outputMem[2];
	D = outputMem[3];
	E = outputMem[4];

	for(t = 0; t < 20; t++)
    {
        temp =  SHA1CircularShift(5,A) +
                ((B & C) | ((~B) & D)) + E + W[t] + K0;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

	for(t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K1;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

	for(t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K2;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K3;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

	//Update hash value for the next chunk:
	outputMem[0] += A;
    outputMem[1] += B;
    outputMem[2] += C;
    outputMem[3] += D;
    outputMem[4] += E;
}

void sha1Utils::ResetState()
{
	intermediateHashStorage[0] = 0x00000000;
	intermediateHashStorage[1] = 0x00000000;
	intermediateHashStorage[2] = 0x00000000;
	intermediateHashStorage[3] = 0x00000000;
	intermediateHashStorage[4] = 0x00000000;
}

//Private methods:

/*
 * Uses internal class state (digest storage):
 */
void sha1Utils::HashBlock(unsigned char* paddedMessageBlock)
{
	int				  t; 
	unsigned int      temp;              /* Temporary word value        */
    unsigned int      W[80];             /* Word sequence               */
    unsigned int      A, B, C, D, E;     /* Word buffers                */
	
	/*
     *  Initialize the first 16 words in the array W
     */
    for(t = 0; t < 16; t++)
    {
        W[t]  = paddedMessageBlock[t * 4]     << 24;
        W[t] |= paddedMessageBlock[t * 4 + 1] << 16;
        W[t] |= paddedMessageBlock[t * 4 + 2] << 8;
        W[t] |= paddedMessageBlock[t * 4 + 3];
    }

	for(t = 16; t < 80; t++)
    {
       W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

	//Set current chunk hash values:
	A = H0;
	B = H1;
	C = H2;
	D = H3;
	E = H4;

	for(t = 0; t < 20; t++)
    {
        temp =  SHA1CircularShift(5,A) +
                ((B & C) | ((~B) & D)) + E + W[t] + K0;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

	for(t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K1;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

	for(t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K2;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K3;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

	//Update hash value for the next chunk:
	intermediateHashStorage[0] += A;
    intermediateHashStorage[1] += B;
    intermediateHashStorage[2] += C;
    intermediateHashStorage[3] += D;
    intermediateHashStorage[4] += E;
}
