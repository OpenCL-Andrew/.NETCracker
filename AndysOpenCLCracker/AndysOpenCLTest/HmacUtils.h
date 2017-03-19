#pragma once
#include <iostream>

class HmacUtils
{
public:
	HmacUtils(void);
	~HmacUtils(void);

	void iPadKey(unsigned char* key, int keyLen);
	void oPadKey(unsigned char* key, int keyLen); 

	/*
	 * TODO - for expansiopn can create an abstract base type 
	 * for the algorithm and pass to this method an instance of the
	 * base type - this allows for dynamic expansion ofr the HMAC class
	 * to any underlying hash function, eg MD / SHA families etc.
	 */
	void iPadSHA1Hash(unsigned char* key, int keyLen, unsigned int* outputMem);
	void oPadSHA1Hash(unsigned char* key, int keyLen, unsigned int* outputMem);
};

