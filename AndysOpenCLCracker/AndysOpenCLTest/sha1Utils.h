#pragma once
class sha1Utils
{
public:
	sha1Utils();
	~sha1Utils(void);

	unsigned int* GetHashStorage();

	void PadMessage(unsigned char* msg, int msgLen);
	void PadandHashBlock(unsigned char* inputMem, int passLen, unsigned int* outputMem);
	void HashBlock(unsigned char* paddedMessageBlock, unsigned int* outputMem);
	void ResetState();
	
private:
	unsigned int intermediateHashStorage[5];

	void HashBlock(unsigned char* paddedMessageBlock);
	void OutputIntermediateBuffer(unsigned char block[], int blockLen);
	void OutputIntermediateHashStorage(unsigned int* block, int blockLen);
};

