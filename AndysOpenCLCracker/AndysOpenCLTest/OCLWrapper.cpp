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
#include "OCLWrapper.h"
#include "RainbowTable.h"
#include "InfInt.h"
#include "HmacUtils.h"

//SHA1
const string ImplementedKernels::SHA1_CRACK_FileLocation = "../AndysOpenCLTest/sha1Crack.cl";
const string ImplementedKernels::SHA1_CRACK_Kernel = "sha1Crack";
const string ImplementedKernels::SHA1_RAINBOW_FileLocation = "../AndysOpenCLTest/sha1Rainbow.cl"; //"../AndysOpenCLTest/sha1Rainbow.cl";
const string ImplementedKernels::SHA1_RAINBOW_Kernel = "sha1Rainbow";
//HMAC-SHA1
const string ImplementedKernels::HMAC_SHA1_CRACK_FileLocation = "../AndysOpenCLTest/HMACSha1Crack.cl";
const string ImplementedKernels::HMAC_SHA1_CRACK_Kernel = "HmacSha1Crack";
const string ImplementedKernels::HMAC_SHA1_RAINBOW_FileLocation = "../AndysOpenCLTest/HmacSha1Rainbow.cl";
const string ImplementedKernels::HMAC_SHA1_RAINBOW_Kernel = "HmacSha1Rainbow";
//PBKDF2 HMAC-SHA1
const string ImplementedKernels::PBKDF2_HMAC_SHA1_CRACK_FileLocation = "../AndysOpenCLTest/PBKDF2Crack.cl";
const string ImplementedKernels::PBKDF2_HMAC_SHA1_CRACK_Kernel = "PBKDF2";
const string ImplementedKernels::PBKDF2_HMAC_SHA1_RAINBOW_FileLocation = "../AndysOpenCLTest/PBKDF2Rainbow.cl";
const string ImplementedKernels::PBKDF2_HMAC_SHA1_RAINBOW_Kernel = "PBKDF2Rainbow";

OCLWrapper::OCLWrapper(void)
{
	core			= new OCLCore();
	rainbowTable	= new RainbowTable();
	//Load Settings from file:
	core->LoadDefaultSettingsFile();
	hashPtr = NULL;
	saltPtr = NULL;
	iPadHash = NULL;
	oPadHash = NULL;
	hashIn = core->GetSettingsObject()->GetTargetHash();
	saltIn = core->GetSettingsObject()->GetTargetSalt();

	environmentReady = false;
}

OCLWrapper::~OCLWrapper(void)
{
	if (core		) { delete core;		 }
	if (rainbowTable) { delete rainbowTable; }
	if (hashPtr		) { delete [] hashPtr;   }
	if (saltPtr		) { delete [] saltPtr;   }
	if (iPadHash	) { delete [] iPadHash;  }
	if (oPadHash	) { delete [] oPadHash;  }
}

void OCLWrapper::RefreshWrapper()
{
	hashPtr = NULL;
	saltPtr = NULL;
	iPadHash = NULL;
	oPadHash = NULL;
	hashIn = core->GetSettingsObject()->GetTargetHash();
	saltIn = core->GetSettingsObject()->GetTargetSalt();
}

OCLCore* OCLWrapper::GetCore()
{
	return core;
}

void OCLWrapper::InitialiseOCLCore(int platformId, int deviceId) //TODO - check chars are in alphabet!
{
	//Select & Load execution device:
	LoadDevice(platformId, deviceId);

	cl_bool hashCollisionFound = false;
	cl_bool* collision = &hashCollisionFound;

	string filePath = "";
	string kernelName = "";

	int saltLen = core->GetSettingsObject()->GetTargetSalt().length() / 2;

	/*
	unsigned int hash[SHA1_HASH_LENGTH_BYTES + 1];
	unsigned int* hashPtr = hash;
	HexStringToIntPtr(hashIn, hashPtr);

	unsigned char salt[DEFAULT_HASH_LENGTH_HEX + 1];
	unsigned char* saltPtr = salt;
	HexStringToCharPtr(saltIn, saltPtr);
	*/
	/*
			unsigned int hash[DEFAULT_PBKDF2_HASH_LENGTH_BYTES + 1];
			unsigned int* hashPtr = hash;
			Pbkdf2HexStringToIntPtr(hashIn, hashPtr);

			unsigned char salt[DEFAULT_PBKDF2_SALT_LENGTH_HEX + 1];
			unsigned char* saltPtr = salt;
			HexStringToCharPtr(saltIn, saltPtr);
	*/

	switch (core->GetSettingsObject()->GetAlgorithm())
	{			
		//PBKDF2 has longer key-size:
		case PBKDF2:
		{
			HmacUtils hostCrypto = HmacUtils();

			hashPtr = new unsigned int[(DEFAULT_PBKDF2_HASH_LENGTH_BYTES / 4)];
			Pbkdf2HexStringToIntPtr(hashIn, hashPtr);

			saltPtr = new unsigned char[(DEFAULT_PBKDF2_SALT_LENGTH_HEX / 2) + 1];
			Pbkdf2HexStringToCharPtr(saltIn, saltPtr);

			//HMAC Host Crypto Pre-Computation Exploit:
			//(Reduces SHA1 block count by 50% per crypt core (work item))
			iPadHash = new unsigned int[(SHA1_HASH_LENGTH_BYTES / 4)]; //AKA 5
			hostCrypto.iPadSHA1Hash(saltPtr, saltLen, iPadHash);

			oPadHash = new unsigned int[(SHA1_HASH_LENGTH_BYTES / 4)]; 
			hostCrypto.oPadSHA1Hash(saltPtr, saltLen, oPadHash);

			//Output pre-computations to console:
			std::cout << std::endl;
			std::cout << "Pre-computed HMAC iPad Hash: " << std::endl;
			std::cout << std::hex << iPadHash[0] << iPadHash[1] << iPadHash[2] << iPadHash[3] << iPadHash[4] << std::endl;
			std::cout << std::dec << "Pre-computed HMAC oPad Hash: " << std::endl; 
			std::cout << std::hex << oPadHash[0] << oPadHash[1] << oPadHash[2] << oPadHash[3] << oPadHash[4] << std::endl;
			std::cout << std::dec << std::endl; //Convert ostream back to base 10.

			break;
		}
		case SHA1:
		{
			hashPtr = new unsigned int[(SHA1_HASH_LENGTH_BYTES / 4)];
			HexStringToIntPtr(hashIn, hashPtr);

			saltPtr = new unsigned char[(DEFAULT_HASH_LENGTH_HEX / 2) + 1];
			HexStringToCharPtr(saltIn, saltPtr);
			break;
		}
		case HMAC_SHA1:
		{
			HmacUtils hostCrypto = HmacUtils();

			hashPtr = new unsigned int[(SHA1_HASH_LENGTH_BYTES / 4)];
			HexStringToIntPtr(hashIn, hashPtr);

			saltPtr = new unsigned char[(DEFAULT_HASH_LENGTH_HEX / 2) + 1];
			HexStringToCharPtr(saltIn, saltPtr);

			//HMAC Host Crypto Pre-Computation Exploit:
			//(Reduces SHA1 block count by 50% per crypt core (work item))
			iPadHash = new unsigned int[(SHA1_HASH_LENGTH_BYTES / 4)]; //AKA 5
			hostCrypto.iPadSHA1Hash(saltPtr, saltLen, iPadHash);

			oPadHash = new unsigned int[(SHA1_HASH_LENGTH_BYTES / 4)]; 
			hostCrypto.oPadSHA1Hash(saltPtr, saltLen, oPadHash);

			//Output pre-computations to console:
			std::cout << std::endl;
			std::cout << "Pre-computed HMAC iPad Hash: " << std::endl;
			std::cout << std::hex << iPadHash[0] << iPadHash[1] << iPadHash[2] << iPadHash[3] << iPadHash[4] << std::endl;
			std::cout << std::dec << "Pre-computed HMAC oPad Hash: " << std::endl; 
			std::cout << std::hex << oPadHash[0] << oPadHash[1] << oPadHash[2] << oPadHash[3] << oPadHash[4] << std::endl;
			std::cout << std::dec << std::endl; //Convert ostream back to base 10.

			break;
		}
		default:
			OCLSetupException("You have specified an invalid OpenCL algorithm.");
			break;
	}

	//Link and compile correct OpenCL src:
	switch (core->GetSettingsObject()->GetAlgorithm())
	{
		case SHA1:
			if (core->GetSettingsObject()->GetGenerateRainbowTableFlag())
			{
				//Rainbow Mode:
				filePath = ImplementedKernels::SHA1_RAINBOW_FileLocation;
				kernelName = ImplementedKernels::SHA1_RAINBOW_Kernel;
			}
			else
			{
				//Crack Mode:
				filePath = ImplementedKernels::SHA1_CRACK_FileLocation;
				kernelName = ImplementedKernels::SHA1_CRACK_Kernel;
			}
			break;
		case HMAC_SHA1:
			if (core->GetSettingsObject()->GetGenerateRainbowTableFlag())
			{
				//Rainbow Mode:
				filePath = ImplementedKernels::HMAC_SHA1_RAINBOW_FileLocation;
				kernelName = ImplementedKernels::HMAC_SHA1_RAINBOW_Kernel;
			}
			else
			{
				//Crack Mode:
				filePath = ImplementedKernels::HMAC_SHA1_CRACK_FileLocation;
				kernelName = ImplementedKernels::HMAC_SHA1_CRACK_Kernel;
			}
			break;
		case PBKDF2:
			if (core->GetSettingsObject()->GetGenerateRainbowTableFlag())
			{
				//Rainbow Mode:
				filePath = ImplementedKernels::PBKDF2_HMAC_SHA1_RAINBOW_FileLocation;
				kernelName = ImplementedKernels::PBKDF2_HMAC_SHA1_RAINBOW_Kernel;
			}
			else
			{
				//Crack Mode:
				filePath = ImplementedKernels::PBKDF2_HMAC_SHA1_CRACK_FileLocation;
				kernelName = ImplementedKernels::PBKDF2_HMAC_SHA1_CRACK_Kernel;
			}
			break;
		default:
			throw OCLSetupException("You have sepcified an invalid OpenCL algorithm.");
			break;
	}

	EnvironmentSetup(filePath, kernelName, hashPtr, saltPtr, collision, saltLen, 
					 iPadHash, oPadHash, core->GetSettingsObject()->GetGenerateRainbowTableFlag());
	environmentReady = true;

	//Convert salt / hash hex strings to uchar*:
	/*
	switch (core->GetSettingsObject()->GetAlgorithm())
	{			
		//PBKDF2 has longer key-size:
		case PBKDF2:
		{
			unsigned int hash[DEFAULT_PBKDF2_HASH_LENGTH_BYTES + 1];
			unsigned int* hashPtr = hash;
			Pbkdf2HexStringToIntPtr(hashIn, hashPtr);

			unsigned char salt[DEFAULT_PBKDF2_SALT_LENGTH_HEX + 1];
			unsigned char* saltPtr = salt;
			HexStringToCharPtr(saltIn, saltPtr);

			EnvironmentSetup(filePath, kernelName, hashPtr, saltPtr, collision, saltLen, core->GetSettingsObject()->GetGenerateRainbowTableFlag());
			environmentReady = true;
			break;
		}
		//SHA1 / Keyed SHA1 are the same:
		case SHA1:
		case HMAC_SHA1:
		{
			unsigned int hash[SHA1_HASH_LENGTH_BYTES + 1];
			unsigned int* hashPtr = hash;
			HexStringToIntPtr(hashIn, hashPtr);

			unsigned char salt[DEFAULT_HASH_LENGTH_HEX + 1];
			unsigned char* saltPtr = salt;
			HexStringToCharPtr(saltIn, saltPtr);

			EnvironmentSetup(filePath, kernelName, hashPtr, saltPtr, collision, saltLen, core->GetSettingsObject()->GetGenerateRainbowTableFlag());
			environmentReady = true;
			break;
		}
		default:
			OCLSetupException("You have sepcified an invalid OpenCL algorithm.");
			break;
	}
	*/
}

/* ================================== OLD VERSION ==================================
void OCLWrapper::BuildSHA1Rainbow()
{
	if (rainbowTable->GetNoBlocks() != 0)
	{
		throw RainbowTableGenerationException("You must clear the existing rainbow table before generating another!");
	}
	else
	{
		if (environmentReady)
		{
			cout << "Beginning SHA1 Rainbow Table Generation. Please Wait... " << endl;

			//Init Rainbow Table:
			rainbowTable->InitFromSettings(core->GetSettingsObject());

			//Construct Rainbow Table:
			InfInt maxIterations = core->GetNoRequiredExecutions();
			InfInt i;
			for (i = 0; i < maxIterations; i++)
			{
				RainbowBlock* block = new RainbowBlock(*core->GetPasswordPointer()->GetPassword(), 
														core->GetHashOutputBlockSize(),
														core->GetPasswordGenerator());
				//Exec. Kernel:
				core->ExecuteKernel();
				//Store Rainbow Results:
				core->RetrieveKernelOutputToRainbowBlock(block);
				//Add Block to Rainbow Table:
				rainbowTable->AddBlock(block);

				cout << "Completed Block " << i << endl;
			}

			cout << "Generation Complete." << endl;

			//Display last block:
			core->RetrieveKernelOutput();
		}
		else
		{
			throw OCLSetupException("You must setup the environment by calling InitialiseOCLCore() before utilising this method!");
		}
	}
}
*/

void OCLWrapper::BuildSHA1Rainbow()
{
	if (rainbowTable->GetNoBlocks() != 0)
	{
		throw RainbowTableGenerationException("You must clear the existing rainbow table before generating another!");
	}
	else
	{
		if (environmentReady)
		{
			cout << "Beginning SHA1 Rainbow Table Generation. Please Wait... " << endl;

			//Init Rainbow Table:
			rainbowTable->InitFromSettings(core->GetSettingsObject());

			//Construct Rainbow Table:
			InfInt maxIterations = core->GetNoRequiredExecutions();
			InfInt i;
			for (i = 0; i < maxIterations; i++)
			{
				RainbowBlock* block = new RainbowBlock(*core->GetPasswordPointer()->GetPassword(), 
														core->GetHashOutputBlockSize()/ 4, //Convert uchar to int rep.
														core->GetPasswordGenerator());
				//Exec. Kernel:
				core->ExecuteKernel();
				//Store Rainbow Results:
				core->RetrieveKernelOutputToRainbowBlockInt(block);
				
				//Add Block to Rainbow Table:
				rainbowTable->AddBlock(block);

				cout << "Completed Block " << i << endl;
			}

			cout << "Generation Complete." << endl;

			//Display last block:
			core->RetrieveKernelOutputInt();
		}
		else
		{
			throw OCLSetupException("You must setup the environment by calling InitialiseOCLCore() before utilising this method!");
		}
	}
}

void OCLWrapper::ExecuteSHA1Crack()
{
	if (environmentReady)
	{
		timer = new Timer();
		timer->StartTimer();
		//Exec. Kernel:
		bool cracked = false;
		InfInt maxIterations = core->GetNoRequiredExecutions();
		InfInt i;
		for (i = 0; i <= maxIterations; i++)
		{
			core->ExecuteKernel();
			//Detect Collision:
			if (core->KernelCollisionFound())
			{
				//If Collision, find match:
				cout << endl;
				cout << "Hash Collision Found on iteration: " << i << "!" << endl;
				core->RetrieveKernelOutput();
				cracked = true;
				break; //Ditch
			}

			if (i == 0)
			{
				cout << "Beginning crack..." << endl;
			}
			else if (i % 100 == 0)
			{
				int noThreads = core->GetSettingsObject()->GetNoThreads();
				int itemsPerThread = core->GetSettingsObject()->GetPasswordBlockSize();
				InfInt total = noThreads * itemsPerThread;

				cout << "Tried " << total * i << " combinations so far..." << endl;
			}
			//cout << "Completed Block " << i << endl;
		}

		if (!cracked)
		{
			cout << "No Collision found!" << endl;
		}
		timer->StopTimer();
		cout << "Process timer stopped at:" << endl;
		cout << timer->TimeElapsed() << endl;
		delete timer;
	}
	else
	{
		throw OCLSetupException("You must setup the environment by calling InitialiseOCLCore() before utilising this method!");
	}
}

void OCLWrapper::BuildHMACSHA1Rainbow()
{
	if (rainbowTable->GetNoBlocks() != 0)
	{
		throw RainbowTableGenerationException("You must clear the existing rainbow table before generating another!");
	}
	else
	{
		if (environmentReady)
		{
			cout << "Beginning HMAC-SHA1 Rainbow Table Generation. Please Wait... " << endl;

			//Init Rainbow Table:
			rainbowTable->InitFromSettings(core->GetSettingsObject());

			//Construct Rainbow Table:
			InfInt maxIterations = core->GetNoRequiredExecutions();
			InfInt i;
			for (i = 0; i < maxIterations; i++)
			{
				RainbowBlock* block = new RainbowBlock(*core->GetPasswordPointer()->GetPassword(), 
														core->GetHashOutputBlockSize()/ 4, //Convert uchar to int rep.
														core->GetPasswordGenerator());
				//Exec. Kernel:
				core->ExecuteKernel();
				//Store Rainbow Results:
				core->RetrieveKernelOutputToRainbowBlockInt(block);
				//Add Block to Rainbow Table:
				rainbowTable->AddBlock(block);

				cout << "Completed Block " << i << endl;
			}

			cout << "Generation Complete." << endl;

			//Display last block:
			core->RetrieveKernelOutputInt();
		}
		else
		{
			throw OCLSetupException("You must setup the environment by calling InitialiseOCLCore() before utilising this method!");
		}
	}
}

void OCLWrapper::ExecuteHMACSHA1Crack()
{
	if (environmentReady)
	{
		timer = new Timer();
		timer->StartTimer();
		//Exec. Kernel:
		bool cracked = false;
		InfInt maxIterations = core->GetNoRequiredExecutions();
		InfInt i;
		for (i = 0; i <= maxIterations; i++)
		{
			core->ExecuteKernel();
			//Detect Collision:
			if (core->KernelCollisionFound())
			{
				//If Collision, find match:
				cout << endl;
				cout << "Hash Collision Found on iteration: " << i << "!" << endl;
				core->RetrieveKernelOutput();
				cracked = true;
				break; //Ditch
			}
			cout << "Completed Block " << i << endl;
		}

		if (!cracked)
		{
			cout << "No Collision found!" << endl;
		}
		timer->StopTimer();
		cout << "Process timer stopped at:" << endl;
		cout << timer->TimeElapsed() << endl;
		delete timer;
	}
	else
	{
		throw OCLSetupException("You must setup the environment by calling InitialiseOCLCore() before utilising this method!");
	}
}

void OCLWrapper::BuildPBKDF2Rainbow()
{
	if (rainbowTable->GetNoBlocks() != 0)
	{
		throw RainbowTableGenerationException("You must clear the existing rainbow table before generating another!");
	}
	else
	{
		if (environmentReady)
		{
			cout << "Beginning PBKDF2-HMAC-SHA1 Rainbow Table Generation. Please Wait... " << endl;

			//Init Rainbow Table:
			rainbowTable->InitFromSettings(core->GetSettingsObject());

			//Construct Rainbow Table:
			InfInt maxIterations = core->GetNoRequiredExecutions();
			InfInt i;
			for (i = 0; i < maxIterations; i++)
			{
				RainbowBlock* block = new RainbowBlock(*core->GetPasswordPointer()->GetPassword(), 
														core->GetHashOutputBlockSize(),
														core->GetPasswordGenerator());
				//Exec. Kernel:
				core->ExecuteKernel();
				//Store Rainbow Results:
				core->RetrieveKernelOutputToRainbowBlock(block);
				//Add Block to Rainbow Table:
				rainbowTable->AddBlock(block);

				cout << "Completed Block " << i << endl;
			}

			cout << "Generation Complete." << endl;
			
			//Display last block:
			core->RetrieveKernelOutput();
		}
		else
		{
			throw OCLSetupException("You must setup the environment by calling InitialiseOCLCore() before utilising this method!");
		}
	}
}

void OCLWrapper::ExecutePBKDF2Crack()
{
	if (environmentReady)
	{
		timer = new Timer();
		timer->StartTimer();
		//Exec. Kernel:
		bool cracked = false;
		InfInt maxIterations = core->GetNoRequiredExecutions();
		InfInt i;
		
		for (i = 0; i <= maxIterations; i++)
		//for (i = 0; i <= 100; i++)
		{
			core->ExecuteKernel();
			//Detect Collision:
			if (core->KernelCollisionFound())
			{
				//If Collision, find match:
				cout << endl;
				cout << "Hash Collision Found on iteration: " << i << "!" << endl;
				core->RetrieveKernelOutput();
				cracked = true;
				break; //Ditch
			}
			cout << "Completed Block " << i << endl;
		}

		if (!cracked)
		{
			cout << "No Collision found!" << endl;
		}
		timer->StopTimer();
		cout << "Process timer stopped at:" << endl;
		cout << timer->TimeElapsed() << endl;
		delete timer;
	}
	else
	{
		throw OCLSetupException("You must setup the environment by calling InitialiseOCLCore() before utilising this method!");
	}
}

RainbowHash OCLWrapper::LookupHashInRainbowTable(string hexEncodedHash) //TODO - check we're in Rainbow Mode!
{
	/*
	unsigned char lookupTarget[DEFAULT_HASH_LENGTH_HEX + 1];
	unsigned char* ptr = lookupTarget;

	HexStringToCharPtr(hexEncodedHash, lookupTarget);
	*/

	//Use Int for hash data representation:
	unsigned int lookupTarget[DEFAULT_HASH_LENGTH_HEX + 1];
	unsigned int* ptr = lookupTarget;

	HexStringToIntPtr(hexEncodedHash, lookupTarget);

	return rainbowTable->LookupHash(ptr);
}
