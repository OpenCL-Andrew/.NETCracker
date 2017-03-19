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
#ifndef OCLWRAPPER_H_
#define OCLWRAPPER_H_

#include "OCLCore.h"
#include "RainbowHash.h"
#include "Timer.h"

#include <string>
#include <iostream>
#include <sstream>
#include <iomanip> //std::hex

using std::cout;
using std::cin;
using std::endl;
using std::istringstream;
using std::hex;

/*
 * A provided wrapper type to hold all of
 * the implemented OpenCL Kernel Information
 * required to initialise the program.
 */
class ImplementedKernels
{   
public:      
	//SHA1
	static const string SHA1_CRACK_FileLocation;
	static const string SHA1_CRACK_Kernel;
	static const string SHA1_RAINBOW_FileLocation;
	static const string SHA1_RAINBOW_Kernel;
	//HMAC-SHA1
	static const string HMAC_SHA1_CRACK_FileLocation;
	static const string HMAC_SHA1_CRACK_Kernel;
	static const string HMAC_SHA1_RAINBOW_FileLocation;
	static const string HMAC_SHA1_RAINBOW_Kernel;
	//PBKDF2 HMAC-SHA1
	static const string PBKDF2_HMAC_SHA1_CRACK_FileLocation;
	static const string PBKDF2_HMAC_SHA1_CRACK_Kernel;
	static const string PBKDF2_HMAC_SHA1_RAINBOW_FileLocation;
	static const string PBKDF2_HMAC_SHA1_RAINBOW_Kernel;
};

const int DEFAULT_PBKDF2_HASH_LENGTH_HEX = 64;
const int DEFAULT_PBKDF2_HASH_LENGTH_BYTES = 32;
const int DEFAULT_PBKDF2_SALT_LENGTH_HEX = 32;
const int DEFAULT_PBKDF2_SALT_LENGTH_BYTES = 16;
const int DEFAULT_HASH_LENGTH_HEX = 40; //No HEX chars in hash (2 * bytes)
const int SHA1_HASH_LENGTH_BYTES = 20;

/*
 * This class provides a convenience wrapper for the core implemented
 * functionality contained within this application.  Direct access to 
 * the implemented core API is provided to allow informational retrieval
 * queries / extension etc. by the caller.  Though the 6 main algorithmic
 * methods should suffice for straight usage purposes.
 */
class OCLWrapper
{

public:
	OCLWrapper(void);
	~OCLWrapper(void);

	void RefreshWrapper();

	OCLCore* GetCore();

	void InitialiseOCLCore(int platformId, int deviceId);

	void BuildSHA1Rainbow();
	void ExecuteSHA1Crack();

	void BuildHMACSHA1Rainbow();
	void ExecuteHMACSHA1Crack();

	void BuildPBKDF2Rainbow(); //Unimplemented
	void ExecutePBKDF2Crack();

	RainbowHash LookupHashInRainbowTable(string hexEncodedHash);

	class UnimplementedFunctionException : public std::runtime_error 
	{ 
		public: 
			UnimplementedFunctionException(string m = "An exception occured in OCLWrapper!") 
				:std::runtime_error(m) { }
	};

	class OCLSetupException : public std::runtime_error 
	{ 
		public: 
			OCLSetupException(string m = "An exception occured in OCLWrapper!") 
				:std::runtime_error(m) { }
	};

	class RainbowTableGenerationException : public std::runtime_error 
	{ 
		public: 
			RainbowTableGenerationException(string m = "An exception occured in OCLWrapper!") 
				:std::runtime_error(m) { }
	};

	class RainbowTableLookupException : public std::runtime_error 
	{ 
		public: 
			RainbowTableLookupException(string m = "An exception occured in OCLWrapper!") 
				:std::runtime_error(m) { }
	};

	class HexConversionError : public std::runtime_error 
	{ 
		public: 
			HexConversionError(string m = "An exception occured in OCLWrapper!") 
				:std::runtime_error(m) { }
	};
private:
	OCLCore*		core;
	RainbowTable*	rainbowTable;
	Timer*			timer;
	bool			environmentReady;
	unsigned int*	hashPtr;
	unsigned char*	saltPtr;
	string			hashIn;
	string			saltIn;
	//HMAC Pre-computation Exploit:
	unsigned int*	iPadHash;
	unsigned int*	oPadHash;

	inline void LoadDevice(int platformId, int deviceId)
	{
		core->SelectAndLoadPlatform(platformId);
		core->SelectAndLoadPlatformDevice(platformId, deviceId); 
	}

	inline void EnvironmentSetup(string filePath, string kernelName, cl_uint* hashPtr, 
								 cl_uchar* saltPtr, cl_bool* hashCollisionFound, 
								 int saltLen, cl_uint* iPadHash, cl_uint* oPadHash, 
								 bool isRainbowMode = false)
	{
		//Ensure we're not in correct mode (manual override):
		core->GetSettingsObject()->SetGenerateRainbowTableFlag(isRainbowMode);
		//Build OCL Program Context:
		cout << "Building OpenCL Context..." << endl;
		core->BuildContext();
		cout << "Generating Initial Password Block..." << endl;
		core->SetupPasswordGenerator();
		core->DisplayPasswordKeyspaceStats();
		cout << "Building Buffers..." << endl;
		core->BuildBuffers(hashPtr, saltPtr, hashCollisionFound, saltLen, iPadHash, oPadHash); //No Hash / Salt Required for Rainbow Table
		cout << "Compiling Kernel... This may take a moment." << endl;
		core->BuildKernel(filePath, kernelName);
		cout << "Kernel Compilation Complete." << endl;
	}

	inline void HexStringToCharPtr(string hexIn, unsigned char* ptrIn)
	{
		if (hexIn.length() > DEFAULT_HASH_LENGTH_HEX)
		{
			throw HexConversionError("The hash provided is not of the correct length. Please provide a HEX encoded string");
		}
		else
		{
			try
			{
				//Add separators to hex:
				unsigned int i, j, size, temp;
				j = 0;
				size = hexIn.length();
				for (i = 2; i < size; i += 2)
				{
					hexIn.insert(i, " ");
					size++;
					i++;
				}

				//Convert to byte array:
				istringstream hexStream(hexIn);
				ptrIn[(DEFAULT_HASH_LENGTH_HEX / 2)] = '\0';

				while ((hexStream >> std::hex >> temp) && (j < size))
				{
					ptrIn[j] = (unsigned char)temp;
					//cout << std::setfill ('0') << std::setw(sizeof(cl_uchar)*2) << std::hex << (int)lookupTarget[j];
					j++;
				}
			}
			catch (...)
			{
				throw HexConversionError("An error occurred converting this hash value. Please provide a HEX encoded string");
			}
		}
	}

	inline void HexStringToIntPtr(string hexIn, unsigned int* ptrIn)
	{
		if (hexIn.length() > DEFAULT_HASH_LENGTH_HEX)
		{
			throw HexConversionError("The hash provided is not of the correct length. Please provide a HEX encoded string");
		}
		else
		{
			try
			{
				//Add separators to hex:
				unsigned int i, j, size, temp;
				j = 0;
				size = DEFAULT_HASH_LENGTH_HEX;
				for (i = 8; i < size; i += 8)
				{
					hexIn.insert(i, " ");
					size++;
					i++;
				}

				//Convert to byte array:
				istringstream hexStream(hexIn);
				while ((hexStream >> std::hex >> temp) && (j < size))
				{
					ptrIn[j] = (unsigned int)temp;
					//cout << std::setfill ('0') << std::setw(sizeof(cl_uchar)*2) << std::hex << (int)lookupTarget[j];
					j++;
				}
			}
			catch (...)
			{
				throw HexConversionError("An error occurred converting up this has value. Please provide a HEX encoded string");
			}
		}
	}

	//PBKDF2 Methods:

	inline void Pbkdf2HexStringToIntPtr(string hexIn, unsigned int* ptrIn)
	{
		if (hexIn.length() != DEFAULT_PBKDF2_HASH_LENGTH_HEX)
		{
			throw HexConversionError("The hash provided is not of the correct length. Please provide a HEX encoded string of length 64 for PBKDF2");
		}
		else
		{
			try
			{
				//Add separators to hex:
				unsigned int i, j, size, temp;
				j = 0;
				size = DEFAULT_PBKDF2_HASH_LENGTH_HEX;
				for (i = 8; i < size; i += 8)
				{
					hexIn.insert(i, " ");
					size++;
					i++;
				}

				//Convert to byte array:
				istringstream hexStream(hexIn);
				while ((hexStream >> std::hex >> temp) && (j < size))
				{
					ptrIn[j] = (unsigned int)temp;
					//cout << std::setfill ('0') << std::setw(sizeof(cl_uchar)*2) << std::hex << (int)lookupTarget[j];
					j++;
				}
			}
			catch (...)
			{
				throw HexConversionError("An error occurred converting up this has value. Please provide a HEX encoded string");
			}
		}
	}

	inline void Pbkdf2HexStringToCharPtr(string hexIn, unsigned char* ptrIn)
	{
		if (hexIn.length() > DEFAULT_PBKDF2_SALT_LENGTH_HEX)
		{
			throw HexConversionError("The hash provided is not of the correct length. Please provide a HEX encoded string");
		}
		else
		{
			try
			{
				//Add separators to hex:
				unsigned int i, j, size, temp;
				j = 0;
				size = hexIn.length();
				for (i = 2; i < size; i += 2)
				{
					hexIn.insert(i, " ");
					size++;
					i++;
				}

				//Convert to byte array:
				istringstream hexStream(hexIn);
				ptrIn[(DEFAULT_PBKDF2_SALT_LENGTH_HEX / 2)] = '\0';

				while ((hexStream >> std::hex >> temp) && (j < size))
				{
					ptrIn[j] = (unsigned char)temp;
					//cout << std::setfill ('0') << std::setw(sizeof(cl_uchar)*2) << std::hex << (int)lookupTarget[j];
					j++;
				}
			}
			catch (...)
			{
				throw HexConversionError("An error occurred converting this hash value. Please provide a HEX encoded string");
			}
		}
	}
};

#endif