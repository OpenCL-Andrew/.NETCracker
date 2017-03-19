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
#include "OCLBuffer.h"


OCLBuffer::OCLBuffer(void)
{
	throw("Error in OCLBuffer::OCLBuffer(void) - Default constructor is undefined.");
}

OCLBuffer::OCLBuffer(Context& ctx, cl_uchar* passwordBufferPtr, cl_uint* hashBufferPtr, 
					 cl_uchar* saltBufferPtr, cl_bool* hashCollisionFound, cl_uint* iPadHashPtr, cl_uint* oPadHashPtr,
					 int passwordBufferLen, int saltLenBytes, int hashLenBytes, int outputBufferSze, int passwordLen, 
					 bool isRainbowMode, bool isHmac)
		:isRainbowMode(isRainbowMode), isHmac(isHmac)
{
	//Store CL_x data types:
	passwordBufferPointer	  =	passwordBufferPtr;
	saltBufferPointer		  =	saltBufferPtr;
	hashBufferPointer		  =	hashBufferPtr;
	context					  =	ctx;
	collisionFlagPointer	  = hashCollisionFound;
	iPadHashPointer			  = iPadHashPtr;
	oPadHashPointer			  = oPadHashPtr;

	//Store data lengths:
	saltByteLength			  =	(cl_int) saltLenBytes;
	hashByteLength			  =	(cl_int) hashLenBytes;
	passwordBufferLength	  =	(cl_int) passwordBufferLen;
	passwordLength			  =	(cl_int) passwordLen;
							  
	//Calc output size:		 			 
	outputBufferSize		  =	(cl_int) outputBufferSze;

	//Allocate buffers:
	AllocOCLBuffers();
}

OCLBuffer::~OCLBuffer(void) { }

//Getters:

Buffer OCLBuffer::GetPasswordBuffer() const
{
	return passwordBuffer;
}

Buffer OCLBuffer::GetTargetHash() const
{
	return targetHash;
}

Buffer OCLBuffer::GetTargetSalt() const
{
	return targetSalt;
}

Buffer OCLBuffer::GetBlockOutput() const
{
	return blockOutput;
}

Buffer OCLBuffer::GetPasswordSize() const
{
	return passwordSizeBuffer;
}

Buffer OCLBuffer::GetSaltSize() const
{
	return saltSizeBuffer;
}

Buffer OCLBuffer::GetCollisionFound() const
{
	return collisionBuffer;
}

Buffer OCLBuffer::GetOPadHash() const
{
	return oPadHash;
}

Buffer OCLBuffer::GetIPadHash() const
{
	return iPadHash;
}

//Setters:

void OCLBuffer::SetPasswordBuffer(Buffer& bufIn)
{
	passwordBuffer = bufIn;
}

void OCLBuffer::SetTargetHash(Buffer& bufIn)		
{
	targetHash = bufIn;
}

void OCLBuffer::SetTargetSalt(Buffer& bufIn)	
{
	targetSalt = bufIn;
}

void OCLBuffer::SetBlockOutput(Buffer& bufIn)
{
	blockOutput = bufIn;
}

void OCLBuffer::SetPasswordSize(Buffer& bufIn)
{
	passwordSizeBuffer = bufIn;
}

void OCLBuffer::SetSaltSize(Buffer& bufIn)
{
	saltSizeBuffer = bufIn;
}

void OCLBuffer::SetCollisionBuffer(Buffer& bufIn)
{
	collisionBuffer = bufIn;
}

void OCLBuffer::SetOPadHash(Buffer& bufIn)
{
	oPadHash = bufIn;
}

void OCLBuffer::SetIPadHash(Buffer& bufIn)
{
	iPadHash = bufIn;
}

void OCLBuffer::AllocOCLBuffers()
{
	try
	{
		cl_int errorCode;

		//Build Buffer:
		passwordBuffer			= Buffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(cl_uchar) * passwordBufferLength, passwordBufferPointer, &errorCode);
		//Check CL.C C error flags:
		checkErr(errorCode, "OCLBuffer::AllocOCLBuffers()"); //TODO - if not 0, throw.
		
		targetHash				= Buffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, hashByteLength, hashBufferPointer, &errorCode);
		checkErr(errorCode, "OCLBuffer::AllocOCLBuffers()");

		targetSalt				= Buffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, saltByteLength, saltBufferPointer, &errorCode);
		checkErr(errorCode, "OCLBuffer::AllocOCLBuffers()");

		passwordSizeBuffer		= Buffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(cl_int), &passwordLength, &errorCode);
		checkErr(errorCode, "OCLBuffer::AllocOCLBuffers()");

		saltSizeBuffer			= Buffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(cl_int), &saltByteLength, &errorCode);
		checkErr(errorCode, "OCLBuffer::AllocOCLBuffers()");

		blockOutput				= Buffer(context, CL_MEM_WRITE_ONLY, sizeof(cl_uchar) * outputBufferSize, NULL, &errorCode);
		checkErr(errorCode, "OCLBuffer::AllocOCLBuffers()");

		//If is HMAC or PBKDF2, need iPad & oPad pre-computation buffers:
		if (isHmac)
		{
			iPadHash			= Buffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(cl_int) * 5, 
										 iPadHashPointer, &errorCode); //Hard-coded to SHA1 (160-bit |h|)
			checkErr(errorCode, "OCLBuffer::AllocOCLBuffers()");

			oPadHash			= Buffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(cl_int) * 5, 
										 oPadHashPointer, &errorCode); //Hard-coded to SHA1 (160-bit |h|)
			checkErr(errorCode, "OCLBuffer::AllocOCLBuffers()");
		}

		if (isRainbowMode)
		{
			blockOutput				= Buffer(context, CL_MEM_WRITE_ONLY, sizeof(cl_uint) * outputBufferSize, NULL, &errorCode);
			checkErr(errorCode, "OCLBuffer::AllocOCLBuffers()");
		}
		else 
		{
			//We're in brute-force crack mode, hence only require one hash output, i.e. the crack:
			blockOutput				= Buffer(context, CL_MEM_WRITE_ONLY, passwordLength, NULL, &errorCode);
			checkErr(errorCode, "OCLBuffer::AllocOCLBuffers()");
			//Crack Found flag:
			collisionBuffer			= Buffer(context, CL_MEM_WRITE_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(cl_bool), collisionFlagPointer, &errorCode);
			checkErr(errorCode, "OCLBuffer::AllocOCLBuffers()");
		}
	}
	catch (...)
	{
		//Catch and log CL.HPP C++ wrapper errors:
		std::cout << "Exception in OCLBuffer::AllocOCLBuffers()!" << std::endl;
	}
}

void OCLBuffer::RemapPasswordInputData()
{
	try
	{
		cl_int errorCode;

		//Build Buffer:
		passwordBuffer = Buffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(cl_uchar) * passwordBufferLength, passwordBufferPointer, &errorCode);
		//Check CL.C C error flags:
		checkErr(errorCode, "OCLBuffer::AllocOCLBuffers()"); 
	}
	catch (...)
	{
		//Catch and log CL.HPP C++ wrapper errors:
		std::cout << "Exception in OCLBuffer::AllocOCLBuffers()!" << std::endl;
	}
}