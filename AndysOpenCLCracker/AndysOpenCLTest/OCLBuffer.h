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
#ifndef OCLBUFFER_H_
#define OCLBUFFER_H_

//Use cl::vector instead of STL vector:
#define __NO_STD_VECTOR 
//Enable Deprecated CL functionality:
#define CL_USE_DEPRECATED_OPENCL_1_1_APIS
//Enable CL-C++ Exception handling mechanism:
#define __CL_ENABLE_EXCEPTIONS

//cl.hpp is the C++ version of the CL header file:
#ifdef MAC
	#include <OpenCL/cl.hpp>
#else
	#include <CL/cl.hpp>
#endif

#include "OCLErrorChecker.h"

using cl::Buffer;
using cl::Context;

class OCLBuffer
{
public:
	OCLBuffer(void); //throws
	OCLBuffer(Context& ctx, cl_uchar* passwordBufferPtr, cl_uint* hashBufferPointer, 
			  cl_uchar* saltBufferPointer, cl_bool* hashCollisionFound, cl_uint* iPadHashPtr, cl_uint* oPadHashPtr, 
			  int passwordBufferLen, int saltLenBytes, int hashLenBytes, int outputBufferSize, int passwordLen, 
			  bool isRainbowMode, bool isHmac);
	~OCLBuffer(void);

	Buffer GetPasswordBuffer()	const;
	Buffer GetTargetHash()		const;
	Buffer GetTargetSalt()		const;
	Buffer GetBlockOutput()		const;
	Buffer GetPasswordSize()	const;
	Buffer GetSaltSize()		const;
	Buffer GetCollisionFound()	const;
	Buffer GetOPadHash()		const;
	Buffer GetIPadHash()		const;

	void SetPasswordBuffer	(Buffer& bufIn);
	void SetTargetHash		(Buffer& bufIn);		
	void SetTargetSalt		(Buffer& bufIn);	
	void SetBlockOutput		(Buffer& bufIn);
	void SetPasswordSize	(Buffer& bufIn);
	void SetSaltSize		(Buffer& bufIn);
	void SetCollisionBuffer	(Buffer& bufIn);
	void SetOPadHash		(Buffer& bufIn);
	void SetIPadHash		(Buffer& bufIn);

	void RemapPasswordInputData();

protected:
	void AllocOCLBuffers();

private:
	bool isRainbowMode;
	bool isHmac;
	//Input buffer sizes:
	cl_int saltByteLength;
	cl_int hashByteLength;
	cl_int passwordLength;
	cl_int passwordBufferLength;
	//Block size output = hashByteLength * passwordBufferByteLength
	cl_int outputBufferSize;
	cl_bool collisionFound;
	
	//Buffer Context params:
	Context context;
	cl_uchar* passwordBufferPointer;
	cl_uchar* saltBufferPointer;
	cl_uint* hashBufferPointer;
	cl_bool* collisionFlagPointer;
	//HMAC Pre-Comp Buffer Context params:
	cl_uint* iPadHashPointer;
	cl_uint* oPadHashPointer;

	//OCL Buffer objects:
	Buffer passwordBuffer;
	Buffer targetHash;
	Buffer targetSalt;
	Buffer blockOutput;
	Buffer passwordSizeBuffer;
	Buffer saltSizeBuffer;
	Buffer collisionBuffer;
	//HMAC Pre-Comp Buffers:
	Buffer iPadHash;
	Buffer oPadHash;
};
#endif