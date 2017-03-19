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
#ifndef OCLCOMMANDQUEUE_H_
#define OCLCOMMANDQUEUE_H_

#define __NO_STD_VECTOR 
#define CL_USE_DEPRECATED_OPENCL_1_1_APIS
#define __CL_ENABLE_EXCEPTIONS

#ifdef MAC
	#include <OpenCL/cl.hpp>
#else
	#include <CL/cl.hpp>
#endif

#include <iomanip> //std::hex
#include <bitset>  //bitset

#include "OCLErrorChecker.h"
#include "OCLBuffer.h"
#include "PasswordGenerator.h"
#include "RainbowBlock.h"

using cl::CommandQueue;
using cl::Context;
using cl::Device;
using cl::NDRange;
using cl::Event;
using cl::Kernel;
using cl::NullRange;
using cl::Buffer;

/*
	Wrapper around the core Cl.hpp API CommandQueue wrapper.

	Open CL command queue is used to handle all commands between
	the CPU-side code and the OCL kernel code.  This includes data
	transfers to and from OCL buffers along with kernel code execution
	dispatch, callback and error handling (such as compilation / linking
	failiures).
 */
class OCLCommandQueue
{
public:
	OCLCommandQueue(void);
	OCLCommandQueue(Context& ctx, Device& device, Kernel* kernel,
					int globalWorkgroupSize, int localWorkgroupSize,
					int globalWorkgroupDimensions, int localWorkgroupDimensions,
					int noKernels, int hashOutputBytes);
	~OCLCommandQueue(void);

	void ExecuteKernel(PasswordGenerator* passwords, OCLBuffer* kernelDataBuffers);
	void ExecuteKernelOutputRead(Buffer outputBuffer, const int outputBufferSize, bool isRainbowMode); //TODO -Return results?
	void ExecuteKernelOutputReadInt(Buffer outputBuffer, const int outputBufferSize, bool isRainbowMode);

	cl_bool ExecuteKernelCollisionDetect(Buffer collisionBuffer);
	void ExecuteKernelOutputReadToRainbow(Buffer outputBuffer, const int outputBufferSize, RainbowBlock* blockIn);
	void ExecuteKernelOutputReadToRainbowInt(Buffer outputBuffer, const int outputBufferSize, RainbowBlock* blockIn);
	void LoadNextPasswordBlock(Buffer inputBuffer, const int inputBufferSize, cl_uchar* passwordBuffer);
protected:
private:
	cl_int errorCode;

	Context context;
	Device device;
	Kernel* kernel;
	int globalWorkgroupSize;
	int globalWorkgroupDimensions;
	int localWorkgroupSize;
	int localWorkgroupDimensions;
	int noKernels;
	int hashOutputBytes;

	CommandQueue* dispatchQueue;
};
#endif