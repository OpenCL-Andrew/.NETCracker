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
#include "OCLCommandQueue.h"
#include "Timer.h"

OCLCommandQueue::OCLCommandQueue(void) 
{ 
	throw("Error in OCLBuffer::OCLBuffer(void) - Default constructor is undefined.");
}

OCLCommandQueue::OCLCommandQueue(Context& ctx, Device& device, Kernel* kernel,
								 int globalWorkgroupSize, int localWorkgroupSize,
								 int globalWorkgroupDimensions, int localWorkgroupDimensions,
								 int noKernels, int hashOutputBytes)
					: context(ctx), device(device), kernel(kernel),
					globalWorkgroupSize(globalWorkgroupSize), localWorkgroupSize(localWorkgroupSize),
					globalWorkgroupDimensions(globalWorkgroupDimensions), localWorkgroupDimensions(localWorkgroupDimensions),
					noKernels(noKernels), hashOutputBytes(hashOutputBytes)
{
	dispatchQueue = new CommandQueue(context, device, 0, &errorCode);
	checkErr(errorCode, "OCLCommandQueue::OCLCommandQueue()");
}

OCLCommandQueue::~OCLCommandQueue(void) 
{
	if (dispatchQueue) { delete dispatchQueue; }
}

/*
	TODO - fix this so that it takes a delegate for the call back.
	This will prevent us blocking.  We can use the slack time to produce more
	password input data.  Maybe back / front buffering of raw password data etc.
 */
void OCLCommandQueue::ExecuteKernel(PasswordGenerator* passwords, OCLBuffer* kernelDataBuffers)
{
	Timer time = Timer();
	try
	{
		if (noKernels <= 1)
		{
			if (localWorkgroupSize <= 0)
			{
				//Set default:
				localWorkgroupSize = 256;
			}
			//Allow default kernel-execution model:

			//This fn is used to distribute data across device processing resources:
			errorCode = dispatchQueue->enqueueNDRangeKernel(
				*kernel,
				NDRange(0,0),//NullRange, //Offset to first block (0).
				NDRange(globalWorkgroupSize, globalWorkgroupDimensions),//NDRange((globalWorkgroupSize / 64), 64), //Global work item size = sizeof(cl_uchar) * outputBufferSize,
				NDRange(localWorkgroupSize, localWorkgroupDimensions),//NullRange, //Local work item size -no. work items per work group
				NULL,
				NULL); //Pass event for callback //&dispatchDelegate
		}
		//Allows split-kernel processing on device (sub-divides workload to prevent locking device resources):
		else if (noKernels > 1)
		{

			//Init First Kernel:
			errorCode = dispatchQueue->enqueueNDRangeKernel(
				*kernel,
				NDRange(0,0),//NullRange, //Offset to first block (0).
				NDRange(globalWorkgroupSize / noKernels, globalWorkgroupDimensions), //Global work item size //sizeof(cl_uchar) * outputBufferSize,
				NDRange(localWorkgroupSize, localWorkgroupDimensions),//NullRange,//NDRange(1,1),//NDRange(localWorkgroupSize, localWorkgroupDimensions), //Local work item size -no. work items per work group
				NULL,
				NULL); //Pass event for callback //&dispatchDelegate

			//Init remaining kernels:
			int i;
			for (i = 1; i < noKernels; i++)
			{
				errorCode = dispatchQueue->enqueueNDRangeKernel(
					*kernel,
					NDRange(((globalWorkgroupSize / noKernels) * i), globalWorkgroupDimensions), 
					NDRange(globalWorkgroupSize / noKernels, globalWorkgroupDimensions), 
					NDRange(localWorkgroupSize, localWorkgroupDimensions),
					NULL,
					NULL);
			}
		}
		
		//********************************************************************
		//*			 ASYNC DATA COLLECTION OF NEXT PASSWORD BLOCK			 *
		//********************************************************************
		passwords->LoadBlockThreaded();

		//Force block on completion of workgroup, before reading from returned buffer:
		//dispatchDelegate.wait();

		//Load next password block to GPU:
		const Buffer& inputBuffer = kernelDataBuffers->GetPasswordBuffer();
		LoadNextPasswordBlock(inputBuffer, passwords->GetBufferSize(), (cl_uchar*)(passwords->GetBufferPointer()));
	}
	catch (std::exception& e)
	{
		std::cout << "Exception in OCLCommandQueue::ExecuteKernel() - " << e.what() << std::endl;
	}
	catch (...)
	{
		//TODO - THROW a custom exception back to caller. For now:
		std::cout << "Exception in OCLCommandQueue::ExecuteKernel()" << std::endl;
	}
}

void OCLCommandQueue::ExecuteKernelOutputRead(Buffer outputBuffer, const int outputBufferSize, bool isRainbowMode)
{
	//Malloc C uchar array to store output buffer:
	cl_uchar* out_global = (cl_uchar*)malloc(sizeof(cl_uchar) * outputBufferSize);

	errorCode = dispatchQueue->enqueueReadBuffer(
		outputBuffer,
		CL_TRUE,
		0,
		sizeof(cl_uchar) * outputBufferSize,
		out_global);
	checkErr(errorCode, "CommandQueue::enqueueReadBuffer()");

	//********************************TODO********************************
	//*																	 *
	//*		<<SOMETHING MORE USEFUL THAN JUST PRINTING OUT HERE>>		 *
	//*																	 *
	//********************************TODO********************************

	//Test first hash:
	for (int i = 0; i < outputBufferSize; i++)
	{
		if (isRainbowMode)
		{
			std::cout << std::setfill ('0') << std::setw(sizeof(cl_uchar)*2) 
			<< std::hex << (int)out_global[i]; //Print Hash Hex
			//std::cout << (unsigned char)out_global[i];
		}
		else
		{
			std::cout << (unsigned char)out_global[i]; //Print Password
		}

		if (((i + 1) % hashOutputBytes) == 0)
		{
			std::cout << std::dec << " - " << i << std::endl;
		}
	}
	std::cout << std::endl;

	free(out_global);
}

/*
 * Duplicate of above function, added post-dissertation, so that the buffer would handle
 * integer datatypes.  Should really be merged back into the above fn() to deal with all#
 * cases once I'm happy everything works correctly.
 */
void OCLCommandQueue::ExecuteKernelOutputReadInt(Buffer outputBuffer, const int outputBufferSize, bool isRainbowMode)
{
	//Malloc C uchar array to store output buffer:
	cl_uint* out_global = (cl_uint*)malloc(sizeof(cl_uint) * outputBufferSize);

	errorCode = dispatchQueue->enqueueReadBuffer(
		outputBuffer,
		CL_TRUE,
		0,
		sizeof(cl_uint) * outputBufferSize,
		out_global);
	checkErr(errorCode, "CommandQueue::enqueueReadBuffer()");

	//********************************TODO********************************
	//*																	 *
	//*		<<SOMETHING MORE USEFUL THAN JUST PRINTING OUT HERE>>		 *
	//*					>:-D Somethings never happen...					 *
	//*																	 *
	//********************************TODO********************************

	//Test first hash:
	for (int i = 0; i < 2000; i++) //Print first 1k for now only.
	{
		if (isRainbowMode)
		{
			std::cout << std::setfill ('0') << std::setw(sizeof(cl_uchar)*8) << std::hex << (int)out_global[i];
			//std::cout << std::setfill ('0') << std::setw(sizeof(cl_uchar)*2) 
			//<< std::hex << (int)out_global[i]; //Print Hash Hex
			//std::cout << (unsigned char)out_global[i];
		}

		if (((i + 1) % (hashOutputBytes / 4)) == 0) 
		{
			std::cout << std::dec << " - " << i << std::endl;
		}
	}
	std::cout << std::endl;

	free(out_global);
}

cl_bool OCLCommandQueue::ExecuteKernelCollisionDetect(Buffer collisionBuffer)
{
	cl_bool out = false;
	cl_bool* out_global = &out;

	errorCode = dispatchQueue->enqueueReadBuffer(
		collisionBuffer,
		CL_TRUE,
		0,
		sizeof(cl_bool),
		out_global);
	checkErr(errorCode, "CommandQueue::enqueueReadBuffer()");

	return out;
}

void OCLCommandQueue::ExecuteKernelOutputReadToRainbow(Buffer outputBuffer, const int outputBufferSize, RainbowBlock* blockIn)
{
	//Write Output to Rainbow Block:
	errorCode = dispatchQueue->enqueueReadBuffer(
		outputBuffer,
		CL_TRUE,
		0,
		sizeof(cl_uchar) * outputBufferSize,
		blockIn->GetBlockHandle());
	checkErr(errorCode, "CommandQueue::enqueueReadBuffer()");
}

void OCLCommandQueue::ExecuteKernelOutputReadToRainbowInt(Buffer outputBuffer, const int outputBufferSize, RainbowBlock* blockIn)
{
	//Write Output to Rainbow Block:
	errorCode = dispatchQueue->enqueueReadBuffer(
		outputBuffer,
		CL_TRUE,
		0,
		sizeof(cl_uint) * outputBufferSize,
		blockIn->GetBlockHandle());
	checkErr(errorCode, "CommandQueue::enqueueReadBuffer()");
}

void OCLCommandQueue::LoadNextPasswordBlock(Buffer inputBuffer, const int inputBufferSize, cl_uchar* passwordBuffer)
{
	try
	{
		Event dispatchDelegate;

		errorCode = dispatchQueue->enqueueWriteBuffer(
			inputBuffer,
			CL_FALSE,//CL_TRUE,
			0,
			sizeof(cl_uchar) * inputBufferSize,
			passwordBuffer,
			NULL,
			&dispatchDelegate);

		//Must force block on completion of workgroup, before reading from returned buffer:
		//dispatchDelegate.wait();
	}
	catch (std::exception& e)
	{
		std::cout << "Exception in OCLCommandQueue::ExecuteKernel() - " << e.what() << std::endl;
	}
	catch (...)
	{
		//TODO - THROW a custom exception back to caller. For now:
		std::cout << "Exception in OCLCommandQueue::ExecuteKernel()" << std::endl;
	}
}
