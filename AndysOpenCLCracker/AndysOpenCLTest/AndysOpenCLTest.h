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
#ifndef ANDYSOPENCLAPP_H_
#define ANDYSOPENCLAPP_H_
#define MEM_SIZE (128)
#define MAX_SOURCE_SIZE (0x100000)

#include <utility>
#define __NO_STD_VECTOR // Use cl::vector instead of STL version

#define CL_USE_DEPRECATED_OPENCL_1_1_APIS
#ifdef MAC
#include <OpenCL/cl.hpp>
#else
//cl.hpp is the ++ version of the CL header file.
#include <CL/cl.hpp>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
//#include <SDKCommon.hpp>
//#include <SDKApplication.hpp>
//#include <SDKCommandArgs.hpp>
//#include <SDKFile.hpp>

class AndysOpenCLTest
{
public:
	AndysOpenCLTest() : BUFFER_SIZE(10000) { }
    void GetDeviceInfo();
    void CreateDeviceContext();
	void CreateIOBuffers();
	void BuildProgram();
	void CreateAndExecKernel();
	void CreateAndExecKernelV2();
	void ReleaseResources();

private:
    //Class variables:
	cl_float BUFFER_SIZE;
    
    //Number of platforms and platform IDs:
    cl_uint num_platforms;			//this number will hold the number of platforms on this machine
    cl_platform_id *platforms;
	cl_int ret;

    //Number of devices per platform and IDs:
    cl_uint num_devices;
    cl_uint num_cpu;
    cl_uint num_gpu;
    cl_device_id *devices;

    //Platform information allocations:
    char vendor[1024];				//this strirng will hold a platforms vendor
    char version[1024];				
    char name[1024];				
    char platformExt[1024];		
    char platformProf[1024];

    //Device information allocations:
    char deviceName[1024];			//this string will hold the devices name
    cl_uint numberOfCores;			//this variable holds the number of cores of on a device
    cl_uint workgroupSize;          //max size of a workgroup
	cl_long amountOfMemory;			//this variable holds the amount of memory on a device
	cl_uint clockFreq;				//this variable holds the clock frequency of a device
	cl_ulong maxAlocatableMem;		//this variable holds the maximum allocatable memory
	cl_ulong localMem;				//this variable holds local memory for a device
	cl_bool	available;				//this variable holds if the device is available

    //Queue:
    cl_context context;
    cl_command_queue queue;

	//Mem buffers:
	cl_mem inputBuffer;				// device memory used for the input array
	cl_mem outputBuffer;			// device memory used for the output array
	cl_mem memobj;

	char string[MEM_SIZE]; //Temp, to hold output values

	cl_program program;
	cl_kernel kernel; 

	//Kernel File reading:
	FILE *fp;
	char *source_str;
	size_t source_size;
};

#endif