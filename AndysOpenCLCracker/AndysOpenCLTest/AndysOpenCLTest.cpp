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
#define _CRT_SECURE_NO_DEPRECATE

#include "AndysOpenCLTest.h"
#include "FileHandle.h"

#define SUCCESS 0
#define FAILURE 1

//using namespace cl;
using namespace std;
using namespace OpenCLAppLib;

//int main(int argc, char* argv[])
//{
//	//Test DLL linking:
//	FileHandle file = FileHandle();
//
//    AndysOpenCLTest openClInstance;
//
//	try
//	{
//		openClInstance.GetDeviceInfo();
//		openClInstance.CreateDeviceContext();
//		openClInstance.CreateIOBuffers();
//		openClInstance.BuildProgram();
//		//openClInstance.CreateAndExecKernel();
//		openClInstance.CreateAndExecKernelV2();
//		openClInstance.ReleaseResources();
//	}
//	catch (const std::exception &exc)
//	{
//		std::cerr << exc.what();
//	}
//
//    std::cin.get();
//
//	return SUCCESS;
//}


void AndysOpenCLTest::GetDeviceInfo()
{
    /***********************************
     *      DEVICE INFO
     ***********************************/
    
    // Ascertain the number of platforms available on this machine, using the OpenCL specification:

    //Get Number of Platforms:
    clGetPlatformIDs(NULL, NULL, &num_platforms);
    printf("\nNumber of available OpenCL platforms on this machine:\t%u\n\n", num_platforms);

    //Dynamically allocate an array of the correct size to hold the available platform IDs:
    platforms = new cl_platform_id[num_platforms];
    //Retrive platform Id's:
    clGetPlatformIDs(num_platforms, platforms, NULL);

    //Loop through platforms and display Platform data:
    unsigned int i,j;
    for (i = 0; i < num_platforms; i++)
    {
        printf("Platform:\n\n");

        clGetPlatformInfo(platforms[i], CL_PLATFORM_VENDOR, sizeof(vendor), vendor, NULL);
        clGetPlatformInfo(platforms[i], CL_PLATFORM_NAME, sizeof(name), name, NULL);
        clGetPlatformInfo(platforms[i], CL_PLATFORM_VERSION, sizeof(version), version, NULL);
        clGetPlatformInfo(platforms[i], CL_PLATFORM_EXTENSIONS, sizeof(platformExt), platformExt, NULL);
        clGetPlatformInfo(platforms[i], CL_PLATFORM_PROFILE, sizeof(platformProf), platformProf, NULL);

        printf("Platform Vendor:\t%s\n", vendor);
        printf("Platform Name:\t\t%s\n", name);
        printf("Platform Version:\t%s\n", version);
        printf("Platform Extensions:\t%s\n", platformExt);
        printf("Platform Profile:\t%s\n", platformProf);

        printf("\n");

        clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_ALL, NULL, NULL, &num_devices);
        clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_CPU, NULL, NULL, &num_cpu);
        clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_GPU, NULL, NULL, &num_gpu);
        printf("\nNumber of available OpenCL Devices for this platform:\t%u", num_devices);
        printf("\nCPUs:\t%u", num_cpu);
        printf("\nGPUs:\t%u\n\n", num_gpu);

        //Dynamically allocate an array of the correct size to hold the available device IDs:
        devices = new cl_device_id[num_devices];
        //Retrive platform Id's:
        clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_ALL, num_devices, devices, NULL);

        // Loop through GPU devices for this platform:
        for (j = 0; j < num_devices; j++)
        {
            //scan in device information
			clGetDeviceInfo(devices[j], CL_DEVICE_NAME, sizeof(deviceName), deviceName, NULL);
			clGetDeviceInfo(devices[j], CL_DEVICE_VENDOR, sizeof(vendor), vendor, NULL);
			clGetDeviceInfo(devices[j], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(numberOfCores), &numberOfCores, NULL);
            clGetDeviceInfo(devices[j], CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(workgroupSize), &workgroupSize, NULL);
			clGetDeviceInfo(devices[j], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(amountOfMemory), &amountOfMemory, NULL);
			clGetDeviceInfo(devices[j], CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(clockFreq), &clockFreq, NULL);
			clGetDeviceInfo(devices[j], CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(maxAlocatableMem), &maxAlocatableMem, NULL);
			clGetDeviceInfo(devices[j], CL_DEVICE_LOCAL_MEM_SIZE, sizeof(localMem), &localMem, NULL);
			clGetDeviceInfo(devices[j], CL_DEVICE_AVAILABLE, sizeof(available), &available, NULL);

			//print out device information
			printf("Device: %u\n", j);
			printf("\tName:\t\t\t\t%s\n", deviceName);
			printf("\tVendor:\t\t\t\t%s\n", vendor);
			printf("\tAvailable:\t\t\t%s\n", available ? "Yes" : "No");
			printf("\tCompute Units:\t\t\t%u\n", numberOfCores);
            printf("\tMax Workgroup size:\t\t%u\n", workgroupSize);
			printf("\tClock Frequency:\t\t%u mHz\n", clockFreq);
			printf("\tGlobal Memory:\t\t\t%0.00f mb\n", (double)amountOfMemory/1048576);
			printf("\tMax Allocateable Memory:\t%0.00f mb\n", (double)maxAlocatableMem/1048576);
			printf("\tLocal Memory:\t\t\t%u kb\n\n", (unsigned int)localMem);
        }
    }
}

void AndysOpenCLTest::CreateDeviceContext()
{
    /***********************************
     *      OPEN CL CONTEXT
     ***********************************/

     // Returns the context of the current CL instance:
    context = clCreateContext(0, 1, devices, NULL, NULL, NULL);
	
    queue = clCreateCommandQueue(context, devices[0], 0, NULL);
}

void AndysOpenCLTest::CreateIOBuffers()
{
	inputBuffer = clCreateBuffer(context, CL_MEM_READ_ONLY,
		sizeof((cl_float)BUFFER_SIZE), NULL, &ret);
	outputBuffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY,
		sizeof((cl_float)BUFFER_SIZE), NULL, &ret);

	memobj = clCreateBuffer(context, CL_MEM_READ_WRITE, MEM_SIZE * sizeof(char), NULL, &ret);
}

void AndysOpenCLTest::BuildProgram()
{
	char fileName[] = "../AndysOpenCLTest/hello.cl";
	/* Load the source code containing the kernel*/
	fp = fopen(fileName, "r");
	if (!fp) 
	{
		fprintf(stderr, "Failed to load kernel.\n");
		exit(1);
	}

	source_str = (char*)malloc(MAX_SOURCE_SIZE);
	source_size = fread(source_str, 1, MAX_SOURCE_SIZE, fp);
	fclose(fp);

	program = clCreateProgramWithSource(context, 1, (const char **)&source_str, (const size_t *)&source_size, &ret);
	
	/* Build Kernel Program */
	ret = clBuildProgram(program, 1, &devices[0], NULL, NULL, NULL);
}

void AndysOpenCLTest::CreateAndExecKernel()
{
	kernel = clCreateKernel(program, "hello", &ret); //hello = __kernel method name

	ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *)&memobj);
	ret = clEnqueueTask(queue, kernel, 0, NULL,NULL);

	/* Copy results from the memory buffer */
	ret = clEnqueueReadBuffer(queue, memobj, CL_TRUE, 0, MEM_SIZE * sizeof(char),string, 0, NULL, NULL);

	/* Display Result */
	puts(string);
}

void AndysOpenCLTest::CreateAndExecKernelV2()
{
	kernel = clCreateKernel(program, "hello", &ret); //hello = __kernel method name

	ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *)&memobj);
	ret = clEnqueueTask(queue, kernel, 0, NULL,NULL);

	/* Copy results from the memory buffer */
	ret = clEnqueueReadBuffer(queue, memobj, CL_TRUE, 0, MEM_SIZE * sizeof(char),string, 0, NULL, NULL);

	/* Display Result */
	puts(string);
}

void AndysOpenCLTest::ReleaseResources()
{
	/* Finalization */
	ret = clFlush(queue);
	ret = clFinish(queue);
	ret = clReleaseKernel(kernel);
	ret = clReleaseProgram(program);
	ret = clReleaseMemObject(memobj);
	ret = clReleaseCommandQueue(queue);
	ret = clReleaseContext(context);
 
	free(source_str);
}