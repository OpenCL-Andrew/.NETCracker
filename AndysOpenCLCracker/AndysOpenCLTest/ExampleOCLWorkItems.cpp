///*
// * -------------------------------------------------------------------------------
// * 
// * Copyright (C) 2013 - 2014 Andrew Ruddick
// * BSc Computer Science (Security & Resilience) Dissertation
// * University Of Newcastle Upon Tyne
// *
// * Distributed under the Boost Software License, Version 1.0.
// * (See accompanying file LICENSE_1_0.txt or copy at
// * http://www.boost.org/LICENSE_1_0.txt)
// *
// * -------------------------------------------------------------------------------
// *
// * This file is part of The .NETCracker Suite, an OpenCL accelerated password 
// * cracking application.
// *
// * The .NETCracker Suite is free software: you can redistribute it and/or modify
// * it under the terms of the GNU General Public License as published by
// * the Free Software Foundation, either version 3 of the License, or
// * (at your option) any later version.
// *
// * The .NETCracker Suite is distributed in the hope that it will be useful,
// * but WITHOUT ANY WARRANTY; without even the implied warranty of
// * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// * GNU General Public License for more details.
// *
// * You should have received a copy of the GNU General Public License
// * along with The .NETCracker Suite.  If not, see <http://www.gnu.org/licenses/>.
// *
// * This program uses InfInt - Arbitrary-Precision Integer Arithmetic Library
// * which is Copyright (C) 2013 Sercan Tutar, as released under the LGPL.
// *
// * Additionally, the following C++ boost libraries have been used:
// *     boost.Thread
// *     boost.Serialization
// * 
// */
//#include "ExampleOCLWorkItems.h"
//
//ExampleOCLWorkItems::ExampleOCLWorkItems(void)
//{
//	Execute();
//}
//
//ExampleOCLWorkItems::~ExampleOCLWorkItems(void)
//{
//}
//
//void ExampleOCLWorkItems::Execute()
//{
//	
//	std::cout << "Hello World" << std::endl;
//	
//	try
//	{
//		cl_int errorCode;
//
//		/*****************************************
//		 *		CREATE PLATFORM HANDLE:
//		 *****************************************/
//
//		//Create a vector to store OCL platforms:
//		vector<Platform> availablePlatforms;
//
//		//Retrieve reference to available platforms:
//		Platform::get(&availablePlatforms);
//
//		checkErr(availablePlatforms.size() !=0 ? CL_SUCCESS : CL_DEVICE_NOT_FOUND, "cl::Platform::get");
//	
//		//Check no avail platforms:
//		cl_int noPlatforms = availablePlatforms.size();
//		cout << "Number of Available Platforms is: " << noPlatforms << endl;
//
//		/*****************************************
//		 *		RETRIEVE PLATFORM INFO:
//		 *****************************************/
//
//		//Check Platform Vendor info:	
//		string platformVendor;
//		availablePlatforms[0].getInfo((cl_platform_info)CL_PLATFORM_VENDOR, &platformVendor);
//		cerr << "Platform is by: " << platformVendor << "\n";
//
//
//		/*****************************************
//		 *		CREATE DEVICE CONTEXT:
//		 *****************************************/
//
//		cl_context_properties cprops[3] =
//		{
//			CL_CONTEXT_PLATFORM, 
//			(cl_context_properties)(availablePlatforms[0])(), 
//			0
//		};
//	
//		Context context(
//			CL_DEVICE_TYPE_GPU,
//			cprops,
//			NULL,
//			NULL,
//			&errorCode);
//	
//		checkErr(errorCode, "Conext::Context()"); 
//
//		/*****************************************
//		 *		ALLOCATE OCL BUFFER:
//		 *****************************************/
//		//char* outBuffer = new char[10];
//		const char inBuffer[] = "Password12Password12Password12Password12";
//		cl_uchar* input = (cl_uchar*) &inBuffer;
//
//		const cl_int inputBufferSize = 40;
//		const cl_int outputBufferSize = 80;
//
//		Buffer inCL (context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(cl_uchar) * inputBufferSize, input, &errorCode);
//		checkErr(errorCode, "Buffer::Buffer()");
//
//		Buffer outCL(context, CL_MEM_WRITE_ONLY, sizeof(cl_uchar) * outputBufferSize, NULL, &errorCode);
//		checkErr(errorCode, "Buffer::Buffer()");
//
//		/*****************************************
//		 *		BUILD OCL DEVICE VECTOR:
//		 *****************************************/
//
//		vector<Device> devices;
//		devices = context.getInfo<CL_CONTEXT_DEVICES>();
//
//		checkErr(devices.size() > 0 ? CL_SUCCESS : -1, "devices.size() > 0");
//
//		cl_int noDevices = devices.size();
//		cout << "Number of Devices: " << noDevices << endl;
//
//		/*****************************************
//		 *		LOAD KERNEL:
//		 *****************************************/
//		ifstream file("passthrough.cl");
//		checkErr(file.is_open() ? CL_SUCCESS:-1, "passthrough_kernel.cl");
//	
//		string prog(
//			istreambuf_iterator<char>(file),
//			(std::istreambuf_iterator<char>()));
//	
//		Program::Sources source(1, make_pair(prog.c_str(), prog.length()+1));
//		Program program(context, source); //Needs to be built for a SET of devices.  ie once per device context.
//
//		errorCode = program.build(devices);
//		checkErr(errorCode, "Program::build()");
//
//		//if (errorCode == CL_BUILD_PROGRAM_FAILURE) {
//		//	// Determine the size of the log
//		//	size_t log_size;
//		//	clGetProgramBuildInfo(program, devices_id[0], CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
//
//		//	// Allocate memory for the log
//		//	char *log = (char *) malloc(log_size);
//
//		//	// Get the log
//		//	clGetProgramBuildInfo(program, devices_id[0], CL_PROGRAM_BUILD_LOG, log_size, log, NULL);
//
//		//	// Print the log
//		//	printf("%s\n", log);
//		//}
//
//		/*****************************************
//		 *		BUILD KERNEL:
//		 *****************************************/
//
//		//Build Kernel:
//		Kernel kernel(program, "passthrough", &errorCode);
//		checkErr(errorCode, "Kernel::Kernel()");
//
//		//Set kernel arguments (index and value for a given kernel argument):
//		errorCode = kernel.setArg(0, outCL);
//		checkErr(errorCode, "Kernel::setArg()");
//
//		errorCode = kernel.setArg(1, inCL);
//		checkErr(errorCode, "Kernel::setArg()");
//
//		/*****************************************
//		 *		KERNEL COMMAND QUEUE EXECUTION:
//		 *****************************************/
//	
//		//Command queue is virtual interface for the device in question (one per device):
//		CommandQueue queue(context, devices[0], 0, &errorCode);
//		checkErr(errorCode, "CommandQueue::CommandQueue()");
//	
//		//Async task for kernel completion:
//		Event event;
//	
//		/* 
//			OK, this next function is the beast.
//
//			We enqueue our data for the GPU in a 1D array or chars (at present).
//		
//			Global Work Item size is the TOTAL length of data - so this is the total number
//			of passwords * length of each (ie number of characters).  We index into the array
//			based on the ID of the current compute unit.
//
//			Local Work Item size is the length of each individual block for processing by the
//			kernel.  Again, 1D output.
//
//			//TODO - need to work out how to have a larger output than input per CU...
//	
//		*/
//
//		//This fn is used to distribute data across device processing resources:
//		errorCode = queue.enqueueNDRangeKernel(
//			kernel,
//			NullRange, //Offset to first block (0).
//			NDRange(20, 1), //Global work item size //sizeof(cl_uchar) * outputBufferSize,
//			NDRange(10, 1), //Local work item size -no. work items per work group
//			NULL,
//			&event); //Pass event for callback
//		checkErr(errorCode, "ComamndQueue::enqueueNDRangeKernel()");
//
//		//errorCode = queue.enqueueNDRangeKernel(
//		//	kernel,
//		//	NullRange,
//		//	sizeof(cl_uchar) * outputBufferSize,
//		//	NDRange(1, 1),
//		//	NULL,
//		//	&event); //Pass event for callback
//	 //   OCLWrapper::checkErr(errorCode, "ComamndQueue::enqueueNDRangeKernel()");
//
//		//Must force block on completion of workgroup, before reading from returned buffer:
//		event.wait();
//
//		//Another way of doing the above:
//			//errorCode = queue.enqueueTask(kernel);
//			//OCLWrapper::checkErr(errorCode, "ComamndQueue::enqueueTask()");
//			////Wait for queue to finish:
//			//queue.finish();
//
//
//
//		cl_uchar out_global[outputBufferSize];
//
//		errorCode = queue.enqueueReadBuffer(
//			outCL,
//			CL_TRUE,
//			0,
//			sizeof(cl_uchar) * outputBufferSize,
//			&out_global);
//		checkErr(errorCode, "ComamndQueue::enqueueReadBuffer()");
//	
//		cout << "Output \t\t:" << *out_global << endl << "Output[1..n] \t:";
//		for (unsigned int i=0; i < outputBufferSize; i ++) 
//		{
//			cout << out_global[i];
//		}
//		cout << endl;
//		//return EXIT_SUCCESS;
//	}
//	catch (cl::Error e) {
//        cout << endl << e.what() << " : " << e.err() << endl;
//    }
//
//	int x;
//	std::cin >> x;
//}
