/*
 * This Program is an OpenCL accelerated password cracking application.
 *
 *     ___              __                     ____            __    ___      __  
 *    /   |  ____  ____/ /_______ _      __   / __ \__  ______/ /___/ (_)____/ /__
 *   / /| | / __ \/ __  / ___/ _ \ | /| / /  / /_/ / / / / __  / __  / / ___/ //_/
 *  / ___ |/ / / / /_/ / /  /  __/ |/ |/ /  / _, _/ /_/ / /_/ / /_/ / / /__/ ,<   
 * /_/  |_/_/ /_/\__,_/_/   \___/|__/|__/  /_/ |_|\__,_/\__,_/\__,_/_/\___/_/|_|  
 *
 * BSc Computer Science (Security & Resilience) Dissertation
 * University Of Newcastle Upon Tyne
 *
 *
 * -------------------------------------------------------------------------------
 * 
 * Copyright (C) 2013 - 2014 Andrew Ruddick
 * Distributed under the Boost Software License, Version 1.0.
 * (See accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 *
 * -------------------------------------------------------------------------------
 *
 * This file is part of The .NETCracker Suite.
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

#ifndef OCLCORE_H_
#define OCLCORE_H_

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

//Custom Types:
#include "OCLPlatformSelector.h"
#include "OCLContext.h"
#include "OCLKernel.h"
#include "OCLBuffer.h"
#include "OCLCommandQueue.h"
#include "OCLSettings.h"

//Support Libs:
#include "CrackingAlphabet.h"
#include "PasswordGenerator.h"
#include "Password.h"

//Other includes:
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <exception>

using std::cout;
using std::cerr;
using std::cin;
using std::endl;
using std::string;
using std::exception;

using cl::Program;
using cl::Platform;
using cl::Context;
using cl::Device;
using cl::Kernel;
using cl::vector;

const int LOCAL_WORKGROUP_DIM = 1;
const int GLOBAL_WORKGROUP_DIM = 1;

/*
 * This class forms the core OpenCL API wrapper and encapsulates 
 * a good portion of the functionality provided by the rest of 
 * this library.  It does not currently support split operation
 * of kernel cracking over multiple platform devices, though the
 * underlying data structures and types have all been designed
 * with such functionality in mind.  Thus it should be possible
 * to extend this Core wrapper to split the execution of kernel
 * cracking across all devices on a given platform, without a
 * massive expenditure of effort. AR
 *
 */
class OCLCore
{
public:
	OCLCore(void);
	~OCLCore(void);

	void Init();
	
	//Settings File Persistence Helpers:
	void				LoadDefaultSettingsFile				();
	void				LoadCustomSettingsFile				(string fileLoc);
	void				LoadCustomSettingsObject			(OCLSettings& settingsIn);
	void				SaveToDefualtSettingsFile			();
	void				SaveSettingsFile					(string fileLoc);
	void				SaveCustomSettingsObject			(OCLSettings& settingsIn); //Convenience Wrapper (handles errors)
	void				SaveCustomSettingsObjectToFile		(OCLSettings& settingsIn, string fileLoc); //Convenience Wrapper (handles errors)
	OCLSettings*		GetSettingsObject					();

	//OpenCL Platform Management:
	string				GetAvailablePlatformInfo			()								const;
	void				DisplayAvailablePlatformInfo		()								const;
	int					GetNumberOfPlatforms				()								const;
	string				GetPlatformDetails					(int platformId)				const;
	void				DisplayPlatformDetails				(int platformId)				const;
	string				GetPlatformDeviceSummary			()								const;
	void				DisplayPlatformDeviceSummary		()								const;
	string				GetPlatformAllDeviceDetails			(int platformId)				const;
	void				DisplayPlatformAllDeviceDetails		(int platformId)				const;
	string				GetPlatformDeviceDetails			(int platformId, int deviceId)	const;
	void				DisplayPlatformDeviceDetails		(int platformId, int deviceId)	const;
	string				GetSelectedPlatform					()								const;	
	void				DisplaySelectedPlatform				()								const;
	string				GetSelectedPlatformDevice			()								const;	
	void				DisplaySelectedPlatformDevice		()								const;
	string				GetLoadedPlatform					()								const;	
	void				DisplayLoadedPlatform				()								const;
	string				GetLoadedPlatformDevice				()								const;	
	void				DisplayLoadedPlatformDevice			()								const;

	//Platform/Device Selection/ Loading:
	void				SelectAvailablePlatform				(int platformId);
	void				SelectAvailablePlatformDevice		(int platformId, int deviceId);
	void				LoadSelectedPlatform				();
	void				LoadSelectedPlatformDevice			();
	void				SelectAndLoadPlatform				(int platformId);
	void				SelectAndLoadPlatformDevice			(int platformId, int deviceId);

	//Password Generator Info:
	PasswordGenerator*	GetPasswordGenerator				();
	Password*			GetPasswordPointer					();
	int					GetPasswordLength					()								const;
	int					GetPasswordBlockSize				()								const;
	int					GetHashByteLength					()								const;
	int					GetHashOutputBlockSize				()								const;
	InfInt				GetPasswordKeyspaceSize				()								const;
	string				GetPasswordKeyspaceStats			()								const;
	InfInt				GetNoRequiredExecutions				()								const;
	void				DisplayPasswordKeyspaceStats		()								const;
	string				GetPasswordBufferData				()								const;
	void				DisplayPasswordBufferData			()								const;
	string				GetPasswordBufferDataForThread		(int threadId)					const;
	void				DisplayPasswordBufferDataForThread	(int threadId)					const;
	string				GetPasswordAlphabet					()								const;
	int					GetPasswordAlphabetSize				()								const;

	//Kernel Info:
	string				GetKernelSource						()								const;
	void				DisplayKernelSource					()								const;

	//Kernel Management Methods:
	void				BuildContext						();
	void				SetupPasswordGenerator				();
	void				BuildBuffers						(cl_uint* targetHash, 
															 cl_uchar* targetSalt,  
															 cl_bool* hashCollisionFound,
															 int saltLen, 
															 cl_uint* iPadHash, 
															 cl_uint* oPadHash);
	void				BuildKernel							(string filePath, string kernelName);
	void				ExecuteKernel						();
	void				RetrieveKernelOutput				();
	void				RetrieveKernelOutputInt				();
	cl_bool				KernelCollisionFound				();
	void				RetrieveKernelOutputToRainbowBlock	(RainbowBlock* blockIn);
	void				RetrieveKernelOutputToRainbowBlockInt(RainbowBlock* blockIn);

	//Custom ExceptionTypes:
	class LoadDeviceException : public std::runtime_error 
	{ 
		public: 
			LoadDeviceException(string m = "An exception occured in OCLCore!") 
				:std::runtime_error(m) { }
	};
	
	class InvalidSettingsException : public std::runtime_error 
	{ 
		public: 
			InvalidSettingsException(string m = "An exception occured in OCLCore!") 
				:std::runtime_error(m) { }
	};

	class PasswordGeneratorException : public std::runtime_error 
	{ 
		public: 
			PasswordGeneratorException(string m = "An exception occured in OCLCore!") 
				:std::runtime_error(m) { }
	};

protected:
	//Platform / Device Methods:
	void PlatformConversion(const OCLPlatform* platformWrapper);
	void PlatformConversion(const VECTOR_CLASS<OCLPlatform*>& platformWrapper);
	void DeviceConversion(const OCLDevice* deviceWrapper);
	void DeviceConversion(const VECTOR_CLASS<OCLDevice*>& deviceWrapper);

	//Kernel Methods:
	void CreateOCLBuffers(cl_uint* hashPtr, cl_uchar* saltPtr, cl_bool* hashCollisionFound, int hashLen, int saltLen, int outputBufferSize, 
						  cl_uint* iPadHash, cl_uint* oPadHash);
	void CreateDeviceKernelHandle(string filePath, string kernelName);
	void CreateKernelIOQueue(Device& device, int globalWorkgroupSize,
								 int globalWorkgroupDimensions, int localWorkgroupDimensions);
private:
	OCLPlatformSelector*	platformHandle;
	OCLContext*				executionContext; //Maybe could have a Vector of these to allow multiple platforms?
	//VECTOR_CLASS<OCLCommandQueue*> deviceQueue; //To store a list of OCL device kernel command queues
	OCLPlatform*			system;
	OCLDevice*				device;

	OCLBuffer*				kernelDataBuffers;
	OCLKernel*				deviceKernelHandle;
	PasswordGenerator*		passwords;
	OCLCommandQueue*		kernelIOQueue;
	OCLSettings*			settings;
	
	VECTOR_CLASS<Platform>	platforms;
	VECTOR_CLASS<Device>	devices;
};
#endif