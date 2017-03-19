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
#ifndef OCLCONTEXT_H_
#define OCLCONTEXT_H_

#define __NO_STD_VECTOR 
#define CL_USE_DEPRECATED_OPENCL_1_1_APIS
#define __CL_ENABLE_EXCEPTIONS

#ifdef MAC
	#include <OpenCL/cl.hpp>
#else
	#include <CL/cl.hpp>
#endif

#include <string>
#include <iostream>
#include <sstream>

#include "OCLErrorChecker.h"
#include "OCLTypeEnums.h"
#include "OCLPlatform.h"
#include "OCLDevice.h"

using std::endl;
using std::cout;
using std::stringstream;
using std::ostream;

using cl::Device;
using cl::Platform;
using cl::Context;

const int NO_CONTEXT_PROPERTIES = 3;

class OCLContext
{
public:
	OCLContext(void);
	OCLContext(Platform& platform, DeviceTypes& deviceType);
	OCLContext(Platform& platform, Device& device);
	OCLContext(Platform& platform, VECTOR_CLASS<Device>& devices);
	~OCLContext(void);

	//Getters:
	Context					GetContext()	const;
	Platform				GetPlatform()	const;
	VECTOR_CLASS<Device>	GetDevices()	const;
	//Setters:
	void SetContext		(Context contextIn);
	void SetPlatform	(Platform platformsIn);
	void SetDevices		(VECTOR_CLASS<Device> devicesIn);

protected:

private:
	cl_int errorCode;

	Platform operationalPlatform;
	VECTOR_CLASS<Device> operationalPlatformDevices;

	cl_context_properties cprops[NO_CONTEXT_PROPERTIES];
	Context context;
	int selectedPlatformType;

	inline void BuildContextProperties()
	{
		cprops[0] = CL_CONTEXT_PLATFORM;
		cprops[1] = (cl_context_properties)(operationalPlatform)();
		cprops[2] = 0;
	}

	inline void BuildContextForDeviceType()
	{
		context = Context(selectedPlatformType, cprops, NULL, NULL, &errorCode);
		//TODO - Probably want to raise an exception here if there has been an error!
		//Check if there has been a context creation error:
		checkErr(errorCode, "Conext::Context()"); 
	}

	inline void BuildContextForDeviceList()
	{
		context = Context(operationalPlatformDevices, cprops, NULL, NULL, &errorCode);
		//TODO - Probably want to raise an exception here if there has been an error!
		//Check if there has been a context creation error:
		checkErr(errorCode, "Conext::Context()"); 
	}

	/*
		Method converts a given platform device type enums into a 32-bit code
		used by the CL API to select given devices on the platform of execution.
	 */
	inline int ConvertDeviceType(DeviceTypes toConvert)
	{
		switch (toConvert)
		{
			case ALL		 :	return CL_DEVICE_TYPE_ALL;
				break;
			case GPU		 :	return CL_DEVICE_TYPE_GPU;
				break;
			case CPU		 :	return CL_DEVICE_TYPE_CPU;
				break;
			case CUSTOM		 :	return CL_DEVICE_TYPE_CUSTOM;
				break;
			case ACCELERATOR :	return CL_DEVICE_TYPE_ACCELERATOR;
				break;
			case DEFAULT	 :	return CL_DEVICE_TYPE_DEFAULT;
				break;
			//Default case should never hit, without subsequent erroneous source changes, but lets
			//throw just in case of such an error:
			default			 :  throw("An invalid Platform Device Type has been selected");
		}
	}

};
#endif