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
#ifndef OCLPLATFORMSELECTOR_H_
#define OCLPLATFORMSELECTOR_H_

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

#include "OCLTypeEnums.h"
#include "OCLPlatform.h"
#include "OCLDevice.h"

using std::endl;
using std::cout;
using std::stringstream;
using std::ostream;
using cl::Device;
using cl::Platform;

class OCLPlatformSelector
{
public:
	OCLPlatformSelector(void);
	OCLPlatformSelector(VECTOR_CLASS<DeviceTypes> selectedDeviceTypes);
	~OCLPlatformSelector(void);

	//Platform Informational Querying:
	cl_int GetNumberOfPlatforms			()										const;
	string GetAllAvailablePlatforms		()										const;
	string GetPlatformDeviceInfo		(const int& platformId)					const;
	string GetDeviceInfoForPlatform		(const int& platformId, int& deviceId)	const;
	string GetAllDeviceInfoForPlatform	(const int& platformId)					const;
	//Platform handles (API wrappers):
	OCLPlatform*				SelectPlatform						(const int& platformId);
	VECTOR_CLASS<OCLPlatform*>	SelectPlatforms						(const VECTOR_CLASS<int>& platformIds);
	VECTOR_CLASS<OCLPlatform*>* SelectAllPlatforms					();
	VECTOR_CLASS<OCLDevice*>	SelectAllDevicesForPlatform			(const int& platformId);
	OCLDevice*					SelectDeviceForPlatform				(const int& platformId, const int& deviceId);
	VECTOR_CLASS<OCLDevice*>	SelectDevicesForPlatform			(const int& platformId, const VECTOR_CLASS<int>& deviceList);
	VECTOR_CLASS<OCLDevice*>	SelectDevicesOfGivenTypeForPlatform	(const int& platformId);

protected:

private:
	bool allDeviceTypes; 

	VECTOR_CLASS<Platform> availablePlatforms;
	cl_int numberOfAvailPlatforms;

	VECTOR_CLASS<DeviceTypes> selectedDeviceTypes;
	VECTOR_CLASS<OCLPlatform*> availablePlatformInfo;

	//Methods:

	/*
		Method retrieves iniformation on the available platforms and
		associated devices for a given collection of OpenCL core API
		platform handles.  i.e. VECTOR_CLASS<Platform> availablePlatforms;
	 */
	inline void RetrievePlatformInfoObjects()
	{
		int i;
		for (i = 0; i < numberOfAvailPlatforms; ++i)
		{
			//Build Platform Object:
			OCLPlatform* platform = new OCLPlatform(i, availablePlatforms[i]);

			//Enumerate specified types:
			if (allDeviceTypes)
			{
				platform->GetPlatformDevices()->EnumerateAllDeviceDetailsLists();
			}
			else
			{
				int noSelectedPlatforms = selectedDeviceTypes.size();
				int j;
				for (j = 0; i < noSelectedPlatforms; j++)
				{
					platform->GetPlatformDevices()->EnumerateDetailsList(selectedDeviceTypes[j]);
				}
			}

			//Push onto platform collection:
			availablePlatformInfo.push_back(platform);
		}
	}

	//TODO - Need to return any errors to caller ultimately...
	inline void checkPlatformError()
	{
		int code = availablePlatforms.size() !=0 ? CL_SUCCESS : CL_DEVICE_NOT_FOUND;
		checkErr(code, "cl::Platform::get");
	}

	//Error Checking Function, adapted from OCL tutorial:
	//http://developer.amd.com/tools-and-sdks/heterogeneous-computing/amd-accelerated-parallel-processing-app-sdk/introductory-tutorial-to-opencl/
    inline void checkErr(cl_int err, const char* name)
    {
		if (err != CL_SUCCESS) 
		{
			cout << "ERROR: " << name << " (" << err << ")" << endl;
		}
    }

	/*
		Method retrieves the core OpenCL API platform object handles.
	 */
	inline void RetrieveCorePlatformHandles() 
	{
		//Retrieve available platforms:
		Platform::get(&availablePlatforms);
		//Set number avail:
		numberOfAvailPlatforms = availablePlatforms.size();
		//Log any errors:
		checkPlatformError();
	}

	inline void AddDeviceTypesToList(VECTOR_CLASS<OCLDevice*>& sourceList, VECTOR_CLASS<OCLDevice*>& destinationList)
	{
		int i;
		for (i = 0; (unsigned)i < sourceList.size(); i++)
		{
			destinationList.push_back(sourceList[i]);
		}
	}
};
#endif