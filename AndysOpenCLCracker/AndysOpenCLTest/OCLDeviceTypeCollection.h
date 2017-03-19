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
#ifndef OCLDEVICETYPECOLLECTION_H_
#define OCLDEVICETYPECOLLECTION_H_

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
#include "OCLDevice.h"

using std::endl;
using std::stringstream;
using std::ostream;
using cl::Device;
using cl::Platform;

class OCLDeviceTypeCollection
{
public:
	OCLDeviceTypeCollection(void);
	OCLDeviceTypeCollection(Platform* pObj);
	OCLDeviceTypeCollection(cl_int* pId, Platform* pObj);
	~OCLDeviceTypeCollection(void);

	//Getters:
	cl_int GetNumberDevices()							const;
	cl_int GetNumberCPUs()								const;
	cl_int GetNumberGPUs()								const;
	cl_int GetNumberAccelerators()						const;
	cl_int GetNumberCustomDevices()						const;
	cl_int GetNumberDefaultDevices()					const;

	VECTOR_CLASS<Device> GetAllDevices()				const;
	VECTOR_CLASS<Device> GetCPUs()						const;
	VECTOR_CLASS<Device> GetGPUs()						const;
	VECTOR_CLASS<Device> GetAccelerators()				const;
	VECTOR_CLASS<Device> GetCustomDevices()				const;
	VECTOR_CLASS<Device> GetDefault()					const;

	VECTOR_CLASS<OCLDevice*> GetAllDeviceInfo()			const;
	VECTOR_CLASS<OCLDevice*> GetCpuDeviceInfo()			const;
	VECTOR_CLASS<OCLDevice*> GetGpuDeviceInfo()			const;
	VECTOR_CLASS<OCLDevice*> GetAcceleratorDeviceInfo()	const;
	VECTOR_CLASS<OCLDevice*> GetDefaultDeviceInfo()		const;
	VECTOR_CLASS<OCLDevice*> GetCustomDeviceInfo()		const;

	//Functions:
	void EnumerateAllDeviceDetailsLists();
	void EnumerateDetailsList(DeviceTypes type);

	//Provide stats on platform devices:
	void GetPlatformDeviceStats(stringstream &streamIn);
	//void GetPlatformDeviceStats(stringstream &ostream);
	friend ostream& operator<<(ostream& outStream, OCLDeviceTypeCollection& devCol);

protected:
private:
	//DeviceTypes deviceType;
	//VECTOR_CLASS<Device> deviceCollection;

	//Platform Info:
	Platform* platform;
	cl_int* platformId;

	//Platform Devices:
	cl_int noDevices;
	//Specific Device Types:
	cl_int noDefault;
	cl_int noCPU;
	cl_int noGPU;
	cl_int noAccelerator;
	cl_int noCustom;
	//Vector of available platform devices:
	VECTOR_CLASS<Device> allDevices;
	VECTOR_CLASS<Device> cpuDevices;
	VECTOR_CLASS<Device> gpuDevices;
	VECTOR_CLASS<Device> acceleratorDevices;
	VECTOR_CLASS<Device> defaultDevices;
	VECTOR_CLASS<Device> customDevices;

	//Enumerable Collections of Device Info:
	VECTOR_CLASS<OCLDevice*> allDeviceInfo;
	VECTOR_CLASS<OCLDevice*> cpuDeviceInfo;
	VECTOR_CLASS<OCLDevice*> gpuDeviceInfo;
	VECTOR_CLASS<OCLDevice*> acceleratorDeviceInfo;
	VECTOR_CLASS<OCLDevice*> defaultDeviceInfo;
	VECTOR_CLASS<OCLDevice*> customDeviceInfo;

	/*
		Initialise vectors to store OCLDevice data for each platform.  
		
		In a large distributed system, this could form a large collection
		of objects - on the assumption we could potentialy run this software on
		multiple racks of systems (be that blades in the cloud or more specialised
		GPGPU cracking rigs), anyway, hence 'newing them up.
	 */
	inline void InitDetailsLists()
	{
		allDeviceInfo = VECTOR_CLASS<OCLDevice*>();
		cpuDeviceInfo = VECTOR_CLASS<OCLDevice*>();
		gpuDeviceInfo = VECTOR_CLASS<OCLDevice*>();
		acceleratorDeviceInfo = VECTOR_CLASS<OCLDevice*>();
		defaultDeviceInfo = VECTOR_CLASS<OCLDevice*>();
		customDeviceInfo = VECTOR_CLASS<OCLDevice*>();
	}

	/*
		Given a device type, storage vector and cl_int will return a list of all devices of 
		the specified type along with the total count of that device type.  Wraps the call
		in CL exception handler - if device type is unavailable, a NULL reference is returned.
	 */
	inline void RetrieveDeviceList(const cl_uint attrib, VECTOR_CLASS<Device>& output, cl_int& noDevices)
	{
		try
		{
			platform->getDevices(attrib,	&output);
			noDevices = output.size();
		}
		catch (...)
		{
			output = NULL;
			noDevices = 0;
		}
	}

	/*
		Inline method defined to retrieve objects of type OCLDevice to populate 
		the Device type collection objects.
	 */
	inline void RetrieveDeviceInfo(const cl_int noDevices, VECTOR_CLASS<Device> &deviceList, VECTOR_CLASS<OCLDevice*> &infoList)
	{
		//Ensure List is empty before we populate, else it's possible that we're double-populating:
		if (infoList.size() == 0)
		{
			int i;
			for (i = 0; i < noDevices; i++)
			{
				infoList.push_back(new OCLDevice(platformId, platform, &deviceList[i]));
			}
		}
		else
		{
			throw("ERROR in OCLDeviceTypeCollection.RetrieveDeviceInfo(): The provided OCLDevice Collection object is not currently empty.");
		}
	}

	/*
		Cleanup any object references made when details were retrieved:
	 */
	inline void DeleteDeviceInfo(VECTOR_CLASS<OCLDevice*> &infoList)
	{
		//Check not NULL reference:
		if (infoList)
		{
			//Clean up:
			int i;
			for (i = 0; (unsigned) i < infoList.size(); i++)
			{
				delete infoList[i];
			}
			infoList.clear();
		}
	}

};
#endif