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
#include "OCLDeviceTypeCollection.h"


OCLDeviceTypeCollection::OCLDeviceTypeCollection(void) 
{ 
	platformId = 0;
	platform = NULL;
	InitDetailsLists();
}

OCLDeviceTypeCollection::OCLDeviceTypeCollection(Platform* pObj) : platform(pObj) 
{ 
	platformId = 0;
	InitDetailsLists();

	//Retrive CL platform available devices:
	RetrieveDeviceList(CL_DEVICE_TYPE_ALL, allDevices, noDevices);
	RetrieveDeviceList(CL_DEVICE_TYPE_CPU, cpuDevices, noCPU);
	RetrieveDeviceList(CL_DEVICE_TYPE_GPU, gpuDevices, noGPU);
	RetrieveDeviceList(CL_DEVICE_TYPE_ACCELERATOR, acceleratorDevices, noAccelerator);
	RetrieveDeviceList(CL_DEVICE_TYPE_DEFAULT, defaultDevices, noDefault);
	RetrieveDeviceList(CL_DEVICE_TYPE_CUSTOM, customDevices, noCustom);
}

OCLDeviceTypeCollection::OCLDeviceTypeCollection(cl_int* pId, Platform* pObj) : platformId(pId), platform(pObj) 
{ 
	InitDetailsLists();

	//Retrive CL platform available devices:
	RetrieveDeviceList(CL_DEVICE_TYPE_ALL, allDevices, noDevices);
	RetrieveDeviceList(CL_DEVICE_TYPE_CPU, cpuDevices, noCPU);
	RetrieveDeviceList(CL_DEVICE_TYPE_GPU, gpuDevices, noGPU);
	RetrieveDeviceList(CL_DEVICE_TYPE_ACCELERATOR, acceleratorDevices, noAccelerator);
	RetrieveDeviceList(CL_DEVICE_TYPE_DEFAULT, defaultDevices, noDefault);
	RetrieveDeviceList(CL_DEVICE_TYPE_CUSTOM, customDevices, noCustom);
}

OCLDeviceTypeCollection::~OCLDeviceTypeCollection(void) 
{ 
	DeleteDeviceInfo(allDeviceInfo);
	DeleteDeviceInfo(cpuDeviceInfo);
	DeleteDeviceInfo(gpuDeviceInfo);
	DeleteDeviceInfo(acceleratorDeviceInfo);
	DeleteDeviceInfo(customDeviceInfo);
	DeleteDeviceInfo(defaultDeviceInfo);
}

//Getters:
cl_int OCLDeviceTypeCollection::GetNumberDevices()								const	{ return noDevices; }
cl_int OCLDeviceTypeCollection::GetNumberCPUs()									const	{ return noCPU; }
cl_int OCLDeviceTypeCollection::GetNumberGPUs()									const	{ return noGPU; }
cl_int OCLDeviceTypeCollection::GetNumberAccelerators()							const	{ return noAccelerator; }
cl_int OCLDeviceTypeCollection::GetNumberCustomDevices()						const	{ return noCustom; }
cl_int OCLDeviceTypeCollection::GetNumberDefaultDevices()						const	{ return noDefault; }

VECTOR_CLASS<Device> OCLDeviceTypeCollection::GetAllDevices()					const	{ return allDevices; }
VECTOR_CLASS<Device> OCLDeviceTypeCollection::GetCPUs()							const	{ return cpuDevices; }
VECTOR_CLASS<Device> OCLDeviceTypeCollection::GetGPUs()							const	{ return gpuDevices; }
VECTOR_CLASS<Device> OCLDeviceTypeCollection::GetAccelerators()					const	{ return acceleratorDevices; }
VECTOR_CLASS<Device> OCLDeviceTypeCollection::GetCustomDevices()				const	{ return customDevices; }
VECTOR_CLASS<Device> OCLDeviceTypeCollection::GetDefault()						const	{ return defaultDevices; }

VECTOR_CLASS<OCLDevice*> OCLDeviceTypeCollection::GetAllDeviceInfo()			const	{ return allDeviceInfo; }
VECTOR_CLASS<OCLDevice*> OCLDeviceTypeCollection::GetCpuDeviceInfo()			const	{ return cpuDeviceInfo; }
VECTOR_CLASS<OCLDevice*> OCLDeviceTypeCollection::GetGpuDeviceInfo()			const	{ return gpuDeviceInfo; }
VECTOR_CLASS<OCLDevice*> OCLDeviceTypeCollection::GetAcceleratorDeviceInfo()	const	{ return acceleratorDeviceInfo; }
VECTOR_CLASS<OCLDevice*> OCLDeviceTypeCollection::GetDefaultDeviceInfo()		const	{ return customDeviceInfo; }
VECTOR_CLASS<OCLDevice*> OCLDeviceTypeCollection::GetCustomDeviceInfo()			const	{ return defaultDeviceInfo; }

//Functions:

void OCLDeviceTypeCollection::EnumerateAllDeviceDetailsLists() 
{ 
		RetrieveDeviceInfo(noDevices,		allDevices,			allDeviceInfo);
		RetrieveDeviceInfo(noGPU,			gpuDevices,			gpuDeviceInfo);
		RetrieveDeviceInfo(noCPU,			cpuDevices,			cpuDeviceInfo);
		RetrieveDeviceInfo(noCustom,		customDevices,		customDeviceInfo);
		RetrieveDeviceInfo(noAccelerator,	acceleratorDevices, acceleratorDeviceInfo);
		RetrieveDeviceInfo(noDefault,		defaultDevices,		defaultDeviceInfo);
}

void OCLDeviceTypeCollection::EnumerateDetailsList(DeviceTypes type) 
{ 
	switch (type)
	{
		case ALL		 :	RetrieveDeviceInfo(noDevices,		allDevices,			allDeviceInfo);
			break;
		case GPU		 :	RetrieveDeviceInfo(noGPU,			gpuDevices,			gpuDeviceInfo);
			break;
		case CPU		 :	RetrieveDeviceInfo(noCPU,			cpuDevices,			cpuDeviceInfo);
			break;
		case CUSTOM		 :	RetrieveDeviceInfo(noCustom,		customDevices,		customDeviceInfo);
			break;
		case ACCELERATOR :	RetrieveDeviceInfo(noAccelerator,	acceleratorDevices, acceleratorDeviceInfo);
			break;
		case DEFAULT	 :	RetrieveDeviceInfo(noDefault,		defaultDevices,		defaultDeviceInfo);
			break;
		//Default case should never hit, without subsequent erroneous source changes, but let's
		//throw just in case of such an error:
		default			 :  throw("An invalid Platform Device Type has been selected");
	}
}

void OCLDeviceTypeCollection::GetPlatformDeviceStats(stringstream &streamIn)
{
	streamIn <<	"Number of available OpenCL devices on this platform:\t" 
			  << noDevices << endl
			  << "CPUs:\t"					<< noCPU			<< endl
			  << "GPUs:\t"					<< noGPU			<< endl
			  << "Accelerators:\t"			<< noAccelerator	<< endl
			  << "Custom:\t"				<< noCustom			<< endl
			  << "of which are default:\t"	<< noDefault		<< endl;
}

//OStream overload:
ostream& operator<< (ostream& outStream, OCLDeviceTypeCollection& devCol)
{
	outStream << "Number of available OpenCL devices on this platform:\t" 
			  << devCol.noDevices << endl
			  << "CPUs:\t"					<< devCol.noCPU			<< endl
			  << "GPUs:\t"					<< devCol.noGPU			<< endl
			  << "Accelerators:\t"			<< devCol.noAccelerator	<< endl
			  << "Custom:\t"				<< devCol.noCustom		<< endl
			  << "of which are default:\t"	<< devCol.noDefault		<< endl;

	return outStream;
}