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
#include "OCLDevice.h"

OCLDevice::OCLDevice(void) { }

OCLDevice::OCLDevice(cl_int* platformId, Platform* platform, Device* device) 
	: platformId(platformId), platform(platform), device(device) 
{ 
	device->getInfo(CL_DEVICE_NAME, &name); //Also pass cl_int &err and check for CL_SUCCESS here!
	device->getInfo(CL_DEVICE_VENDOR, &vendor);
	device->getInfo(CL_DEVICE_PLATFORM, &platform);
	device->getInfo(CL_DEVICE_OPENCL_C_VERSION, &oclCVersion);
	device->getInfo(CL_DEVICE_EXTENSIONS, &supportedExtensions);
	device->getInfo(CL_DEVICE_MAX_COMPUTE_UNITS, &computeUnits);
	device->getInfo(CL_DEVICE_MAX_WORK_ITEM_DIMENSIONS, &workItemDimensions);
	device->getInfo(CL_DEVICE_MAX_WORK_ITEM_SIZES, &maxWorkItemSize);
	device->getInfo(CL_DEVICE_MAX_WORK_GROUP_SIZE, &maxWorkgroupSize);
	device->getInfo(CL_DEVICE_GLOBAL_MEM_SIZE, &globalMemSize);
	device->getInfo(CL_DEVICE_MAX_CLOCK_FREQUENCY, &maxClockFreq);
	device->getInfo(CL_DEVICE_MAX_MEM_ALLOC_SIZE, &maxAllocatableMem);
	device->getInfo(CL_DEVICE_LOCAL_MEM_SIZE, &localMemSize);
	device->getInfo(CL_DEVICE_ENDIAN_LITTLE, &isLittleEndian);
	device->getInfo(CL_DEVICE_AVAILABLE, &deviceAvailable);
}

OCLDevice::~OCLDevice(void) { }

//Getters:
Device*						OCLDevice::GetDevice()					const { return device; }
string						OCLDevice::GetName()					const { return name; }
string						OCLDevice::GetVendor()					const { return vendor; }
string						OCLDevice::GetDevicePlatform()			const { return devicePlatform; }
string						OCLDevice::GetOCLCVersion()				const { return oclCVersion; }
string						OCLDevice::GetSupportedExtensions()		const { return supportedExtensions; }
cl_uint						OCLDevice::GetComputeUnits()			const { return computeUnits; }
cl_uint						OCLDevice::GetMaxWorkItemDimensions()	const { return workItemDimensions; }
VECTOR_CLASS<std::size_t>	OCLDevice::GetMaxWorkItemSize()			const { return maxWorkItemSize; }
cl_uint						OCLDevice::GetMaxWorkgroupSize()		const { return maxWorkgroupSize; }
cl_long						OCLDevice::GetGlobalMemSize()			const { return globalMemSize; }
cl_uint						OCLDevice::GetMaxClockFreq()			const { return maxClockFreq; }
cl_ulong					OCLDevice::GetMaxAllocatableMem()		const { return maxAllocatableMem; }
cl_ulong					OCLDevice::GetLocalMemSize()			const { return localMemSize; }
cl_bool						OCLDevice::GetIsLittleEndian()			const { return isLittleEndian; }
cl_bool						OCLDevice::GetDeviceAvailablity()		const { return deviceAvailable; }

//Setters:
void OCLDevice::SetName							(string   nIn)						{ name = nIn; }
void OCLDevice::SetVendor						(string   vIn)						{ vendor = vIn; }
void OCLDevice::SetDevicePlatform				(string   pIn)						{ devicePlatform = pIn; }
void OCLDevice::SetOpenCLCVersion				(string   cvIn)						{ oclCVersion = cvIn; }
void OCLDevice::SetSupportedExtensions			(string   extIn)					{ supportedExtensions = extIn; }
void OCLDevice::SetComputeUnits					(cl_uint  cuIn)						{ computeUnits = cuIn; }
void OCLDevice::SetMaxWorkItemDimensions		(cl_uint  dIn)						{ workItemDimensions = dIn; }
void OCLDevice::SetMaxWorkItemSize				(VECTOR_CLASS<std::size_t>  isIn)	{ maxWorkItemSize = isIn; }
void OCLDevice::SetMaxWorkgroupSize				(cl_uint  wgsIn)					{ maxWorkgroupSize = wgsIn; }
void OCLDevice::SetGlobalMemSize				(cl_long  gMemIn)					{ globalMemSize = gMemIn; }
void OCLDevice::SetMaxClockFreq					(cl_uint  freqIn)					{ maxClockFreq = freqIn; }
void OCLDevice::SetMaxAllocatableMem			(cl_ulong allocMemIn)				{ maxAllocatableMem = allocMemIn; }
void OCLDevice::SetLocalMemSize					(cl_ulong locMemIn)					{ localMemSize = locMemIn; }
void OCLDevice::SetIsLittleEndian				(cl_bool  leFlagIn)					{ isLittleEndian = leFlagIn; }
void OCLDevice::SetDeviceAvailablity			(cl_bool  devAvailIn)				{ deviceAvailable = devAvailIn; }

//OStream overload:
ostream& operator<< (ostream& outStream, OCLDevice& device)
{
	outStream << "Device Name:\t"				<< device.name						<< endl
			  << "Vendor:\t"					<< device.vendor					<< endl
			  << "Platform:\t"					<< device.devicePlatform			<< endl
			  << "Supported OpenCL C Version:\t"<< device.oclCVersion				<< endl
			  << "Supported Extensions:\t"		<< device.supportedExtensions		<< endl
			  << "Compute Units:\t"				<< device.computeUnits				<< endl
			  << "Max WorkItem Dimesions:\t"	<< device.workItemDimensions		<< endl
			  << "Max WorkItem Sizes:\t"		<< device.maxWorkItemSize[0] << "," << 
			   device.maxWorkItemSize[1] << "," << device.maxWorkItemSize[2]		<< endl
			  << "Max Workgroup Size:\t"		<< device.maxWorkgroupSize			<< endl
			  << "Clock Frequency:\t"			<< device.maxClockFreq				<< endl
			  << "Global Memory:\t"				<< (double)device.globalMemSize / 1048576		
												<< " MB"					<< endl
			  << "Max Allocatable Memory:\t"	<< (double)device.maxAllocatableMem / 1048576	
												<< " MB"					<< endl
			  << "Local Memory:\t"				<< device.localMemSize				<< endl
			  << "Is Little Endian:\t"			<< device.isLittleEndian			<< endl
			  << "Available:\t"					<< device.deviceAvailable			<< endl;
	
	return outStream;
}