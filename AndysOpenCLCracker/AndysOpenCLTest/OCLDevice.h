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
#ifndef OCLDEVICE_H_
#define OCLDEVICE_H_
//#define __CL_ENABLE_EXCEPTIONS

#ifdef MAC
	#include <OpenCL/cl.hpp>
#else
	#include <CL/cl.hpp>
#endif

#include <string>
#include <cstring>
#include <iostream>
#include <sstream>

using std::string;
using std::stringstream;
using std::ostream;
using std::endl;
using std::size_t;

using cl::Platform;
using cl::Device;

class OCLDevice
{
public:
	OCLDevice(void);
	OCLDevice(cl_int* platformId, Platform* platform, Device* device);
	~OCLDevice(void);

	//Getters:
	Device*						GetDevice()					const;
	string						GetName()					const;
	string						GetVendor()					const;
	string						GetDevicePlatform()			const;
	string						GetOCLCVersion()			const;
	string						GetSupportedExtensions()	const;
	cl_uint						GetComputeUnits()			const;
	cl_uint						GetMaxWorkItemDimensions()	const;
	VECTOR_CLASS<std::size_t>	GetMaxWorkItemSize()		const;
	cl_uint						GetMaxWorkgroupSize()		const;
	cl_long						GetGlobalMemSize()			const;
	cl_uint						GetMaxClockFreq()			const;
	cl_ulong					GetMaxAllocatableMem()		const;
	cl_ulong					GetLocalMemSize()			const;
	cl_bool						GetIsLittleEndian()			const;
	cl_bool						GetDeviceAvailablity()		const;

	//Setters:
	void SetName					(string   nIn);
	void SetVendor					(string   vIn);
	void SetDevicePlatform			(string   pIn);
	void SetOpenCLCVersion			(string   cvIn);
	void SetSupportedExtensions		(string   extIn);
	void SetComputeUnits			(cl_uint  cuIn);
	void SetMaxWorkItemDimensions	(cl_uint  dIn);
	void SetMaxWorkItemSize			(VECTOR_CLASS<std::size_t> isIn);
	void SetMaxWorkgroupSize		(cl_uint  wgsIn);
	void SetGlobalMemSize			(cl_long  gMemIn);
	void SetMaxClockFreq			(cl_uint  freqIn);
	void SetMaxAllocatableMem		(cl_ulong alocMemIn);
	void SetLocalMemSize			(cl_ulong locMemIn);
	void SetIsLittleEndian			(cl_bool  leFlagIn);
	void SetDeviceAvailablity		(cl_bool  devAvailIn);

	friend ostream& operator<<(ostream& outStream, OCLDevice& device);

protected:
private:
	//Device Data:
	Platform* platform;
	cl_int* platformId;
	Device* device;

	string   name;
	string   vendor;
	string	 devicePlatform;
	string	 oclCVersion;
	string	 supportedExtensions;
	cl_uint  computeUnits;
	cl_uint	 workItemDimensions;
	VECTOR_CLASS<std::size_t>  maxWorkItemSize;
	cl_uint  maxWorkgroupSize;
	cl_long  globalMemSize;
	cl_uint  maxClockFreq;
	cl_ulong maxAllocatableMem;
	cl_ulong localMemSize;
	cl_bool  isLittleEndian;
	cl_bool  deviceAvailable;
};
#endif