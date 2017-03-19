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
#ifndef OCLPLATFORM_H_
#define OCLPLATFORM_H_

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

#include "OCLDeviceTypeCollection.h"

using std::string;
using std::stringstream;
using std::ostream;
using std::endl;

using cl::Platform;
using cl::Device;

class OCLPlatform
{
public:
	OCLPlatform(void);
	OCLPlatform(cl_int pId);
	OCLPlatform(cl_int pId, Platform);
	OCLPlatform(cl_int pId,		string vendor, string name, 
				string version, string ext, string prof);
	~OCLPlatform(void);

	//Getters:
	Platform GetPlatform() const;
	cl_int GetPlatformId() const;
	string GetVendor()     const;
	string GetName()       const;
	string GetVersion()	   const;
	string GetExtensions() const;
	string GetProfile()    const;
	OCLDeviceTypeCollection* GetPlatformDevices() const;

	//Setters:
	void SetVendor		(string vIn);
	void SetName		(string nIn);
	void SetVersion		(string vIn);
	void SetExtensions	(string eIn);
	void SetProfile		(string pIn);
	//Platform Data:
	string GetPlatformInfo();

	bool            operator==(const OCLPlatform& platform) const;
	friend ostream& operator<<(ostream& outStream, OCLPlatform& platform);
protected:
private:
	//Platform Data:
	Platform platform;
	cl_int platformId;
	string vendor;
	string name;
	string version;
	string extensions;
	string profile;

	//Platform Devices:
	OCLDeviceTypeCollection* platformDevices;

	/*
		Given a device info attribute and a string, will return details of that
		particular device information.  If a CL Exception is encountered, we don't
		want to halt execution, so return empty string.
	 */
	inline void RetrievePlatformInfo(const cl_uint attrib, string& output)
	{
		try
		{
			platform.getInfo((cl_platform_info)attrib, &output);
		}
		catch (...)
		{
			output = "";
		}
	}
};
#endif