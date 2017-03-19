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
#include "OCLPlatform.h"

OCLPlatform::OCLPlatform(void) 
{ 
	platformDevices = NULL;
}

OCLPlatform::OCLPlatform(cl_int pId) : platformId(pId) 
{ 
	platformDevices = NULL;
}

OCLPlatform::OCLPlatform(cl_int pId, Platform pObj) : platformId(pId) 
{ 
	platform = pObj;
	//Set platform data from the current OCL platform object:
	RetrievePlatformInfo(CL_PLATFORM_VENDOR,     vendor);
	RetrievePlatformInfo(CL_PLATFORM_NAME,		 name);
	RetrievePlatformInfo(CL_PLATFORM_VERSION,	 version);
	RetrievePlatformInfo(CL_PLATFORM_EXTENSIONS, extensions);
	RetrievePlatformInfo(CL_PLATFORM_PROFILE,    profile);

	//Retrive CL platform available devices:
	platformDevices = new OCLDeviceTypeCollection(&platformId, &platform);
}

OCLPlatform::OCLPlatform(cl_int pId,	 string vendor, string name, 
						 string version, string ext,	string prof) 
						 : platformId(pId),	 vendor(vendor),  name(name), 
						 version(version), extensions(ext), profile(prof) { }

OCLPlatform::~OCLPlatform(void) 
{ 
	if (platformDevices) { delete platformDevices; }
}

//Getters:
Platform					OCLPlatform::GetPlatform()			const	{ return platform; }
cl_int						OCLPlatform::GetPlatformId()		const	{ return platformId; }
string						OCLPlatform::GetVendor()			const	{ return vendor; }
string						OCLPlatform::GetName()				const	{ return name; }
string						OCLPlatform::GetVersion()			const	{ return version;}
string						OCLPlatform::GetExtensions()		const	{ return extensions; }
string						OCLPlatform::GetProfile()			const	{ return profile; }
OCLDeviceTypeCollection*	OCLPlatform::GetPlatformDevices()	const	{ return platformDevices; };
//Setters:
void						OCLPlatform::SetVendor(string vIn)			{ vendor = vIn; }
void						OCLPlatform::SetName(string nIn)			{ name = nIn; }
void						OCLPlatform::SetVersion(string vIn)			{ version = vIn; }
void						OCLPlatform::SetExtensions(string eIn)		{ extensions = eIn; }
void						OCLPlatform::SetProfile(string pIn)			{ profile = pIn; }

//Platform Data Retrieval:
string OCLPlatform::GetPlatformInfo()
{
	stringstream output;

	output << "Platform Vendor:\t"		<< vendor		<< endl;
	output << "Platform Name:\t"		<< name			<< endl;
	output << "Platform Version:\t"		<< version		<< endl;
	output << "Platform Extensions:\t"	<< extensions	<< endl;
	output << "Platform Profile:\t"		<< profile		<< endl;
	output << endl;
	
	//Write Device Data to output:
	platformDevices->GetPlatformDeviceStats(output);

	return output.str();
}

//Equivalence Overload
bool OCLPlatform::operator==(const OCLPlatform& rhsPlatform) const
{
	//If platform index / ID matches, are referenced as same platform:
	return platformId == rhsPlatform.platformId;
}

//OStream overload:
ostream& operator<< (ostream& outStream, OCLPlatform& platform)
{
	outStream << "Platform Vendor:\t"		<< platform.vendor			<< endl
			  << "Platform Name:\t"		    << platform.name			<< endl
			  << "Platform Version:\t"		<< platform.version			<< endl
			  << "Platform Extensions:\t"	<< platform.extensions		<< endl
			  << "Platform Profile:\t"		<< platform.profile			<< endl
			  << endl;

	outStream << *platform.platformDevices;

	return outStream;
}