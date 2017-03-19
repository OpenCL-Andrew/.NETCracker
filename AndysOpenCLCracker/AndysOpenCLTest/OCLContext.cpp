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
#include "OCLContext.h"

OCLContext::OCLContext(void)
{
	throw("Error in OCLContext::OCLContext(void) - Default constructor is undefined.");
}

OCLContext::OCLContext(Platform& platform, DeviceTypes& deviceType)
{
	operationalPlatform = platform;
	selectedPlatformType = ConvertDeviceType(deviceType);
	BuildContextProperties();
	BuildContextForDeviceType();
}

OCLContext::OCLContext(Platform& platform, Device& device)
{
	operationalPlatform = platform;
	operationalPlatformDevices.push_back(device);
	BuildContextProperties();
	BuildContextForDeviceList();
}

OCLContext::OCLContext(Platform& platform, VECTOR_CLASS<Device>& devices)
{
	operationalPlatform = platform;
	operationalPlatformDevices = devices;
	BuildContextProperties();
	BuildContextForDeviceList();
}

OCLContext::~OCLContext(void) { }

//Getters:
Context OCLContext::GetContext() const
{
	return context;
}

Platform OCLContext::GetPlatform() const
{
	return operationalPlatform;
}

VECTOR_CLASS<Device> OCLContext::GetDevices() const
{
	return operationalPlatformDevices;
}

//Setters:
void OCLContext::SetContext(Context contextIn)
{
	context = contextIn;
}

void OCLContext::SetPlatform(Platform platformIn)
{
	operationalPlatform = platformIn;
}

void OCLContext::SetDevices(VECTOR_CLASS<Device> devicesIn)
{
	operationalPlatformDevices = devicesIn;
}