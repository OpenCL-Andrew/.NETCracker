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
#include "OCLPlatformSelector.h"


OCLPlatformSelector::OCLPlatformSelector(void)
{
	//Default = 0 Platforms:
	numberOfAvailPlatforms = 0;
	//All types of platform (e.g. GPU / CPU):
	allDeviceTypes = true;
	selectedDeviceTypes = NULL;
	availablePlatformInfo = VECTOR_CLASS<OCLPlatform*>();
	//Retrieve List of the available CL platforms from this instance:
	RetrieveCorePlatformHandles();
	//Build a detailed information collection on the current platform handle:
	RetrievePlatformInfoObjects();
}

OCLPlatformSelector::OCLPlatformSelector(VECTOR_CLASS<DeviceTypes> selectedDeviceTypes)  
	: selectedDeviceTypes(selectedDeviceTypes)
{ 
	//Default = 0 Platforms:
	numberOfAvailPlatforms = 0;
	allDeviceTypes = false;
	availablePlatformInfo = VECTOR_CLASS<OCLPlatform*>();
	//Retrieve List of the available CL platforms from this instance:
	RetrieveCorePlatformHandles();
	//Build a detailed information collection on the current platform handle:
	RetrievePlatformInfoObjects();
}

OCLPlatformSelector::~OCLPlatformSelector(void) 
{ 
	if (availablePlatformInfo.size() >= 1)
	{
		//Cleanup platform objects:
		int i;
		for (i = 0; (unsigned)i < availablePlatformInfo.size(); i++)
		{
			delete availablePlatformInfo[i];
		}
	}
}

/*
	Returns to caller the total number of OpenCl platforms
	available on this instace.
*/
cl_int OCLPlatformSelector::GetNumberOfPlatforms() const
{
	return numberOfAvailPlatforms;
}

string OCLPlatformSelector::GetAllAvailablePlatforms() const
{
	stringstream output;

	int i;
	for (i = 0; i < numberOfAvailPlatforms; i++)
	{
		output << "Platform " << i << ": \t" << availablePlatformInfo[i]->GetName() << endl;
		output << "\t\tAvailable Devices: \t" << availablePlatformInfo[i]->GetPlatformDevices()->GetNumberDevices() << endl;
	}

	output << endl;

	return output.str();
}

string OCLPlatformSelector::GetPlatformDeviceInfo(const int& platformId) const
{
	VECTOR_CLASS<OCLDevice*> platformDevices = availablePlatformInfo[platformId]->GetPlatformDevices()->GetAllDeviceInfo();
	stringstream output;

	output << "Selected Platform: " << platformId << " - " << availablePlatformInfo[platformId]->GetName() << endl;
	output << "Available Platform Devices: " << endl;
	output << endl;

	int i;
	for (i = 0; (unsigned)i < platformDevices.size(); i++)
	{
		output << "\tDevice " << i << " - " << platformDevices[i]->GetName() << endl;
		output << "\tDevice Vendor: \t" << platformDevices[i]->GetVendor() << endl;
		output << endl;
	}
	
	output << endl;

	return output.str();
}

string OCLPlatformSelector::GetDeviceInfoForPlatform(const int& platformId, int& deviceId) const
{
	VECTOR_CLASS<OCLDevice*> platformDevices = availablePlatformInfo[platformId]->GetPlatformDevices()->GetAllDeviceInfo();
	stringstream output;

	output << "Selected Platform: " << platformId << " - " << availablePlatformInfo[platformId]->GetName() << endl;
	output << "Selected Device: " << deviceId << " - " << platformDevices[deviceId]->GetName() << endl;
	output << endl;
	output << "Details:" << endl;
	output << endl;
	output << *platformDevices[deviceId] << endl;

	return output.str();
}

string OCLPlatformSelector::GetAllDeviceInfoForPlatform(const int& platformId) const
{
	VECTOR_CLASS<OCLDevice*> platformDevices = availablePlatformInfo[platformId]->GetPlatformDevices()->GetAllDeviceInfo();
	stringstream output;

	output << "Selected Platform: " << platformId << " - " << availablePlatformInfo[platformId]->GetName() << endl;

	int i;
	for (i = 0; (unsigned)i < platformDevices.size(); i++)
	{
		output << "Selected Device: " << i << " - " << platformDevices[i]->GetName() << endl;
		output << endl;
		output << "Details:" << endl;
		output << endl;
		output << *platformDevices[i] << endl;
	}

	return output.str();
}

OCLPlatform* OCLPlatformSelector::SelectPlatform(const int& platformId)
{
	return availablePlatformInfo[platformId];
}

VECTOR_CLASS<OCLPlatform*> OCLPlatformSelector::SelectPlatforms(const VECTOR_CLASS<int>& platformIds)
{
	VECTOR_CLASS<OCLPlatform*> selectedPlatforms = VECTOR_CLASS<OCLPlatform*>();

	int i;
	for (i = 0; (unsigned)i < platformIds.size(); i++)
	{
		selectedPlatforms.push_back(availablePlatformInfo[platformIds[i]]);
	}

	return selectedPlatforms;
}

VECTOR_CLASS<OCLPlatform*>* OCLPlatformSelector::SelectAllPlatforms()
{
	return &availablePlatformInfo;
}

VECTOR_CLASS<OCLDevice*> OCLPlatformSelector::SelectAllDevicesForPlatform(const int& platformId)
{
	return availablePlatformInfo[platformId]->GetPlatformDevices()->GetAllDeviceInfo();
}

OCLDevice* OCLPlatformSelector::SelectDeviceForPlatform(const int& platformId, const int& deviceId)
{
	return availablePlatformInfo[platformId]->GetPlatformDevices()->GetAllDeviceInfo()[deviceId];
}

VECTOR_CLASS<OCLDevice*> OCLPlatformSelector::SelectDevicesForPlatform(const int& platformId, const VECTOR_CLASS<int>& deviceList)
{
	VECTOR_CLASS<OCLDevice*> allPlatformDevices = availablePlatformInfo[platformId]->GetPlatformDevices()->GetAllDeviceInfo();
	VECTOR_CLASS<OCLDevice*> selectedDevices = VECTOR_CLASS<OCLDevice*>();

	int i;
	for (i = 0; (unsigned)i < deviceList.size(); i++)
	{
		selectedDevices.push_back(allPlatformDevices[deviceList[i]]);
	}

	return selectedDevices;
}

VECTOR_CLASS<OCLDevice*> OCLPlatformSelector::SelectDevicesOfGivenTypeForPlatform(const int& platformId)
{
	if (selectedDeviceTypes == NULL)
	{
		throw("ERROR in OCLPlatformSelector::SelectDevicesOfGivenTypeForPlatform(const int& platformId) - No device types specified!");
	}

	VECTOR_CLASS<OCLDevice*> allPlatformDevices = availablePlatformInfo[platformId]->GetPlatformDevices()->GetAllDeviceInfo();
	VECTOR_CLASS<OCLDevice*> selectedDevices = VECTOR_CLASS<OCLDevice*>();

	int i;
	for (i = 0; (unsigned)i < selectedDeviceTypes.size(); i++)
	{
		switch (selectedDeviceTypes[i])
		{
			case ALL		 :	//If an all specifier has been set, we're wasting time in this loop,
								//so lets break out:
								return allPlatformDevices;
				break;
				//Else lets concat the lists:
			case GPU		 :	AddDeviceTypesToList(availablePlatformInfo[platformId]->GetPlatformDevices()->GetGpuDeviceInfo(),
													 selectedDevices);
				break;
			case CPU		 :	AddDeviceTypesToList(availablePlatformInfo[platformId]->GetPlatformDevices()->GetCpuDeviceInfo(),
												     selectedDevices);
				break;
			case CUSTOM		 :	AddDeviceTypesToList(availablePlatformInfo[platformId]->GetPlatformDevices()->GetCustomDeviceInfo(),
													 selectedDevices);
				break;
			case ACCELERATOR :	AddDeviceTypesToList(availablePlatformInfo[platformId]->GetPlatformDevices()->GetAcceleratorDeviceInfo(),
													 selectedDevices);
				break;
			case DEFAULT	 :	AddDeviceTypesToList(availablePlatformInfo[platformId]->GetPlatformDevices()->GetDefaultDeviceInfo(),
													 selectedDevices);
				break;
			//Default case should never hit, without subsequent erroneous source changes, but lets
			//throw just in case of such an error:
			default			 :  throw("An invalid Platform Device Type has been selected");
		}
	}

	//Return the resultant combined list:
	return selectedDevices;
}