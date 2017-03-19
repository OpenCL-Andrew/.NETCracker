/*
 * This Program is an OpenCL accelerated password cracking application.
 *
 * BSc Computer Science (Security & Resilience) Dissertation
 * University Of Newcastle Upon Tyne
 *
 * -------------------------------------------------------------------------------
 * 
 * Copyright (C) 2013 - 2014 Andrew Ruddick
 * Distributed under the Boost Software License, Version 1.0.
 * (See accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 *
 * -------------------------------------------------------------------------------
 *
 * This file is part of The .NETCracker Suite.
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

#include "OCLCore.h"

OCLCore::OCLCore(void)
{
	platformHandle = new OCLPlatformSelector();
	settings = new OCLSettings();
	//Init other pointers:
	executionContext	= NULL;
	system				= NULL;
	device				= NULL;
	kernelDataBuffers	= NULL;
	deviceKernelHandle	= NULL;
	passwords			= NULL;
	kernelIOQueue		= NULL;
}

OCLCore::~OCLCore(void)
{
	delete platformHandle;
	//delete program;
	system = NULL;
	device = NULL;
	if (passwords		  ) { delete passwords;			 }
	if (kernelDataBuffers ) { delete kernelDataBuffers;  }
	if (deviceKernelHandle) { delete deviceKernelHandle; }
	if (executionContext  ) { delete executionContext;   }
	if (settings		  ) { delete settings;			 }
	if (kernelIOQueue	  ) { delete kernelIOQueue;		 }

}

void OCLCore::Init() 
{
	//Test Password Generation:
	//TestPasswordBlockGeneration();
}

/*******************************************************
 *					Cracker Settings
 *******************************************************/
//Loaders

void OCLCore::LoadDefaultSettingsFile()
{
	string fileLoc = settings->GetDefaultFileLocation();

	try
	{
		//Password Generator test:
		//const int alphabetSize = 10;
		//char alphabet[alphabetSize + 1] = "0123456789";
		//CrackingMode mode = INCREMENTAL_FIXED;
		//int passwordLength = 5;
		//int hashOutputBytes = 20; //ie. 40-chars long.
		//int passwordBlockSize = 100;
		//int noThreads = 10; //TODO - Fix a bug in the partitioning of the data space.  int rounding error if not divisible by block size
		//passwords = new PasswordGenerator(alphabet, alphabetSize, mode, passwordLength, passwordBlockSize, noThreads);

		//Enable ability to load settings from file:
		/*
		settings->SetAlphabetSize(10);
		settings->SetAlphabet("0123456789");
		settings->SetMode(INCREMENTAL_FIXED);
		settings->SetGenerateRainbowTableFlag(true);
		settings->SetPasswordLength(5);
		settings->SetHashOutputBytes(20); //ie. 40-chars long.
		settings->SetPasswordBlockSize(100);
		settings->SetNoThreads(10); //TODO - Fix a bug in the partitioning of the data space.  int rounding error if not divisible by block size
		*/
		//Test settings serialization:
		//settings->Save();
		settings->Load(fileLoc);
	}
	catch (OCLSettings::SettingsSerialisationException &settingsException)
	{
		cout << settingsException.what() << endl << "Please check the filepath and try again." << endl;
	}
}

void OCLCore::LoadCustomSettingsFile(string fileLoc)
{
	try
	{
		settings->Load(fileLoc);
	}
	catch (OCLSettings::SettingsSerialisationException &settingsException)
	{
		cout << settingsException.what() << endl << "Please check the filepath and try again." << endl;
	}
}

void OCLCore::LoadCustomSettingsObject(OCLSettings& settingsIn)
{
	*settings = settingsIn;
}

//Persistance
void OCLCore::SaveToDefualtSettingsFile()
{
	string fileLoc = settings->GetDefaultFileLocation();

	try
	{
		settings->Save(fileLoc);
	}
	catch (OCLSettings::SettingsSerialisationException &settingsException)
	{
		cout << settingsException.what() << endl << "Please check the filepath and try again." << endl;
	}
}

void OCLCore::SaveSettingsFile(string fileLoc)
{
	try
	{
		settings->Save(fileLoc);
	}
	catch (OCLSettings::SettingsSerialisationException &settingsException)
	{
		cout << settingsException.what() << endl << "Please check the filepath and try again." << endl;
	}
}

void OCLCore::SaveCustomSettingsObject(OCLSettings& settingsIn)
{
	try
	{
		settingsIn.Save();
	}
	catch (OCLSettings::SettingsSerialisationException &settingsException)
	{
		cout << settingsException.what() << endl << "Please check the filepath and try again." << endl;
	}
}

void OCLCore::SaveCustomSettingsObjectToFile(OCLSettings& settingsIn, string fileLoc)
{
	try
	{
		settingsIn.Save(fileLoc);
	}
	catch (OCLSettings::SettingsSerialisationException &settingsException)
	{
		cout << settingsException.what() << endl << "Please check the filepath and try again." << endl;
	}
}

OCLSettings* OCLCore::GetSettingsObject()
{
	if (settings)
	{
		return settings;
	}
	else
	{
		throw InvalidSettingsException("There is no settings file defined that can be retrieved. Please load one before retrieving.");
	}
}

/*******************************************************
 *					OpenCL Platforms
 *******************************************************/

string OCLCore::GetAvailablePlatformInfo() const
{
	stringstream output;

	output	<< "Number of platforms: " <<  platformHandle->GetNumberOfPlatforms() << endl
			<<  endl
			<<  platformHandle->GetAllAvailablePlatforms() << endl;

	return output.str();
}

int OCLCore::GetNumberOfPlatforms() const
{
	return platformHandle->GetNumberOfPlatforms();
}

void OCLCore::DisplayAvailablePlatformInfo() const
{
	cout << "Number of platforms: " <<  platformHandle->GetNumberOfPlatforms() << endl;
	cout <<  endl;
	cout <<  platformHandle->GetAllAvailablePlatforms() << endl;
}

string OCLCore::GetPlatformDetails(int platformId) const
{
	return platformHandle->GetPlatformDeviceInfo(platformId);
}

void OCLCore::DisplayPlatformDetails(int platformId) const
{
	cout << platformHandle->GetPlatformDeviceInfo(platformId) << endl;
}

string OCLCore::GetPlatformDeviceSummary() const
{
	stringstream output;

	int noAvailablePlatforms = platformHandle->GetNumberOfPlatforms();
	int i;
	for (i = 0; i < noAvailablePlatforms; i++)
	{
		output << GetPlatformDetails(i);
	}

	return output.str();
}

void OCLCore::DisplayPlatformDeviceSummary() const
{
	int noAvailablePlatforms = platformHandle->GetNumberOfPlatforms();
	int i;
	for (i = 0; i < noAvailablePlatforms; i++)
	{
		DisplayPlatformDetails(i);
	}
}

string OCLCore::GetPlatformAllDeviceDetails(int platformId)	const
{
	stringstream output;
	output << platformHandle->GetAllDeviceInfoForPlatform(platformId);
	return output.str();
}

void OCLCore::DisplayPlatformAllDeviceDetails(int platformId) const
{
	cout << platformHandle->GetAllDeviceInfoForPlatform(platformId);
}

string OCLCore::GetPlatformDeviceDetails(int platformId, int deviceId) const
{
	stringstream output;
	output << platformHandle->GetDeviceInfoForPlatform(platformId, deviceId);
	return output.str();
}

void OCLCore::DisplayPlatformDeviceDetails(int platformId, int deviceId) const
{
	cout << platformHandle->GetDeviceInfoForPlatform(platformId, deviceId);
}

//Platform/Device Selection:
void OCLCore::SelectAvailablePlatform(int platformId)
{
	system = platformHandle->SelectPlatform(platformId);
}

void OCLCore::SelectAvailablePlatformDevice(int platformId, int deviceId)
{
	device = platformHandle->SelectDeviceForPlatform(platformId, deviceId);
}

string OCLCore::GetSelectedPlatform() const
{
	stringstream output;
	output << *system;
	return output.str();
}

void OCLCore::DisplaySelectedPlatform() const
{
	cout << *system;
}

string OCLCore::GetSelectedPlatformDevice() const
{
	stringstream output;
	output << *device;
	return output.str();
}

void OCLCore::DisplaySelectedPlatformDevice() const
{
	cout << *device;
}

//Load A Platform
void OCLCore::LoadSelectedPlatform()
{
	PlatformConversion(system);
}

void OCLCore::LoadSelectedPlatformDevice()
{
	if (system)
	{
		DeviceConversion(device);
	}
	else
	{
		//No platform selected.  Raise:
		throw LoadDeviceException("You need to select and Load a Platform before Loading a Device.");
	}
}

string OCLCore::GetLoadedPlatform() const
{
	stringstream output;
	output << &platforms[0] << endl;
	return output.str();
}

void OCLCore::DisplayLoadedPlatform() const
{
	cout << &platforms[0] << endl;
	
}

string OCLCore::GetLoadedPlatformDevice() const
{
	stringstream output;
	output << &devices[0] << endl;
	return output.str();
}

void OCLCore::DisplayLoadedPlatformDevice() const
{
	cout << &devices[0] << endl;
}

void OCLCore::SelectAndLoadPlatform(int platformId)
{
	SelectAvailablePlatform(platformId);
	LoadSelectedPlatform();
}

void OCLCore::SelectAndLoadPlatformDevice(int platformId, int deviceId)
{
	SelectAvailablePlatformDevice(platformId, deviceId);
	LoadSelectedPlatformDevice();
}

/*******************************************************
 *				Password Generator Info
 *******************************************************/

PasswordGenerator* OCLCore::GetPasswordGenerator()
{
	return passwords;
}

Password* OCLCore::GetPasswordPointer()
{
	return passwords->GetCurrentPasswordMarker();
}

int OCLCore::GetPasswordLength() const
{
	return settings->GetPasswordLength();
}

int OCLCore::GetPasswordBlockSize() const
{
	return settings->GetPasswordBlockSize();
}

int OCLCore::GetHashByteLength() const
{
	return settings->GetHashOutputBytes();
}

int OCLCore::GetHashOutputBlockSize() const
{
	return (settings->GetPasswordBlockSize() * settings->GetNoThreads() * settings->GetHashOutputBytes());
}

InfInt OCLCore::GetPasswordKeyspaceSize() const
{
	return passwords->GetTotalKeySpace();
}

InfInt OCLCore::GetNoRequiredExecutions() const
{
	return passwords->GetNoRequiredExecutions();
}

string OCLCore::GetPasswordKeyspaceStats() const
{
	stringstream output;

	if (passwords)
	{
		output << *passwords << endl;

		output << passwords->GetThreadSummary() << endl;
		output << passwords->GetThreadKeyspaceInfo() << endl;

		output << "Buffer Size: " << passwords->GetBufferSize() << endl;
		output << "Total Executions required to exhaust key space: " << passwords->GetNoRequiredExecutionsString() << endl;
	}
	else
	{
		throw PasswordGeneratorException("Password Generator has not been built, no information available yet.");
	}

	return output.str();
}

void OCLCore::DisplayPasswordKeyspaceStats() const
{
	if (passwords)
	{
		cout << endl;
		cout << passwords->GetThreadSummary() << endl;
		cout << "Next block starts at: " << *passwords << endl;
		cout << passwords->GetThreadKeyspaceInfo() << endl;

		cout << "Buffer Size: " << passwords->GetBufferSize() << endl;
		cout << "Total Executions required to exhaust key space: " << passwords->GetNoRequiredExecutionsString() << endl;
	}
	else
	{
		throw PasswordGeneratorException("Password Generator has not been built, no information available yet.");
	}
}

string OCLCore::GetPasswordBufferData() const
{
	return passwords->GetBufferContents();
}

void OCLCore::DisplayPasswordBufferData() const
{
	passwords->OutputBufferContents();
}

string OCLCore::GetPasswordBufferDataForThread(int threadId) const
{
	return passwords->GetBufferContentsForThread(threadId);
}

void OCLCore::DisplayPasswordBufferDataForThread(int threadId) const
{
	cout << passwords->GetBufferContentsForThread(threadId);
}

string OCLCore::GetPasswordAlphabet() const
{
	return settings->GetAlphabet();
}
int OCLCore::GetPasswordAlphabetSize() const
{
	return settings->GetAlphabetSize();
}

/*******************************************************
 *				Kernel Info
 *******************************************************/

string OCLCore::GetKernelSource() const
{
	return deviceKernelHandle->GetRawKernelSource();
}

void OCLCore::DisplayKernelSource() const
{
	cout << deviceKernelHandle->GetRawKernelSource();
}

/*******************************************************
 *				Cracker Settings
 *******************************************************/

void OCLCore::BuildContext()
{
	//Create a new context for the primary platform and selected devices:
	executionContext = new OCLContext(platforms[0], devices); //TODO - no default constructor
}

void OCLCore::SetupPasswordGenerator()
{
	if (passwords) { delete passwords; }
	passwords = new PasswordGenerator(settings);
	//Generate First Password block:
	passwords->LoadBlockThreaded();
}

void OCLCore::BuildBuffers(cl_uint* targetHash, cl_uchar* targetSalt, cl_bool* hashCollisionFound, int saltLen, cl_uint* iPadHash, cl_uint* oPadHash)
{
	if (settings)
	{
		int totalHashesPerBlock = settings->GetPasswordBlockSize() * settings->GetNoThreads();
		int hashLen = settings->GetHashOutputBytes();
		CreateOCLBuffers(targetHash, targetSalt, hashCollisionFound, hashLen, saltLen, (totalHashesPerBlock * hashLen), iPadHash, oPadHash);
	}
	else
	{
		//Settings not valid, raise:
		throw InvalidSettingsException("No settings file found.  Please check you have correctly loaded it.");
	}
}

void OCLCore::BuildKernel(string filePath, string kernelName)
{
	CreateDeviceKernelHandle(filePath, kernelName);

	//Create IO Queue (Depth 1 local and global work items):
	//(Works on first device only for now)
	int passLen = settings->GetPasswordLength();
	int totalHashesPerOutputBlock = settings->GetPasswordBlockSize() * settings->GetNoThreads();
	CreateKernelIOQueue(devices[0], (totalHashesPerOutputBlock), /*passLen,*/ LOCAL_WORKGROUP_DIM, GLOBAL_WORKGROUP_DIM);
}

void OCLCore::ExecuteKernel()
{
	//Dispatch Kernel (generate next password block async inline):
	kernelIOQueue->ExecuteKernel(passwords, kernelDataBuffers);
}

void OCLCore::RetrieveKernelOutput()
{
	if (settings)
	{
		int hashLen = settings->GetHashOutputBytes();
		int outputBufferSize = settings->GetPasswordBlockSize() * settings->GetNoThreads();
		
		//Create output buffer handle:
		const Buffer& outputBuffer = kernelDataBuffers->GetBlockOutput();
		if (settings->GetGenerateRainbowTableFlag())
		{
			kernelIOQueue->ExecuteKernelOutputRead(outputBuffer, (outputBufferSize * hashLen), settings->GetGenerateRainbowTableFlag());
		}
		else
		{
			kernelIOQueue->ExecuteKernelOutputRead(outputBuffer, settings->GetPasswordLength(), settings->GetGenerateRainbowTableFlag());
		}
	}
	else
	{
		//Settings not valid, raise:
		throw InvalidSettingsException("No settings file found.  Please check you have correctly loaded it.");
	}
}

void OCLCore::RetrieveKernelOutputInt()
{
	if (settings)
	{
		int hashLen = settings->GetHashOutputBytes() / 4;
		int outputBufferSize = settings->GetPasswordBlockSize() * settings->GetNoThreads();
		
		//Create output buffer handle:
		const Buffer& outputBuffer = kernelDataBuffers->GetBlockOutput();
		if (settings->GetGenerateRainbowTableFlag())
		{
			kernelIOQueue->ExecuteKernelOutputReadInt(outputBuffer, (outputBufferSize * hashLen), settings->GetGenerateRainbowTableFlag());
		}
		else
		{
			kernelIOQueue->ExecuteKernelOutputReadInt(outputBuffer, settings->GetPasswordLength(), settings->GetGenerateRainbowTableFlag());
		}
	}
	else
	{
		//Settings not valid, raise:
		throw InvalidSettingsException("No settings file found.  Please check you have correctly loaded it.");
	}
}

cl_bool OCLCore::KernelCollisionFound()
{
	//Create output buffer handle:
	const Buffer& collisionBuffer = kernelDataBuffers->GetCollisionFound();
	return kernelIOQueue->ExecuteKernelCollisionDetect(collisionBuffer);
}

void OCLCore::RetrieveKernelOutputToRainbowBlock(RainbowBlock* blockIn)
{
	if (settings)
	{
		int hashLen = settings->GetHashOutputBytes();
		int outputBufferSize = settings->GetPasswordBlockSize() * settings->GetNoThreads();
		
		//Create output buffer handle:
		const Buffer& outputBuffer = kernelDataBuffers->GetBlockOutput();
		kernelIOQueue->ExecuteKernelOutputReadToRainbow(outputBuffer, (outputBufferSize * hashLen), blockIn); //Modified to read back Int.
	}
	else
	{
		//Settings not valid, raise:
		throw InvalidSettingsException("No settings file found.  Please check you have correctly loaded it.");
	}
}

void OCLCore::RetrieveKernelOutputToRainbowBlockInt(RainbowBlock* blockIn)
{
	if (settings)
	{
		int hashLen = settings->GetHashOutputBytes() / 4; //Convert uchar to uint
		int outputBufferSize = settings->GetPasswordBlockSize() * settings->GetNoThreads();
		
		//Create output buffer handle:
		const Buffer& outputBuffer = kernelDataBuffers->GetBlockOutput();
		kernelIOQueue->ExecuteKernelOutputReadToRainbowInt(outputBuffer, (outputBufferSize * hashLen), blockIn); //Modified to read back Int.
	}
	else
	{
		//Settings not valid, raise:
		throw InvalidSettingsException("No settings file found.  Please check you have correctly loaded it.");
	}
}

/*******************************************************
 *		Internal Utility Methods / Wrappers
 *******************************************************/
//Hidden from the world (except our descendants....) ;)

void OCLCore::CreateOCLBuffers(cl_uint* hashPtr, cl_uchar* saltPtr, cl_bool* hashCollisionFound, int hashLen, int saltLen, int outputBufferSize, 
							   cl_uint* iPadHash, cl_uint* oPadHash)
{
	//Pre-computes iPad & oPad hash blocks, host-side in HMAC / PBKDF2 modes:
	bool isHmac = ((settings->GetAlgorithm() == HMAC_SHA1) || 
				   (settings->GetAlgorithm() == PBKDF2));

	kernelDataBuffers = new OCLBuffer(executionContext->GetContext(), 
									  (cl_uchar*)(passwords->GetBufferPointer()),
									  hashPtr, 
									  saltPtr, 
									  hashCollisionFound,
									  iPadHash,
									  oPadHash,
									  passwords->GetBufferSize(), 
									  saltLen, 
									  hashLen, 
									  outputBufferSize,
									  settings->GetPasswordLength(), 
									  settings->GetGenerateRainbowTableFlag(),
									  isHmac);
}

void OCLCore::CreateDeviceKernelHandle(string filePath, string kernelName)
{
	deviceKernelHandle = new OCLKernel(filePath, kernelName, settings->GetGenerateRainbowTableFlag(), settings->GetAlgorithm());

	//Prints kernel contents, if needed:
	//cout << deviceKernelHandle->GetRawKernelSource() << endl;

	deviceKernelHandle->BuildProgram(executionContext->GetContext(), devices, settings->GetPasswordLength());
	//Pass contents of call to CreateOCLBuffers method:
	deviceKernelHandle->BuildKernel(kernelDataBuffers);
}

void OCLCore::CreateKernelIOQueue(Device& device, int globalWorkgroupSize,
								 int globalWorkgroupDimensions, int localWorkgroupDimensions)
{
	//Build Kernel IO command queue:
	kernelIOQueue = new OCLCommandQueue(executionContext->GetContext(), device, deviceKernelHandle->GetKernel(), 
										globalWorkgroupSize,  settings->GetLocalWorkgroupSize(),
										globalWorkgroupDimensions,  localWorkgroupDimensions, 
										settings->GetNoKernels(), settings->GetHashOutputBytes());
}

void OCLCore::PlatformConversion(const OCLPlatform* platformWrapper)
{
	platforms.push_back(platformWrapper->GetPlatform());
}

void OCLCore::PlatformConversion(const VECTOR_CLASS<OCLPlatform*>& platformWrapper)
{
	int i;
	for (i = 0; (unsigned)i < platformWrapper.size(); i++)
	{
		platforms.push_back(platformWrapper[i]->GetPlatform());
	}
}

void OCLCore::DeviceConversion(const OCLDevice* deviceWrapper)
{
	devices.push_back(*deviceWrapper->GetDevice());
}

void OCLCore::DeviceConversion(const VECTOR_CLASS<OCLDevice*>& deviceWrapper)
{
	int i;
	for (i = 0; (unsigned)i < deviceWrapper.size(); i++)
	{
		devices.push_back(*deviceWrapper[i]->GetDevice());
	}
}