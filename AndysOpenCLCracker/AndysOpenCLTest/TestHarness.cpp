/*
 * This Program is an OpenCL accelerated password cracking application, designed
 * to target ASP.NET applications.
 *
 *     ___              __                     ____            __    ___      __  
 *    /   |  ____  ____/ /_______ _      __   / __ \__  ______/ /___/ (_)____/ /__
 *   / /| | / __ \/ __  / ___/ _ \ | /| / /  / /_/ / / / / __  / __  / / ___/ //_/
 *  / ___ |/ / / / /_/ / /  /  __/ |/ |/ /  / _, _/ /_/ / /_/ / /_/ / / /__/ ,<   
 * /_/  |_/_/ /_/\__,_/_/   \___/|__/|__/  /_/ |_|\__,_/\__,_/\__,_/_/\___/_/|_|  
 *
 * BSc Computer Science (Security & Resilience) Dissertation
 * University Of Newcastle Upon Tyne
 *
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
 * which is Copyright (C) 2013 Sercan Tutar, as released under the LGPL.  As
 * well as base64 - an unlicenced, free for use (and redist) class by René 
 * Nyffenegger.
 *
 * Additionally, the following C++ boost libraries have been used:
 *     boost.Thread
 *     boost.Serialization
 * 
 */

//#include "ExampleOCLWorkItems.h"
#include "OCLCore.h"
#include "OCLWrapper.h"

using std::cout;
using std::cin;
using std::endl;
/*
int main(int argc, char* argv[])
{

	cout << "******************************************************" << endl;
	cout << "*\t OpenCL Exectution Test Harness\t\t     *"			 << endl;
	cout << "******************************************************" << endl;
	cout << endl << endl;
*/
	//ExampleOCLWorkItems workItems = ExampleOCLWorkItems();
	/*
	OCLCore* core = new OCLCore();

	//List platforms:
	core->DisplayAvailablePlatformInfo();
	core->DisplayPlatformDeviceSummary(0);
	//Specific Device for platform:
	core->DisplayPlatformDeviceDetails(0,0);
	//All Devices for platform:
	cout << endl;
	cout << "All devices for platform :" << endl;
	cout << endl;
	core->DisplayPlatformAllDeviceDetails(0);

	//Select and Load Platform and Device:
	cout << "Platform Selection:" << endl;
	cout << endl;
	core->SelectAndLoadPlatform(0);
	core->SelectAndLoadPlatformDevice(0,0); //TODO - maybe store selected platform(?)

	//Display Selections:
	//core->DisplaySelectedPlatform();
	//core->DisplaySelectedPlatformDevice();

	//Load Platform / Device Context:
	//core->LoadSelectedPlatform();
	//core->LoadSelectedPlatformDevice();

	//Load Crack Settings:
	core->LoadDefaultSettingsFile();

	//Build OpenCL Context:
	core->BuildContext();
	//Build Password Generator:
	core->SetupPasswordGenerator();
	//Display Password Keyspace Stats:
	core->DisplayPasswordKeyspaceStats();

	//Setup Buffers:
	unsigned char hash[20] = {0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12};
	cl_uchar* hashPtr = &hash[0];

	unsigned char salt[20] = {0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12};
	cl_uchar* saltPtr = &salt[0];

	core->BuildBuffers(hashPtr, saltPtr, 20);

	//Setup Kernel:
	string filePath = "../AndysOpenCLTest/sha1Rainbow.cl";
	string kernelName = "sha1Rainbow";
	core->BuildKernel(filePath, kernelName);

	cout << endl;
	cout << "Password Buffer Data:" << endl;
	cout << endl;

	//core->DisplayPasswordBufferData();
	InfInt maxIterations = core->GetNoRequiredExecutions();
	InfInt i;
	for (i = 0; i < maxIterations; i++)
	{
		core->ExecuteKernel();
		//core->RetrieveKernelOutput();
		cout << "Completed Block " << i << endl;
	}
	core->RetrieveKernelOutput();
	*/


	//Test SHA1 Rainbow mode:
	/*
	try
	{
		OCLWrapper* sha1Rainbow = new OCLWrapper();

		unsigned int hash[5] = {0x2fd4e1c6, 0x7a2d28fc, 0xed849ee1, 0xbb76e739, 0x1b93eb12};
		cl_uint* hashPtr = &hash[0];

		unsigned char salt[20] = {0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12};
		cl_uchar* saltPtr = &salt[0];

		//sha1Rainbow->GetCore()->DisplayPlatformDeviceDetails(0,0);

		sha1Rainbow->BuildSHA1Rainbow(0, 0, hashPtr, saltPtr);
	
		cout << "00000 : " << sha1Rainbow->LookupHashInRainbowTable("6934105ad50010b814c933314b1da6841431bc8b") << endl;
		cout << "09991 : " << sha1Rainbow->LookupHashInRainbowTable("a4094ca55030ef56b5378785f4aa62e47dd34b76") << endl;
		cout << "12345 : " << sha1Rainbow->LookupHashInRainbowTable("8cb2237d0679ca88db6464eac60da96345513964") << endl;
		cout << "70000 : " << sha1Rainbow->LookupHashInRainbowTable("f41f840e61e4acaed373a21c8d286614698f90ce") << endl;
		cout << "72689 : " << sha1Rainbow->LookupHashInRainbowTable("6236567623771a4564e856648ee41e2f7dc91eab") << endl;
		cout << "99999 : " << sha1Rainbow->LookupHashInRainbowTable("a045b7efa463c6ed195c644163f4168952fbd34a") << endl;
	
		delete sha1Rainbow;
	}
	catch (std::exception& e)
	{
		cout << e.what() << endl;
	}
	*/
	
	//Test SHA1 Crack mode:
	/*
	try
	{
		OCLWrapper* sha1Crack = new OCLWrapper();
		
		//unsigned int hash[5] = {0x9d97a589, 0x2b0bf1b1, 0xaf208b53, 0xe6c9f359, 0x86a0b123}; //00001
		//unsigned int hash[5] = {0x87751f9c, 0xf671f642, 0x7438d819, 0x08261f6f, 0x2aa4ee61}; //27568
		//unsigned int hash[5] = {0xc65f99f8, 0xc5376ada, 0xdddc46d5, 0xcbcf5762, 0xf9e55eb7}; //HELLO
		//unsigned int hash[5] = {0x66983eff, 0xcf01837b, 0x51bfde69, 0x7a706e2d, 0xe9b6c350}; //GANGSTA 66983effcf01837b51bfde697a706e2de9b6c350
		//cl_uint* hashPtr = &hash[0];
		//unsigned char salt[20] = {0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12};
		//cl_uchar* saltPtr = &salt[0];
		

		string No_00001    = "9d97a5892b0bf1b1af208b53e6c9f35986a0b123";
		string No_27568    = "87751f9cf671f6427438d81908261f6f2aa4ee61";
		string HELLO       = "c65f99f8c5376adadddc46d5cbcf5762f9e55eb7";
		string GANGSTA     = "66983effcf01837b51bfde697a706e2de9b6c350";

		string exampleSalt = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";

		//sha1Crack->GetCore()->DisplayPlatformDeviceDetails(0,0);
		sha1Crack->ExecuteSHA1Crack(0, 0, GANGSTA, exampleSalt);
	
		delete sha1Crack;
	}
	catch (std::exception& e)
	{
		cout << e.what() << endl;
	}
	*/

	//Test HMAC-SHA1 Rainbow mode:
	/*
	try
	{
		OCLWrapper* hmacSha1Rainbow = new OCLWrapper();

		string GANGSTA     = "66983effcf01837b51bfde697a706e2de9b6c350"; //SHA1 only.  Salted: ce3141ccb10e6bcd67da9361d145ba12d574a9f1
		string exampleSalt = "6b65796b65796b65796b65796b65796b"; //keykeykeykeykeyk

		//sha1Crack->GetCore()->DisplayPlatformDeviceDetails(0,0);
		hmacSha1Rainbow->BuildHMACSHA1Rainbow(0, 0, GANGSTA, exampleSalt);
		//Salted hashes:
		cout << "00000 : " << hmacSha1Rainbow->LookupHashInRainbowTable("3678baf195ad9bdc69b84c2adeffa5a001e5b220") << endl;
		cout << "09991 : " << hmacSha1Rainbow->LookupHashInRainbowTable("1d61687a33ef9d8151337d0f0da2902773f4a8b3") << endl;
		cout << "12345 : " << hmacSha1Rainbow->LookupHashInRainbowTable("0e04ebfd06921a7d3ef182be445fd3c6d0ac586d") << endl;
		cout << "70000 : " << hmacSha1Rainbow->LookupHashInRainbowTable("d9d3bffb4d10fe7e6d7242cb7b04396798ffd3d4") << endl;
		cout << "72689 : " << hmacSha1Rainbow->LookupHashInRainbowTable("2fefeccbb7bc63faf00a54102fefa7fe935f9461") << endl;
		cout << "99999 : " << hmacSha1Rainbow->LookupHashInRainbowTable("23527981f3efbc0a2121efc091e27d7dfb635baf") << endl;
	
		delete hmacSha1Rainbow;
	}
	catch (std::exception& e)
	{
		cout << e.what() << endl;
	}
	*/
	/*
	//Test HMAC-SHA1 Crack mode:
	try
	{
		OCLWrapper* hmacSha1Crack = new OCLWrapper();

		string Salted_No_00000    = "3678baf195ad9bdc69b84c2adeffa5a001e5b220";
		string Salted_No_27568    = "169023d65a958dc990e22c3738c53e726a899738";
		string exampleSalt = "6b65796b65796b65796b65796b65796b"; //keykeykeykeykeyk

		//sha1Crack->GetCore()->DisplayPlatformDeviceDetails(0,0);
		hmacSha1Crack->ExecuteHMACSHA1Crack(0, 0, Salted_No_27568, exampleSalt);
	
		delete hmacSha1Crack;
	}
	catch (std::exception& e)
	{
		cout << e.what() << endl;
	}
	*/
	/*
	cout << endl;
	cout << "Exec Kernel:" << endl;
	cout << endl;

	core->ExecuteKernel();
	//core->RetrieveKernelOutput();

	cout << endl;
	cout << "Password Buffer Data:" << endl;
	cout << endl;

	core->DisplayPasswordBufferData();

	core->ExecuteKernel();
	*/

	//core->RetrieveKernelOutput();

	//core->Init();

	//Pause prog:
	//int x;

	//cin >> x;
	/*
	//Clean up heap object refs:
	try
	{
		delete core;
	}
	catch (...) 
	{ 
		//Ignore.
	}
	*/
//}
