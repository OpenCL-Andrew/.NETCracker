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
#include "OCLKernel.h"

OCLKernel::OCLKernel(void) { }

OCLKernel::OCLKernel(string& filePath, string& kernelName, 
					 bool isRainbowMode, HashAlgorithms algorithm)
	: filePath(filePath), kernelName(kernelName), isRainbowMode(isRainbowMode),
	algorithm(algorithm)
{
	LoadFile();
}

OCLKernel::~OCLKernel(void) 
{ 
	if (program) { delete program; }
	if (kernel)  { delete kernel;  }
}

string OCLKernel::GetRawKernelSource()
{
	return kernelSource;
}

Kernel* OCLKernel::GetKernel() const
{
	return kernel;
}

void OCLKernel::BuildProgram(Context& cxt, VECTOR_CLASS<Device> devices, int passwordLength)
{
	try
	{
		//Replace passwordLength Constant in src:
		ReplaceInSource("<<|psw|>>", std::to_string(passwordLength));
		//Build CL.hpp Program Source Object:
		Program::Sources source(1, make_pair(kernelSource.c_str(), kernelSource.length()+1));

		program = new Program(cxt, source);
		program->build(devices);
	}
	catch (std::exception& e)
	{
		std::cout << "Exception in OCLKernel::BuildProgram - Have you forgot to put <<|psw|>> in your kernel code? " << e.what() << std::endl;
		std::cout << program->getBuildInfo<CL_PROGRAM_BUILD_STATUS>(devices[0]) << std::endl;
		std::cout << program->getBuildInfo<CL_PROGRAM_BUILD_OPTIONS>(devices[0]) << std::endl;
		std::cout << program->getBuildInfo<CL_PROGRAM_BUILD_LOG>(devices[0]) << std::endl;
	}
	catch (...)
	{
		//TODO - THROW a custom exception back to caller. For now:
		std::cout << "Exception in OCLKernel::BuildProgram" << std::endl;
	}
}

void OCLKernel::BuildKernel(OCLBuffer* buf)
{
	cl_int errorCode = 0;
	try
	{
		kernel = new Kernel(*program, kernelName.c_str(), &errorCode);

		//Maybe want to throw this, rather than print it:
		checkErr(errorCode, "Exception in OCLKernel::BuildKernel()");

		//Set Kernel Arguments:
		
		//Output Buffer:
		errorCode = kernel->setArg(0, buf->GetBlockOutput());
		checkErr(errorCode, "Exception in OCLKernel::BuildKernel()");

		//Password Buffer:
		errorCode = kernel->setArg(1, buf->GetPasswordBuffer());
		checkErr(errorCode, "Exception in OCLKernel::BuildKernel()");

		//Password Length Buffer:
		errorCode = kernel->setArg(2, buf->GetPasswordSize());
		checkErr(errorCode, "Exception in OCLKernel::BuildKernel()");

		switch (algorithm)
		{
			case SHA1:
				if (!isRainbowMode)
				{
					//We're in Brute force crack-mode, so we'll need the target hash:
					errorCode = kernel->setArg(3, buf->GetTargetHash());
					checkErr(errorCode, "Exception in OCLKernel::BuildKernel()");

					//For efficency, also a 'hash collision found' flag:
					errorCode = kernel->setArg(4, buf->GetCollisionFound());
					checkErr(errorCode, "Exception in OCLKernel::BuildKernel()");
				}

				break;

			case HMAC_SHA1:
				//Rainbow Mode:
				//Salt Buffer:
				errorCode = kernel->setArg(3, buf->GetTargetSalt());
				checkErr(errorCode, "Exception in OCLKernel::BuildKernel()");

				//Salt Length Buffer:
				errorCode = kernel->setArg(4, buf->GetSaltSize());
				checkErr(errorCode, "Exception in OCLKernel::BuildKernel()");

				//HMAC iPad & oPad Pre-Computation buffers:
				errorCode = kernel->setArg(5, buf->GetIPadHash());
				checkErr(errorCode, "Exception in OCLKernel::BuildKernel() - iPadHash param");

				errorCode = kernel->setArg(6, buf->GetOPadHash());
				checkErr(errorCode, "Exception in OCLKernel::BuildKernel() - oPadHash param");

				//Crack Mode:
				if (!isRainbowMode)
				{
					//We're in Brute force crack-mode, so we'll need the target hash:
					errorCode = kernel->setArg(5, buf->GetTargetHash());
					checkErr(errorCode, "Exception in OCLKernel::BuildKernel() - target hash param");

					//For efficency, also a 'hash collision found' flag:
					errorCode = kernel->setArg(6, buf->GetCollisionFound());
					checkErr(errorCode, "Exception in OCLKernel::BuildKernel() - collision flag param");

					errorCode = kernel->setArg(7, buf->GetIPadHash());
					checkErr(errorCode, "Exception in OCLKernel::BuildKernel() - iPadHash param");

					errorCode = kernel->setArg(8, buf->GetOPadHash());
					checkErr(errorCode, "Exception in OCLKernel::BuildKernel() - oPadHash param");
				}
				break;
			case PBKDF2:
				//Rainbow Mode:
				//Salt Buffer:
				errorCode = kernel->setArg(3, buf->GetTargetSalt());
				checkErr(errorCode, "Exception in OCLKernel::BuildKernel()");

				//Salt Length Buffer:
				errorCode = kernel->setArg(4, buf->GetSaltSize());
				checkErr(errorCode, "Exception in OCLKernel::BuildKernel()");
				//Crack Mode:
				if (!isRainbowMode)
				{
					//We're in Brute force crack-mode, so we'll need the target hash:
					errorCode = kernel->setArg(5, buf->GetTargetHash());
					checkErr(errorCode, "Exception in OCLKernel::BuildKernel()");

					//For efficency, also a 'hash collision found' flag:
					errorCode = kernel->setArg(6, buf->GetCollisionFound());
					checkErr(errorCode, "Exception in OCLKernel::BuildKernel()");

					errorCode = kernel->setArg(7, buf->GetIPadHash());
					checkErr(errorCode, "Exception in OCLKernel::BuildKernel() - iPadHash param");

					errorCode = kernel->setArg(8, buf->GetOPadHash());
					checkErr(errorCode, "Exception in OCLKernel::BuildKernel() - oPadHash param");
				}

				break;
			default:
				//Do Nothing else.
				break;
		}
	}
	catch (std::exception& e)
	{
		std::cout << "Exception in OCLKernel::BuildKernel - " << e.what() << std::endl;
	}
	catch (...)
	{
		//TODO - THROW a custom exception back to caller. For now:
		std::cout << "Exception in OCLKernel::BuildKernel" << std::endl;
	}
}

void OCLKernel::LoadFile()
{
	FileHandle file;
	try
	{
		kernelSource = file.ReadFile(filePath);
	}
	catch (...)
	{
		std::cout << "There was an error reading from file: " << filePath << std::endl;
		kernelSource = "//No Src defined. There was an error reading from file.";
	}
}

/*
 * Provided to allow caller to override settings in the kernel file,
 * e.g. find and replace constants (# defines etc) prior to compilation.
 *
 * Used to set dynamic variables for compile-time fixed length arrays etc
 * (Dynamic allocation in OpenCL C is illegal, e.g. malloc()). 
 */
void OCLKernel::ReplaceInSource(string toReplace, string replaceWith)
{
	kernelSource.replace(kernelSource.find(toReplace), toReplace.length(), replaceWith);
}