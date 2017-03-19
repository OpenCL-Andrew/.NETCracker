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
#ifndef OCLKERNEL_H_
#define OCLKERNEL_H_

//Use cl::vector instead of STL vector:
#define __NO_STD_VECTOR 
//Enable Deprecated CL functionality:
#define CL_USE_DEPRECATED_OPENCL_1_1_APIS
//Enable CL-C++ Exception handling mechanism:
#define __CL_ENABLE_EXCEPTIONS

//cl.hpp is the C++ version of the CL header file:
#ifdef MAC
	#include <OpenCL/cl.hpp>
#else
	#include <CL/cl.hpp>
#endif

#include "FileHandle.h"
#include "OCLBuffer.h"
#include "OCLErrorChecker.h"
#include "OCLTypeEnums.h"

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <utility>

//std lib:
using std::ostream;
using std::string;
using std::endl;
using std::size_t;
using std::make_pair;

//cl lib:
using cl::Program;
using cl::Context;
using cl::Kernel;
using cl::Device;

//Misc lib:
using namespace OpenCLAppLib;

class OCLKernel
{
public:
	OCLKernel(void);
	OCLKernel(string& filePath, string& fileName, bool isRainbowMode, HashAlgorithms algorithm);
	~OCLKernel(void);

	string GetRawKernelSource();
	Kernel* GetKernel() const;

	void BuildProgram(Context& cxt, VECTOR_CLASS<Device> devices, int passwordLength);
	void BuildKernel(OCLBuffer* buf);

	//Program CompileKernelForContext(Context& cxt, Program* prog);

protected:
private:
	bool isRainbowMode;
	HashAlgorithms algorithm;
	string kernelName;
	string filePath;
	string kernelSource;

	Program* program;
	Kernel* kernel;

	void LoadFile();
	void ReplaceInSource(string toReplace, string replaceWith);
};
#endif;