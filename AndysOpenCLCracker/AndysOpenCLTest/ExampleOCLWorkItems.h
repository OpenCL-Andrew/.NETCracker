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
#ifndef EXAMPLEOCLWORKITEMS_H_
#define EXAMPLEOCLWORKITEMS_H_

#define __NO_STD_VECTOR // Use cl::vector instead of STL version
#define CL_USE_DEPRECATED_OPENCL_1_1_APIS
#define __CL_ENABLE_EXCEPTIONS

//cl.hpp is the C++ version of the CL header file
#ifdef MAC
	#include <OpenCL/cl.hpp>
#else
	#include <CL/cl.hpp>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>

//To remove later:
#include <iterator>
#include <fstream>

#include "OCLErrorChecker.h"

using namespace std;
using namespace cl;

class ExampleOCLWorkItems
{
public:
	ExampleOCLWorkItems(void);
	~ExampleOCLWorkItems(void);

private:
	void Execute();
};

#endif