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
#ifndef RAINBOWBLOCK_H_
#define RAINBOWBLOCK_H_

#define __NO_STD_VECTOR 
#define CL_USE_DEPRECATED_OPENCL_1_1_APIS
#define __CL_ENABLE_EXCEPTIONS

#ifdef MAC
	#include <OpenCL/cl.hpp>
#else
	#include <CL/cl.hpp>
#endif

#include "Password.h"
#include "CrackingAlphabet.h"
#include "PasswordGenerator.h"
#include "RainbowHash.h"

#include <iomanip> //std::hex
#include <bitset>  //bitset
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

using std::stringstream;

/*
 * This class represents a rainbow table storage for previously calculated
 * hashes. It stores only the block of calculated hashes and the plaintext
 * password that represents the start of that block.  In this way, we're 
 * able to save 25% memory storage at the expense of some extra compute
 * time, once a hash match has been verified.
 *
 * Unfortunatley, the reverse calculation to get the original plaintext password 
 * is over-complicated by the keyspace thread-partitioning.  This isn't an issue
 * so far as getting the correct plain text is concerened, but it's quite an 
 * expensive function.  (Though far far less expensive than working it out
 * brute-force again)!
 */
class RainbowBlock
{
	friend class RainbowTable;
public:
	RainbowBlock(void);
	RainbowBlock(PasswordGenerator* passwordGen);
	RainbowBlock(string passwordMarker, int bufferSize, PasswordGenerator* passwordGen);
	~RainbowBlock(void);

	const string	GetBlockStart			() const;
	void			SetBlockStart			(string passwordMarker);

	void			SetPasswordGenerator	(PasswordGenerator* passwordGenIn);

	cl_uint*		GetBlockHandle			();
	void			AllocateBlock			(int bufferSize);
	void			DeAllocateBlock			();

	RainbowHash		LookupHash				(unsigned int* hashIn, int hashesPerBlock, int hashLen,
											 int passwordLen, string& alphabet, int alphabetSize);

private:
	PasswordGenerator* passwordGen;
	string blockStart;
	cl_uint* blockMemPtr;
};
#endif