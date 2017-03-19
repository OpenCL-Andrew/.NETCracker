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
#include "RainbowBlock.h"

RainbowBlock::RainbowBlock(void) 
{ 
	blockMemPtr = NULL;
}

RainbowBlock::RainbowBlock(PasswordGenerator* passwordGen)
	: passwordGen(passwordGen) { }

RainbowBlock::RainbowBlock(string passwordMarker, int bufferSize, PasswordGenerator* passwordGen)
	: passwordGen(passwordGen)
{
	blockStart = passwordMarker;
	AllocateBlock(bufferSize);
}

RainbowBlock::~RainbowBlock(void) 
{ 
	DeAllocateBlock();
}

const string RainbowBlock::GetBlockStart() const
{
	return blockStart;
}

cl_uint* RainbowBlock::GetBlockHandle()
{
	return blockMemPtr;
}

/*
 * Sets the current block to the passwordMarker provided:
 */
void RainbowBlock::SetBlockStart(string passwordMarker)
{
	blockStart = passwordMarker;
}

void RainbowBlock::SetPasswordGenerator(PasswordGenerator* passwordGenIn)
{
	passwordGen = passwordGenIn;
}

void RainbowBlock::AllocateBlock(int bufferSize)
{
	blockMemPtr = (cl_uint*)malloc(sizeof(cl_uint) * bufferSize);
}

void RainbowBlock::DeAllocateBlock()
{
	if (blockMemPtr) 
	{ 
		free(blockMemPtr); 
		blockMemPtr = NULL;
	}
}

RainbowHash RainbowBlock::LookupHash(unsigned int* hashIn, int hashesPerBlock, int hashLen, 
									 int passwordLen, string& alphabet, int alphabetSize)
{
	RainbowHash result = RainbowHash();

	int len =  hashesPerBlock * passwordGen->GetNoThreads() * hashLen;
	cl_uint* blockPtr;
	//Iterate Each Hash:
	int i, c, o;
	for (i = 0; i < len; i += hashLen)
	{
		//Copy Pointer:
		blockPtr = blockMemPtr;
		//Iterate each char:
		c = 0;
		while((c < hashLen) && (blockPtr[(i + c)] == hashIn[c]))
		{
			if (c == (hashLen - 1)) //All characters have matched.
			{
				result.SetMatchFound(true);
				CrackingAlphabet* alphaCrackPtr = new CrackingAlphabet(alphabet, alphabetSize);
				Password psw = Password(alphaCrackPtr, &blockStart, passwordLen);

				//Calc value of hash match found:
				InfInt threadSpacePartition = (InfInt(i / hashLen) / hashesPerBlock) * passwordGen->GetThreadKeySpace();
				InfInt index = InfInt(i) / hashLen;
				InfInt remainder = (((i / hashLen) / hashesPerBlock) * hashesPerBlock);

				//Set Value of hash match found:
				psw -= (hashesPerBlock); //Block start is +1, so subtract
				if (index != remainder)
				{
					psw -= (((i / hashLen) / hashesPerBlock) * hashesPerBlock); //Subtract partition remainder
					psw += (index + threadSpacePartition); //Add index + partition
				}
				else
				{
					psw += threadSpacePartition; //Add partition only
				}
				result.SetPlainText(*psw.GetPassword());
				delete alphaCrackPtr;

				//Build PlainText Hash Hex:
				stringstream output;
				for (o = 0; o < hashLen; o++)
				{
					output << std::setfill ('0') << std::setw(sizeof(cl_uint)*2) 
						  << std::hex << (int)blockPtr[(i + o)];
				}
				result.SetHashValue(output.str());

				//Match found, break:
				return result;
			}
			else
			{
				c++;
			}
		}
	}
	//If no match, return false:
	return result;
}
