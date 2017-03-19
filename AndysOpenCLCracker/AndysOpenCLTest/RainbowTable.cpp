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
#include "RainbowTable.h"


RainbowTable::RainbowTable(void) 
{ 
	currentNoBlocks = 0;
	hashesPerBlock = 0;
}
//RainbowTable::RainbowTable(void) { }

RainbowTable::~RainbowTable(void) 
{ 
	//Must go through and free all mem here.

}

void RainbowTable::InitFromSettings(OCLSettings* settingsIn)
{
	if (settingsIn)
	{
		hashesPerBlock = settingsIn->GetPasswordBlockSize();
		hashLen = settingsIn->GetHashOutputBytes();
		alphabet = settingsIn->GetAlphabet();
		alphabetSize = settingsIn->GetAlphabetSize();
		passwordLen = settingsIn->GetPasswordLength();
	}
	else
	{
		//throw
		throw OCLCore::InvalidSettingsException("The settings file provided is invalid.  Please check you have provided all required fields and try again.");
	}
}

void RainbowTable::AddBlock(RainbowBlock* block)
{
	rainbowTable.push_back(block);
	currentNoBlocks++;
}
 
void RainbowTable::RemoveBlock(int index)
{
	rainbowTable.erase(rainbowTable.begin() + index);
}

InfInt RainbowTable::GetNoBlocks()
{
	return currentNoBlocks;
}

int RainbowTable::GetSizePerBlock() const
{
	return hashesPerBlock;
}

void RainbowTable::SetSizePerBlock(int sizeIn)
{
	hashesPerBlock = sizeIn;
}

int RainbowTable::GetHashLen() const
{
	return hashLen;
}

void RainbowTable::SetHashLen(int sizeIn)
{
	hashLen = sizeIn;
}
string RainbowTable::GetAlphabet() const
{
	return alphabet;
}

void RainbowTable::SetAlphabet(string alphabetIn)
{
	alphabet = alphabetIn;
}

int RainbowTable::GetPasswordLen() const
{
	return passwordLen;
}

void RainbowTable::SetPasswordLen(int sizeIn)
{
	passwordLen = sizeIn;
}

int RainbowTable::GetAlphabetSize() const
{
	return alphabetSize;
}

void RainbowTable::SetAlphabetSize(int alphabetSizeIn)
{
	alphabetSize = alphabetSizeIn;
}

RainbowHash RainbowTable::LookupHash(unsigned int* hashIn)
{
	RainbowHash result = RainbowHash();

	int i;
	for (i = 0; i < currentNoBlocks; i++)
	{
		result = rainbowTable.at(i)->LookupHash(hashIn, hashesPerBlock, (hashLen / 4), //Div by 4 converts uchar to int
												passwordLen, alphabet, alphabetSize);
		if (result.GetMatchFound())
		{
			//Match found:
			return result;
		}
	}
	//No match found:
	return result;
}

