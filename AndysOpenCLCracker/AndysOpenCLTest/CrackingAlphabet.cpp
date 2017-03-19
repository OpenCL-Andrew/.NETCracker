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
#include "CrackingAlphabet.h"


CrackingAlphabet::CrackingAlphabet(void)
{
	throw("Error CrackingAlphabet::CrackingAlphabet(void) - Default constructor undefined.");
}

CrackingAlphabet::CrackingAlphabet(string alphabetIn, int alphabetSize)
	: alphabetSize(alphabetSize)
{
	//Now that field variables have been set, allocate buffer:
	alphabetBuffer = new string(alphabetIn);
}

CrackingAlphabet::~CrackingAlphabet(void)
{
	//Buffer deallocation:
	delete alphabetBuffer;
}

string* CrackingAlphabet::GetAlphabet() const
{
	return alphabetBuffer;
}

int CrackingAlphabet::GetAlphabetSize() const
{
	return alphabetSize;
}

InfInt CrackingAlphabet::GetKeySpace(int keyLen) const
{
	InfInt output = 1;

	int i;
	for (i = 0; i < keyLen; i++)
	{
		output *= alphabetSize;
	}

	return output;
}

int CrackingAlphabet::GetCharacterValue(char& character) const
{
	int i;
	for (i = 0; i < alphabetSize; i++)
	{
		if (character == alphabetBuffer->at(i))
		{
			return i;
		}
	}
	//If reached here, error:
	throw("Error CrackingAlphabet::GetCharacterValue(char& character) - Provided Char out of range");
}

char CrackingAlphabet::GetCharacter(string& character) const
{
	int i;
	for (i = 0; i < alphabetSize; i++)
	{
		if (character.at(0) == alphabetBuffer->at(i))
		{
			return alphabetBuffer->at(i);
		}
	}
	//If reached here, error:
	throw("Error CrackingAlphabet::GetCharacterValue(char& character) - Provided Char out of range");
}

char CrackingAlphabet::GetCharacter(char& character) const
{
	int i;
	for (i = 0; i < alphabetSize; i++)
	{
		if (character == alphabetBuffer->at(i))
		{
			return alphabetBuffer->at(i);
		}
	}
	//If reached here, error:
	throw("Error CrackingAlphabet::GetCharacterValue(char& character) - Provided Char out of range");
}

char CrackingAlphabet::GetCharacterIndex(const int& index) const
{
	return alphabetBuffer->at(index);
}

/*
 * Callers responsibility to free...
 */
string* CrackingAlphabet::GetInitialComboOfLen(int len)	const
{
	return new string(len, alphabetBuffer->at(0));
}

string CrackingAlphabet::ConvertToBase10String(string& wordIn) const
{
	InfInt base10 = 0;
	int count = 0;

	int i,j;
	for (i = wordIn.length() - 1; i >= 0; i--)
	{
		for (j = 0; j < alphabetSize; j++)
		{
			if (wordIn[i] == alphabetBuffer->at(j))
			{
				InfInt currentVal = j;
				base10 += (currentVal * Power(alphabetSize, count));
				count++;
			}
		}
	}
	return base10.toString();
}

string CrackingAlphabet::ConvertBase10ToAlphaBase(string& wordIn) const
{
	//Use imported LGPL lib to convert the input string to a 'BigInt' type:
	InfInt divisor = wordIn;
	return b10toNb(divisor);
}

string CrackingAlphabet::ConvertBase10ToAlphaBase(char* wordIn) const
{
	//Use imported LGPL lib to convert the input string to a 'BigInt' type:
	InfInt divisor = wordIn;
	return b10toNb(divisor);
}

string CrackingAlphabet::ConvertBase10ToAlphaBase(const int& wordIn) const
{
	//Use imported LGPL lib to convert the input string to a 'BigInt' type:
	InfInt divisor = wordIn;
	return b10toNb(divisor);
}

string CrackingAlphabet::ConvertBase10ToAlphaBase(long& wordIn) const
{
	//Use imported LGPL lib to convert the input string to a 'BigInt' type:
	InfInt divisor = wordIn;
	return b10toNb(divisor);
}

string CrackingAlphabet::ConvertBase10ToAlphaBase(long long& wordIn) const
{
	//Use imported LGPL lib to convert the input string to a 'BigInt' type:
	InfInt divisor = wordIn;
	return b10toNb(divisor);
}

string CrackingAlphabet::ConvertBase10ToAlphaBase(unsigned long long& wordIn) const
{
	//Use imported LGPL lib to convert the input string to a 'BigInt' type:
	InfInt divisor = wordIn;
	return b10toNb(divisor);
}

string CrackingAlphabet::ConvertBase10ToAlphaBase(InfInt& wordIn) const
{
	return b10toNb(wordIn);
}