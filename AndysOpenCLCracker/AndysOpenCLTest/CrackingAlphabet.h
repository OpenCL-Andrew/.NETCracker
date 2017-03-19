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
#ifndef CRACKINGALPHABET_H_
#define CRACKINGALPHABET_H_

//LGPL Library, obtained: http://code.google.com/p/infint/:
//LGPL Lib .h file. - Can only include once at top level, else it banjaxes 
//the compilation unit as a result of external linkage errors. :-/
#include "InfInt.h" 

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>

using std::ostream;
using std::string;
using std::endl;
using std::size_t;

class CrackingAlphabet
{
public:
	CrackingAlphabet(void);
	CrackingAlphabet(string alphabetIn, int alphabetSize);
	~CrackingAlphabet(void);

	string* GetAlphabet()					const;
	int		GetAlphabetSize()				const;
	InfInt	GetKeySpace(int keyLen)			const;
	string* GetInitialComboOfLen(int len)	const;

	//Base n to base 10 conversion:
	string ConvertToBase10String	(string& wordIn)				const;
	//Base 10 to base n conversion:
	string ConvertBase10ToAlphaBase	(string& wordIn)				const;
	string ConvertBase10ToAlphaBase	(char* wordIn)					const;
	string ConvertBase10ToAlphaBase	(const int& wordIn)				const;
	string ConvertBase10ToAlphaBase	(long& wordIn)					const;
	string ConvertBase10ToAlphaBase	(long long& wordIn)				const;
	string ConvertBase10ToAlphaBase	(unsigned long long& wordIn)	const;
	string ConvertBase10ToAlphaBase	(InfInt& wordIn)				const;

protected:
private:
	string* alphabetBuffer;
	int alphabetSize;

	int  GetCharacterValue(char& character)		const;
	char GetCharacter(string& character)		const;
	char GetCharacter(char& character)			const;
	char GetCharacterIndex(const int& index)	const;

	/*
		Wrapper for InfInt type to allow calculation
		of powers:
	 */
	inline InfInt Power(const InfInt& intVal, const int& pow) const
	{
		InfInt output = 1;

		int i;
		for (i = 1; i <= pow; i++)
		{
			output *= intVal;
		}
		return output;
	}

	inline string b10toNb(InfInt& divisor) const
	{
		string basen;
		InfInt remainder;

		do //use this construct... ;)
		{
			remainder = divisor % alphabetSize;
			divisor = divisor / alphabetSize;
		
			basen = GetCharacterIndex(remainder.toInt()) + basen;
		} 
		while (divisor > 1);

		if (divisor == 1)
		{
			basen = alphabetBuffer->at(1) + basen;
		}
	
		return basen;
	}
};
#endif