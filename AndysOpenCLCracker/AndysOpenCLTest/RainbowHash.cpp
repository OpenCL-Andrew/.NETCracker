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
#include "RainbowHash.h"


RainbowHash::RainbowHash(void)
{
	matchFound = false;
	plainText = "";
	hashValue = "";
}

RainbowHash::RainbowHash(string hashValue)
	: hashValue(hashValue)
{
	matchFound = false;
	plainText = "";
}

RainbowHash::RainbowHash(bool matchFound, string plainText, string hashValue)
	: matchFound(matchFound), plainText(plainText), hashValue(hashValue) { }

RainbowHash::~RainbowHash(void) { }

bool RainbowHash::GetMatchFound()
{
	return matchFound;
}

string RainbowHash::GetPlainText()
{
	return plainText;
}

string RainbowHash::GetHashValue()
{
	return hashValue;
}

void RainbowHash::SetMatchFound(bool matched)
{
	matchFound = matched; 
}

void RainbowHash::SetPlainText(string plainTextIn)
{
	plainText = plainTextIn;
}

void RainbowHash::SetHashValue(string hashIn)
{
	hashValue = hashIn;
}

//OStream overload:
ostream& operator<<(ostream& outStream, RainbowHash& rainbowHash)
{
	outStream << "Match Found: "	<< ((rainbowHash.matchFound) ? "True" : "False")	<< std::endl;

	if (rainbowHash.matchFound)
	{
		outStream  << "Plain Text: "		<< rainbowHash.plainText	<< std::endl
				   << "Matches Hash: "		<< rainbowHash.hashValue	<< std::endl;
	}

	return outStream;
}
