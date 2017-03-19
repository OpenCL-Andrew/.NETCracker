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
#include "OCLSettings.h"


OCLSettings::OCLSettings(void)
{
	alphabetSize = 0;
	alphabet = "";
	mode = INCREMENTAL_FIXED;
	passwordLength = 0;
	hashOutputBytes = 0;
	passwordBlockSize = 0;
	noThreads = 0;
}

OCLSettings::OCLSettings(int alphabetSize, string alphabet, CrackingMode mode, 
				int pswLenBytes, int hashOutputBytes, int pswBlockSize, int noThreads)
	: alphabetSize(alphabetSize), 
	  alphabet(alphabet), 
	  mode(mode), 
	  passwordLength(pswLenBytes),
	  hashOutputBytes(hashOutputBytes), 
	  passwordBlockSize(pswBlockSize), 
	  noThreads(noThreads)
{ }

OCLSettings::OCLSettings(OCLSettings& settings)
{
	alphabetSize = settings.alphabetSize;
	alphabet = settings.alphabet;
	mode = settings.mode;
	passwordLength = settings.passwordLength;
	hashOutputBytes = settings.hashOutputBytes;
	passwordBlockSize = settings.passwordBlockSize;
	noThreads = settings.noThreads;
}

OCLSettings::~OCLSettings(void) { }


string OCLSettings::GetDefaultFileLocation() const
{
	return DEFAULT_SETTINGS_FILE_LOCATION;
}

int OCLSettings::GetAlphabetSize() const
{
	return alphabetSize;
}

string OCLSettings::GetAlphabet() const
{
	return alphabet;
}

CrackingMode OCLSettings::GetMode() const
{
	return mode;
}

HashAlgorithms OCLSettings::GetAlgorithm() const
{
	return algorithm;
}

bool OCLSettings::GetGenerateRainbowTableFlag() const
{
	return genRainbowTable;
}

int	OCLSettings::GetPasswordLength() const
{
	return passwordLength;
}

string OCLSettings::GetTargetHash() const
{
	return targetHash;
}

string OCLSettings::GetTargetSalt() const
{
	return targetSalt;
}

int	OCLSettings::GetHashOutputBytes() const
{
	return hashOutputBytes;
}

int	OCLSettings::GetPasswordBlockSize() const
{
	return passwordBlockSize;
}

int OCLSettings::GetNoThreads() const
{
	return noThreads;
}

int OCLSettings::GetLocalWorkgroupSize() const
{
	return localWorkgroupSize;
}

int OCLSettings::GetNoKernels() const
{
	return noKernels;
}

void OCLSettings::SetAlphabetSize(int alphabetSizeIn)
{
	alphabetSize = alphabetSizeIn;
}

void OCLSettings::SetAlphabet(string alphabetIn)
{
	alphabet = alphabetIn;
}

void OCLSettings::SetMode(CrackingMode modeIn)
{
	mode = modeIn;
}

void OCLSettings::SetAlgorithm(HashAlgorithms algoIn)
{
	algorithm = algoIn;
}

void OCLSettings::SetGenerateRainbowTableFlag(bool genRainbowTableIn)
{
	genRainbowTable = genRainbowTableIn;
}

void OCLSettings::SetPasswordLength(int passwordLenIn)
{
	passwordLength = passwordLenIn;
}

void OCLSettings::SetTargetHash(string hexIn)
{
	targetHash = hexIn;
}

void OCLSettings::SetTargetSalt(string hexIn)
{
	targetSalt = hexIn;
}

void OCLSettings::SetHashOutputBytes(int hashOutputBytesIn)
{
	hashOutputBytes = hashOutputBytesIn;
}

void OCLSettings::SetPasswordBlockSize(int passwordBlockSizeIn)
{
	passwordBlockSize = passwordBlockSizeIn;
}

void OCLSettings::SetNoThreads(int noThreadsIn)
{
	noThreads = noThreadsIn;
}

void OCLSettings::SetLocalWorkgroupSize(int noLocalWkgIn)
{
	localWorkgroupSize = noLocalWkgIn;
}

void OCLSettings::SetNoKernels(int noKernelsIn)
{
	noKernels = noKernelsIn;
}

//Serialization / Deserialization Encapsulation:
void OCLSettings::Load()
{
	try
	{
		//Create Settings Object:
		OCLSettings settings;
		//Load XML to settings Object:
		std::ifstream file(DEFAULT_SETTINGS_FILE_LOCATION);
		unsigned int modifier = boost::archive::no_header;
		boost::archive::xml_iarchive xmlFile(file, modifier);
		xmlFile >> boost::serialization::make_nvp("settings", settings);
		//Copy into this:
		*this = settings;
		initialiseAfterLoad();
	}
	catch (const exception& e)
	{
		string error = "An exception occured in OCLSettings::Load(), whilst loading the XML file: ";
		//std::cout << error << e.what() << endl;
		throw SettingsSerialisationException(error.append(e.what()));
	}
}

void OCLSettings::Load(string fileLocation)
{
	try
	{
		//Create Settings Object:
		OCLSettings settings;
		//Load XML to settings Object:
		std::ifstream file(fileLocation);
		unsigned int modifier = boost::archive::no_header;
		boost::archive::xml_iarchive xmlFile(file, modifier);
		xmlFile >> boost::serialization::make_nvp("settings", settings); 
		//Copy into this:
		*this = settings;
		initialiseAfterLoad();
	}
	catch (const exception& e)
	{
		string error = "An exception occured in OCLSettings::Load(string fileLocation), whilst loading the XML file: ";
		//std::cout << error << e.what() << endl;
		throw SettingsSerialisationException(error.append(e.what()));
	}
}

void OCLSettings::Save()
{
	try
	{
		std::ofstream file(DEFAULT_SETTINGS_FILE_LOCATION);
		unsigned int modifier = boost::archive::no_header;
		boost::archive::xml_oarchive xmlFile(file, modifier);
		xmlFile << boost::serialization::make_nvp("settings", this);
	}
	catch (const exception& e)
	{
		string error = "An exception occured in OCLSettings::Save(), whilst saving the XML file: ";
		//std::cout << error << e.what() << endl;
		throw SettingsSerialisationException(error.append(e.what()));
	}
}

void OCLSettings::Save(string fileLocation)
{
	try
	{
		std::ofstream file(fileLocation);
		unsigned int modifier = boost::archive::no_header;
		boost::archive::xml_oarchive xmlFile(file, modifier);
		xmlFile << boost::serialization::make_nvp("settings", this);
	}
	catch (const exception& e)
	{
		string error = "An exception occured in OCLSettings::Save(string fileLocation), whilst saving the XML file: ";
		//std::cout << error << e.what() << endl;
		throw SettingsSerialisationException(error.append(e.what()));
	}
}

OCLSettings& OCLSettings::operator=(const OCLSettings& rhs)
{
	alphabetSize		= rhs.alphabetSize;
	alphabet			= rhs.alphabet;
	mode				= rhs.mode;
	algorithm			= rhs.algorithm;
	genRainbowTable		= rhs.genRainbowTable;
	passwordLength		= rhs.passwordLength;
	targetHash			= rhs.targetHash;
	targetSalt			= rhs.targetSalt;
	hashOutputBytes		= rhs.hashOutputBytes;
	passwordBlockSize	= rhs.passwordBlockSize;
	noThreads			= rhs.noThreads;
	localWorkgroupSize   = rhs.localWorkgroupSize;
	noKernels			= rhs.noKernels;

	return *this;
}

//OStream overload:
ostream& operator<< (ostream& outStream, OCLSettings& settings)
{
	outStream	<< "Alphabet Length:\t\t"			<< settings.alphabetSize		<< endl
				<< "Alphabet:\t\t\t"				<< settings.alphabet			<< endl
				<< "Mode:\t\t\t\t"					<< settings.mode				<< endl
				<< "Algorithm:\t\t\t"				<< settings.algorithm			<< endl
				<< "Generate Rainbow Table:\t\t"	<< settings.genRainbowTable		<< endl
				<< "Password Length (Bytes):\t"		<< settings.passwordLength		<< endl
				<< "Target Hash:\t\t\t"				<< settings.targetHash			<< endl
				<< "TargetSalt:\t\t\t"				<< settings.targetSalt			<< endl
				<< "Hash Length (Bytes):\t\t"		<< settings.hashOutputBytes		<< endl
				<< "No. Passwords per Block:\t" 	<< settings.passwordBlockSize	<< endl
				<< "No. Threads:\t\t\t"				<< settings.noThreads			<< endl
				<< "Local Workgroup Size:\t\t"		<< settings.localWorkgroupSize	<< endl
				<< "No Kernels:\t\t\t"				<< settings.noKernels			<< endl;

	return outStream;
}