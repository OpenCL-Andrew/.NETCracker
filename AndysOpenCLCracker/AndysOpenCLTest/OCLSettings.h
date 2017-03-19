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
#ifndef OCLSETTINGS_H_
#define OCLSETTINGS_H_

//Support Libs:
#include "OCLTypeEnums.h"

#include <string>
#include <fstream>
#include <iostream>
#include <exception>
#include <Windows.h>
//Include Boost libs for XML serialization:
#include <boost/archive/xml_iarchive.hpp>
#include <boost/archive/xml_oarchive.hpp>

using std::endl;
using std::string;
using std::ostream;
using std::exception;

//BOOST_CLASS_IMPLEMENTATION(OCLSettings, boost::serialization::object_serializable)

const string DEFAULT_SETTINGS_FILE_LOCATION = "./settings.xml";

class OCLSettings
{
public:
	OCLSettings(void);
	OCLSettings(int alphabetSize, string alphabet, CrackingMode mode, 
				int pswLenBytes, int hashOutputBytes, int pswBlockSize, int noThreads);
	OCLSettings(OCLSettings& settings);
	~OCLSettings(void);

	string			GetDefaultFileLocation()							const;
	int				GetAlphabetSize()									const;
	string			GetAlphabet()										const;
	CrackingMode	GetMode()											const;
	HashAlgorithms  GetAlgorithm()										const;
	bool			GetGenerateRainbowTableFlag()						const;
	int				GetPasswordLength()									const;
	string			GetTargetHash()										const;
	string			GetTargetSalt()										const;
	int				GetHashOutputBytes()								const;
	int				GetPasswordBlockSize()								const;
	int				GetNoThreads()										const;
	int				GetLocalWorkgroupSize()								const;
	int				GetNoKernels()										const;

	void			SetAlphabetSize				(int alphabetSizeIn);
	void			SetAlphabet					(string alphabetIn);
	void			SetMode						(CrackingMode modeIn);
	void			SetAlgorithm				(HashAlgorithms algoIn);
	void			SetGenerateRainbowTableFlag	(bool genRainbowTableIn);
	void			SetPasswordLength			(int passwordLenIn);
	void			SetTargetHash				(string hexIn);
	void			SetTargetSalt				(string hexIn);
	void			SetHashOutputBytes			(int hashOutputBytesIn);
	void			SetPasswordBlockSize		(int passwordBlockSizeIn);
	void			SetNoThreads				(int noThreadsIn);
	void			SetLocalWorkgroupSize		(int noLocalWkgIn);
	void			SetNoKernels				(int noKernelsIn);

	//Load / Save Settings:
	void			Load					();						//throw() //For forgetfulness only!
	void			Load					(string fileLocation);	//throw()
	void			Save					();						//throw()
	void			Save					(string fileLocation);	//throw()

	OCLSettings&    operator=(const OCLSettings& rhs);
	friend ostream& operator<<(ostream& outStream, OCLSettings& settings);

	//Custom ExceptionType:
	class SettingsSerialisationException : public std::runtime_error 
	{ 
		public: 
			SettingsSerialisationException(string m = "An exception occured in OCLSettings!") 
				:std::runtime_error(m) { }

			SettingsSerialisationException(OCLSettings *settingsObj, string m = "An exception occured in OCLSettings!") 
				:std::runtime_error(m) { /* Can add info on settingsObj as required */ }
	};

protected:
private:
	friend class boost::serialization::access;

	template<class Archive> 
	void serialize(Archive & ar, const unsigned int version) 
	{
		UNREFERENCED_PARAMETER(version);
        //ar & BOOST_SERIALIZATION_NVP(alphabetSize);
        ar & BOOST_SERIALIZATION_NVP(alphabet);
        ar & BOOST_SERIALIZATION_NVP(mode);
		ar & BOOST_SERIALIZATION_NVP(algorithm);
		ar & BOOST_SERIALIZATION_NVP(genRainbowTable);
		ar & BOOST_SERIALIZATION_NVP(passwordLength);
		ar & BOOST_SERIALIZATION_NVP(targetHash);
		ar & BOOST_SERIALIZATION_NVP(targetSalt);
		ar & BOOST_SERIALIZATION_NVP(hashOutputBytes);
		ar & BOOST_SERIALIZATION_NVP(passwordBlockSize);
		ar & BOOST_SERIALIZATION_NVP(noThreads);
		ar & BOOST_SERIALIZATION_NVP(localWorkgroupSize);
		ar & BOOST_SERIALIZATION_NVP(noKernels);
    }

	inline void initialiseAfterLoad()
	{
		alphabetSize = alphabet.length();
	}

	int				alphabetSize;
	string			alphabet;
	CrackingMode	mode;
	HashAlgorithms  algorithm;
	bool			genRainbowTable;
	int				passwordLength;
	string			targetHash;
	string			targetSalt;
	int				hashOutputBytes;
	int				passwordBlockSize;
	int				noThreads;
	int				localWorkgroupSize;
	int				noKernels;
};
#endif