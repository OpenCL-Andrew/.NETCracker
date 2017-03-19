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
#ifndef PASSWORDGENERATOR_H_
#define PASSWORDGENERATOR_H_

#include "OCLSettings.h"
#include "CrackingAlphabet.h"
#include "Password.h"

#include <boost/thread.hpp>

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <sstream>

using std::ostream;
using std::stringstream;
using std::atoi;
using std::endl;

using boost::thread;
using boost::bind;
using boost::thread_group;

/*
	This class is provided to facilitate the creation of passwords
	in a brute-force manner.

	TODO - May want to consider inherriting from an abstract base
	to allow multiple password cracking modes. i.e. Incremental 
	(brute-force), Dictionary based and combined.
 */
class PasswordGenerator
{
public:
	PasswordGenerator(void);
	PasswordGenerator(CrackingMode modeIn);
	PasswordGenerator(OCLSettings* settingsIn);
	PasswordGenerator(string alphabetIn, int alphabetSize, CrackingMode mode, 
					  int passwordLength, int passwordBlockSize, int noThreads);
	~PasswordGenerator(void);

	int			GetCurrentPasswordLength()					const;
	int			GetNoThreads()								const;
	string		GetTotalKeySpaceString()					const;
	InfInt		GetTotalKeySpace()							const;
	string		GetThreadKeySpace()							const;
	bool		GetIsEvenDivisionByBlock()					const;
	string		GetThreadSummary()							const;
	string		GetThreadKeyspaceInfo()						const;
	int			GetBufferSize()								const;
	string		GetBufferContents()							const;
	char*		GetBufferPointer()							const;
	string		GetBufferContentsForThread(int threadId)	const;
	string		GetCurrentBlockStart()						const;
	string		GetNoRequiredExecutionsString()				const;
	InfInt		GetNoRequiredExecutions()					const;
	Password*	GetCurrentPasswordMarker()					const;

	void		OutputBufferContents()						const;

	void		LoadBlockThreaded();
	void		LoadBlockSequential();

	void		ProgressReport();
	void		SaveProgress();
	void		ResumePrevious();

	friend ostream& operator<<(ostream& outStream, const PasswordGenerator& platform);
protected:
private:
	CrackingAlphabet* alphabet;
	CrackingMode currentMode;

	//If mode = INCREMENTAL_FIXED, all combinations of a single fixed size attempted:
	int		maxPasswordLength;

	//If mode = INCREMENTAL_FULL, all combinations of length 0 -> maxLen will be attempted:
	int		currentPasswordLength; //AKA - singleBlockInputLength
	//int		hashOutputByteLength;//AKA - singleBlockOutputLength

	int		blockSize; //Number of psw in a block
	int		noExecutionThreads;

	//Informational Storage:
	InfInt	maxKeyLen;
	InfInt	threadSpace;
	InfInt	noRequiredExecutions;
	bool	evenDivision;

	char*	kernelInputBuffer;
	int		kernelInputBufferSize;
	Password* currentPasswordMarker;
	string*	defaultPassword;

	//Private Util Methods:
	void init();

	//Password Methods:
	void	GenerateBlockSection(int startIndex);

	__declspec(deprecated("PasswordGenerator::BruteForce() is deprecated.")) 
	void	BruteForce(int index);
};
#endif