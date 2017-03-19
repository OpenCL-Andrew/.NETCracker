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
#include "PasswordGenerator.h"

PasswordGenerator::PasswordGenerator(void)
{
	throw("Error PasswordGenerator::PasswordGenerator(void) - Default constructor undefined.");
}

PasswordGenerator::PasswordGenerator(OCLSettings* settings)
{
	//Store General Settings:
	currentMode			=	settings->GetMode();
	maxPasswordLength	=	settings->GetPasswordLength();
	blockSize			=	settings->GetPasswordBlockSize();
	noExecutionThreads	=	settings->GetNoThreads();

	//Store alphabet:
	alphabet = new CrackingAlphabet(settings->GetAlphabet(), settings->GetAlphabetSize());
	defaultPassword = alphabet->GetInitialComboOfLen(maxPasswordLength);
	//currentPasswordMarker = new Password(alphabet, alphabet->GetInitialComboOfLen(passwordLength), passwordLength);
	currentPasswordMarker = new Password(alphabet, defaultPassword, maxPasswordLength);

	//Build Initial Password Buffer:
	kernelInputBufferSize = (maxPasswordLength * blockSize * noExecutionThreads) + 1;
	kernelInputBuffer = new char[kernelInputBufferSize];
	//Set NULL terminator:
	kernelInputBuffer[kernelInputBufferSize - 1] = '\0';

	//Set Object Informational Storage:
	init();
}

PasswordGenerator::PasswordGenerator(string alphabetIn,		int alphabetSize,		  CrackingMode mode, 
										int passwordLength, int passwordBlockSize,	  int noThreads)
	: currentMode(mode), 
	  maxPasswordLength(passwordLength), 
	  blockSize(passwordBlockSize),
	  noExecutionThreads(noThreads)
{
	//Store alphabet:
	alphabet = new CrackingAlphabet(alphabetIn, alphabetSize);
	defaultPassword = alphabet->GetInitialComboOfLen(passwordLength);
	//currentPasswordMarker = new Password(alphabet, alphabet->GetInitialComboOfLen(passwordLength), passwordLength);
	currentPasswordMarker = new Password(alphabet, defaultPassword, passwordLength);

	//Build Initial Password Buffer:
	kernelInputBufferSize = (passwordLength * passwordBlockSize * noThreads) + 1;
	kernelInputBuffer = new char[kernelInputBufferSize];
	//Set NULL terminator:
	kernelInputBuffer[kernelInputBufferSize - 1] = '\0';

	//Set Object Informational Storage:
	init();
}

PasswordGenerator::~PasswordGenerator(void)
{
	delete		alphabet;
	delete []	kernelInputBuffer;
	delete		defaultPassword;

	if (currentPasswordMarker)
	{
		delete		currentPasswordMarker;
	}
}

//Informational Utility Methods:

void PasswordGenerator::init()
{
	maxKeyLen		= alphabet->GetKeySpace(maxPasswordLength);
	threadSpace		= maxKeyLen / noExecutionThreads;
	evenDivision	= (maxKeyLen % threadSpace) == 1;
	//Total Number of executions required to scan whole keyspace:
	noRequiredExecutions = threadSpace / InfInt(blockSize) + 1;
}

int PasswordGenerator::GetCurrentPasswordLength() const
{
	return currentPasswordLength;
}

int PasswordGenerator::GetNoThreads() const
{
	return noExecutionThreads;
}

//Thread keyspace Partinitiong methods

string	PasswordGenerator::GetNoRequiredExecutionsString() const
{
	return noRequiredExecutions.toString();
}

InfInt	PasswordGenerator::GetNoRequiredExecutions() const
{
	return noRequiredExecutions;
}

Password* PasswordGenerator::GetCurrentPasswordMarker() const
{
	return currentPasswordMarker;
}

/*
	Returns the total keyspace as a string (as it can
	be a very very very large number!)
 */
string PasswordGenerator::GetTotalKeySpaceString() const
{
	return maxKeyLen.toString();
}

InfInt PasswordGenerator::GetTotalKeySpace() const
{
	return maxKeyLen;
}

/*
	Gets the total keyspace assigned to each thread.
	This is equivalent to:
	
	(total keyspace / no. threads) = thread key space
 */
string PasswordGenerator::GetThreadKeySpace() const
{
	return threadSpace.toString();
}

/*
	Returns bool.  Does the size of a block divide evenly
	by the number of threads?  If not, consider altering
	the parameters to ensure even distribution accross
	kernel work groups.  It's not a problem if you don't
	however - it just may not be optimal.
*/
bool PasswordGenerator::GetIsEvenDivisionByBlock() const
{
	return evenDivision;
}

string PasswordGenerator::GetThreadSummary() const
{
	stringstream output;

	output	<< "Max Key Space ="	<< maxKeyLen << endl 
			<< "Thread Space ="		<< threadSpace << endl
			<< "Remainder? ="		<< evenDivision << endl
			<< endl;

	return output.str();
}

/*
	Method returns a summary of they way that the keyspace has been
	split down for each thread.
 */
string PasswordGenerator::GetThreadKeyspaceInfo() const
{
	stringstream output;

	int i;
	for (i = 0; i < noExecutionThreads; i++)
	{
		//output << "=======================================" << std::endl;
		//output << " Outputting Thread ID " << i				<< std::endl;
		//output << "=======================================" << std::endl;

		InfInt index = InfInt(i);
		//If keyspace unevenly divides by the number of threads, we need to add + 1 to the final block:
		if ((i == (noExecutionThreads -1)) && (evenDivision))
		{
			InfInt currentStart = (index * threadSpace);
			InfInt currentEnd = ((index+1) * threadSpace);
			output << "Thread " << index << " will operate on range: " << (index * threadSpace) << " - " << ((index+1) * threadSpace) << endl;
			output << "Which in alphabet base is: \t" << alphabet->ConvertBase10ToAlphaBase(currentStart)
				   << " - " << alphabet->ConvertBase10ToAlphaBase(currentEnd) << endl;
		}
		//If is first block:
		else if (i == 0)
		{
			InfInt currentStart = 0;
			InfInt currentEnd =   ((index+1) * threadSpace - 1);
			output << "Thread " << index << " will operate on range: " << (index * threadSpace) << " - " << ((index+1) * threadSpace - 1) << endl;
			output << "Which in alphabet base is: \t" << string(maxPasswordLength, alphabet->GetAlphabet()->at(0))
				   << " - " << alphabet->ConvertBase10ToAlphaBase(currentEnd) << endl;
		}
		else
		{
			InfInt currentStart = (index * threadSpace);
			InfInt currentEnd =   ((index+1) * threadSpace - 1);
			
			output << "Thread " << index << " will operate on range: " << (index * threadSpace) << " - " << ((index+1) * threadSpace - 1) << endl;
			output << "Which in alphabet base is: \t" << alphabet->ConvertBase10ToAlphaBase(currentStart)
				   << " - " << alphabet->ConvertBase10ToAlphaBase(currentEnd) << endl;
		}
	}

	return output.str();
}

int	PasswordGenerator::GetBufferSize() const
{
	return kernelInputBufferSize;
}

string PasswordGenerator::GetCurrentBlockStart() const
{
	return *currentPasswordMarker->GetPassword();
}

/*
	Returns the complete contents of the password buffer as 
	a string.  WARNING: if you have not yet initialised the
	buffer, this will return uninit memory to the caller.
	If the buffer is HUGE, this method will take a long time!
 */
string PasswordGenerator::GetBufferContents() const
{
	stringstream output;

	int k;
	for (k = 0; k < kernelInputBufferSize; k++)
	{
		output << kernelInputBuffer[k];
	}
	output << endl;

	return output.str();
}

/*
	Returns a raw pointer to the buffer.

	WARNING! A dirty read may occur if you are buffering data
	whilst reading!
 */
char* PasswordGenerator::GetBufferPointer() const
{
	return kernelInputBuffer;
}

void PasswordGenerator::OutputBufferContents() const
{
	int k;
	for (k = 0; k < kernelInputBufferSize; k++)
	{
		std::cout << kernelInputBuffer[k];
	}
	std::cout << endl;
}

/*
	Returns the contents of an individual threads space within the 
	global password buffer.
 */
string PasswordGenerator::GetBufferContentsForThread(int threadId) const
{
	stringstream output;

	int bufferStartIndex = threadId * blockSize;

	int i;
	for (i = bufferStartIndex; i < (bufferStartIndex + blockSize); i++)
	{
		int j;
		for (j = 0; j < maxPasswordLength; j++)
		{
			output << kernelInputBuffer[(maxPasswordLength * i) + j];
		}
	}
	output << endl;

	return output.str();
}

//Main Block Loading Methods:

/*
	Spanwns n-threads to build the password buffer.
	Each thread is assigned a portion of the keyspace and 
	the buffer, so data construct level synchronisation
	is not required as it should not be possible for race
	conditions to occur.
 */
void PasswordGenerator::LoadBlockThreaded()
{
	thread_group group;

	int i;
	for (i = 0; i < noExecutionThreads; i++)
	{
		group.create_thread(bind(&PasswordGenerator::GenerateBlockSection, this, i));
	}

	//Unleash all hell. >:-D
	group.join_all();

	//Update block start value:
	*currentPasswordMarker += blockSize;
}

/*
	Method as above, but performs the same functionality in
	a the single main thread of execution.
 */
void PasswordGenerator::LoadBlockSequential()
{
	int i;
	for (i = 0; i < noExecutionThreads; i++)
	{
		GenerateBlockSection(i);
	}
	*currentPasswordMarker += blockSize;// ->SetPassword(*psw.GetPassword());
}

/*
	Multi-threaded Execution.

	This method is designed to be ran in an n-threaded fashion to allow
	the multiple partitioning of the data construct into multiple workloads.

	The primary motivators for this multi-threaded creation:
	
	1) The potential expansion of this application to a grid-computing scenario.  
	If we can add remote OpenCL platforms to the intial connection stage of this
	application, the potential is to have one machine doing nothing but 
	allocating password buffers on all network devices (assuming network
	latency can cope - we are afterall just xfering a few k of raw text at 
	the most), then allocating these blocks to worker machines.  Esentially 
	having a command and control type scenario over multiple devices.
	
	2) If we're running on a machine with a particularly fast GPU setup 
	(e.g. SLI / Quad-SLI or better even), we don't want the bottle neck in the 
	creation of hashes to be directly bounded by single-threaded execution of
	this class on a single CPU core.  Rather than creating a whole new OpenCL
	execution run to do the password buffer creation (which would be overkill),
	this n-threaded version should suffice - particularly as it's optimisible 
	on a per-machine basis.

 */
void PasswordGenerator::GenerateBlockSection(int threadId)
{
	try
	{
		InfInt currentThreadPswRangeStart = (InfInt(threadId) * threadSpace);

		int bufferStartIndex = threadId * blockSize;
		//Iterate all password combos within the current block:
		Password psw = Password(alphabet, currentPasswordMarker->GetPassword(), maxPasswordLength);
		//Set current block start:
		psw += (currentThreadPswRangeStart);

		int i;
		for (i = bufferStartIndex; i < (bufferStartIndex + blockSize); i++)
		{
			//Set buffer index: (startIndex + i) = psw;
			int j;
			for (j = 0; j < maxPasswordLength; j++)
			{
				kernelInputBuffer[(maxPasswordLength * i) + j] = psw[j];
			}
			//std::cout << (maxPasswordLength * i) + j << endl;
			//Increment source password combination:
			++psw;
		}
		//std::cout << "Thread " << threadId << " completed." << std::endl;
	}
	catch (const std::bad_alloc& e)
	{
		std::cout << e.what() << endl;
	}
	catch (const std::exception& e)
	{
		std::cout << "Exception in PasswordGenerator::GenerateBlockSection!" << e.what() << endl;
	}
	catch (...)
	{
		std::cout << "Exception in PasswordGenerator::GenerateBlockSection!" << endl;
	}
}

/*
	Single threaded, one-hit recursive method (no good for generating 
	blocks to pass to GPU).	Only reason for inclusion was in the early
	stages of design of the multi-threaded algorithm used above.

	The below has a high depth of recursion, thus is not suitable for
	large keyspaces as it's likely to result in a stack overflow.
 */
void PasswordGenerator::BruteForce(int index)
{
	int i;
	for (i = 0; i < (alphabet->GetAlphabetSize()); i++)
	{
		currentPasswordMarker->GetPassword()->at(index) = alphabet->GetAlphabet()->at(i);

		if (index == (maxPasswordLength - 1))
		{
			std::cout << *currentPasswordMarker->GetPassword() << std::endl;
		}
		else
		{
			BruteForce(index + 1);
		}
	}
}

//OStream overload:
/*
	Default ostream output prints the current buffer contents.  Careful if 
	printing data whilst program is executing - you may get a dirty read
	(and no, not like 50 shades....)  ;)
 */
ostream& operator<< (ostream& outStream, const PasswordGenerator& platform)
{
	outStream << platform.GetCurrentBlockStart() << endl;

	return outStream;
}
