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
#include "FileHandle.h"

namespace OpenCLAppLib 
{
	FileHandle::FileHandle(void) { }
	FileHandle::~FileHandle(void) { }

	//Static util method to read the contents of a file into mem:
	std::string FileHandle::ReadFile(std::string fileLoc)
	{
		std::string fileContents;
		std::string line;
		std::ifstream file (fileLoc);

		if (!file) 
		{
			throw ("Error opening file " + fileLoc);
		}

		try
		{
			if (file.is_open())
			{
				while (getline(file,line))
				{
					//Read File:
					//cout << line << endl; //DEBUG only
					fileContents += line + "\n";
				}
				//Close File:
				file.close();
			}
		}
		catch (...)
		{
			std::cout << "An exception occurred whilst reading from the file: " + fileLoc << std::endl;
		}
	
		return fileContents;
	}

	const char ** FileHandle::ReadFile2(char fileLoc[])
	{
		//Kernel File reading:
		const int MAX_SOURCE_SIZE = 0x100000;

		FILE *fp;
		char *source_str;
		size_t source_size;

		//Load the source code:
		fp = fopen(fileLoc, "r");
		if (!fp) 
		{
			fprintf(stderr, "An exception occurred whilst loading kernel.\n");
		}

		source_str = new char[MAX_SOURCE_SIZE];
		source_size = fread(source_str, 1, MAX_SOURCE_SIZE, fp);
		fclose(fp);

		return(const char **)&source_str;
	}
}
