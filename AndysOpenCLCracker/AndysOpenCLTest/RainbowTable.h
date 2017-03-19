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
#ifndef RAINBOWTABLE_H_
#define RAINBOWTABLE_H_

#include "OClSettings.h"
#include "OClCore.h"

#include "RainbowBlock.h"
#include "RainbowHash.h"

#include <vector>

class RainbowTable
{
public:
	RainbowTable(void);
	~RainbowTable(void);

	void		InitFromSettings(OCLSettings* settingsIn);

	void		AddBlock		(RainbowBlock* block);
	void		RemoveBlock		(int index);

	InfInt		GetNoBlocks		();
	int			GetSizePerBlock	()						const;
	int			GetHashLen		()						const;
	int			GetPasswordLen	()						const;
	string		GetAlphabet		()						const;
	int			GetAlphabetSize ()						const;

	void		SetSizePerBlock	(int sizeIn);
	void		SetHashLen		(int sizeIn);
	void		SetPasswordLen	(int sizeIn);
	void		SetAlphabet		(string alphabetIn);
	void		SetAlphabetSize (int alphabetSizeIn);

	RainbowHash LookupHash		(unsigned int* hashIn); //RainbowHash is a wrapper for result type

private:
	std::vector<RainbowBlock*>	rainbowTable;
	int		currentNoBlocks;
	int		hashesPerBlock;
	int		hashLen;
	string	alphabet;
	int		alphabetSize;
	int		passwordLen;

};
#endif

