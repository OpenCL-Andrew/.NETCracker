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
#ifndef CONSOLEAPP_H_
#define CONSOLEAPP_H_

#include "OCLWrapper.h"
#include "base64.h"

#ifdef _DEBUG
#include <vld.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <sstream>
#include <exception>

using std::cout;
using std::cin;
using std::endl;

const int MAX_MENU_ITEMS = 10;
const int EXIT_VALUE = 10;

class ConsoleApp
{
public:
	ConsoleApp(void);
	~ConsoleApp(void);

	void DisplayWelcome();
	void DisplayMenu();
	void RunMenuOption(int option);
	int  GetInput();

	void DisplayPlatforms();
	void DisplayPlatformDetails(int platformId);
	void DisplayDevicesForPlatform();

	void LoadSettings();
	void LoadASPBase64(string encodedHash);
	void DisplaySettings();

	void DisplayKeySpaceSize();
	void DisplayKeyspaceStats();

	void SelectPlatform();
	void SelectDevice();
	void ExecuteProgram();
	void SearchRainbowTable(string hashToFind);

private:
	OCLWrapper* program;
	int selectedPlatformId;
	int selectedDeviceId;

};
#endif