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
#include "ConsoleApp.h"

int main(int argc, char* argv[])
{
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	try
	{
		ConsoleApp console = ConsoleApp();
		console.DisplayWelcome();

		int selection = 0;

		do
		{
			try
			{
				console.DisplayMenu();
				selection = console.GetInput();
				console.RunMenuOption(selection);
			}
			catch (std::exception& e)
			{
				cout << "Exception! " << e.what() << endl;
			}
		}
		while (selection != EXIT_VALUE);
	}
	catch (std::exception& e)
	{
		cout << "Exception! " << e.what() << endl;
		exit(-1); //Error Code.
	}
}


ConsoleApp::ConsoleApp(void)
{
	program = new OCLWrapper();
}


ConsoleApp::~ConsoleApp(void)
{
	if (program) { delete program; }
}


/* Private Functions */

void ConsoleApp::DisplayWelcome()
{
	cout << "******************************************************"	<< endl;
	cout << "*\t\t .NETCracker Suite \t\t     *"						<< endl;
	cout << "******************************************************"	<< endl;
	cout << endl;
	cout << "Copyright (C) 2013 - 2014 Andrew Ruddick"					<< endl;
	cout << endl;
	cout << "BSc Computer Science (Security & Resilience) Dissertation" << endl;
	cout << "University Of Newcastle Upon Tyne"							<< endl;
	cout << endl << endl;
}

void ConsoleApp::DisplayMenu()
{
	cout << endl << endl;
	cout << "*****************************************" << endl;
	cout << "*\t Main Menu  \t\t        *"				<< endl;
	cout << "*****************************************" << endl;
	cout << endl << endl;
	cout << "Please Select a task:"						<< endl;
	cout << endl << endl;
	cout << "1 . Display OpenCL Platforms"				<< endl;
	cout << "2 . Display OpenCL Platform Details"		<< endl;
	cout << "3 . Display OpenCL Devices for Platform"	<< endl;
	cout << "4 . Display Target Keyspace size"			<< endl;
	cout << "5 . Load ASP.NET Base64 Hash"				<< endl;
	cout << "6 . Display Settings"						<< endl;
	cout << "7 . Re-Load Settings"						<< endl;
	cout << "8 . Execute Program"						<< endl;
	cout << "9 . Search Rainbow Table"					<< endl;
	cout << "10. Exit Program"							<< endl;
	cout << endl << endl;
}

void ConsoleApp::RunMenuOption(int option)
{
	int platformId;
	string encodedHash;
	string hashToFind;

	switch (option)
	{
		case 1:
			DisplayPlatforms();
			break;
		case 2:
			cout << "Enter Platform ID:" << endl;
			cin >> platformId;
			DisplayPlatformDetails(platformId);
			cin.ignore();
			break;
		case 3:
			cout << "Enter Platform ID:" << endl;
			cin >> platformId;
			program->GetCore()->DisplayPlatformAllDeviceDetails(platformId);
			cin.ignore();
			break;
		case 4:
			DisplayKeyspaceStats();
			break;
		case 5:
			cout << "Enter a Base64 Encoded ASP.NET Database Hash:" << endl;
			//cin.ignore();
			getline(cin, encodedHash);
			LoadASPBase64(encodedHash);
			break;
		case 6:
			cout << *program->GetCore()->GetSettingsObject() << endl;
			break;
		case 7:
			LoadSettings();
			break;
		case 8:
			ExecuteProgram();
			cin.ignore();
			break;
		case 9:
			cout << "Enter a HEX Encoded Hash:" << endl;
			getline(cin, hashToFind);
			SearchRainbowTable(hashToFind);
			break;
		case EXIT_VALUE:
			//delete program;
			//exit(0);
			break;
		default:
			cout << "Unrecognised Option Selected." << endl;
			break;
	}
}

int ConsoleApp::GetInput()
{
	string input;
	int x = 0;
	cout << ">> ";
	
	getline(cin, input);
	try
	{
		stringstream(input) >> x;
	}
	catch (...)
	{
		cout << "You have entered an invalid option." << endl;
	}

	if (!(x <= MAX_MENU_ITEMS))
	{
		cout << "You Must Enter a number between 0 and " << MAX_MENU_ITEMS << endl;
		cout << ">> ";
		cin >> x;
		cout << endl << endl;
	}

	return x;
}

void ConsoleApp::DisplayPlatforms()
{
	program->GetCore()->DisplayAvailablePlatformInfo();
}

void ConsoleApp::DisplayPlatformDetails(int platformId)
{
	program->GetCore()->DisplayPlatformDetails(platformId);
}

void ConsoleApp::DisplayDevicesForPlatform()
{
}

void ConsoleApp::LoadSettings()
{
	//Load Settings file:
	program->GetCore()->LoadDefaultSettingsFile();
	//Re-initialise Salt / Hash data in wrapper:
	program->RefreshWrapper();
}

void ConsoleApp::LoadASPBase64(string encodedHash)
{
	string targetHash;
	string targetSalt;
	string decoded = base64_decode(encodedHash);

	if (encodedHash.size() != 68)
	{
		cout << "The encoded hash entered is not in the correct format. " << endl;
		cout << endl;
		cout << "A valid .NET hash should be 68 characters in length when base64 encoded." << endl;
		cout << "The format should be: 0x00 prefix, followed by a 16 byte salt and then "  << endl;
		cout << "a 32 byte hash.  The value entered is of length: " << encodedHash.size()  << endl;
	}
	else
	{
		stringstream stream;

		//Omit first byte (leading 0x00 prefix)
		int i;
		for (i = 1; (unsigned int) i < decoded.size(); ++i) 
		{
			stream << std::setfill('0') << std::hex << std::setw(sizeof(unsigned char)*2) 
				   <<  static_cast<int>(static_cast<unsigned char>(decoded[i]));
		}
	
		//Reset decoded to hex:
		decoded = stream.str();
		//Extract salt and hash hex:
		targetSalt = decoded.substr(0, 32);
		targetHash = decoded.substr(32, decoded.size());

		cout << "Hash hex: " << decoded << endl;
		cout << "Salt hex: " << targetSalt << endl;
		cout << "Hash hex: " << targetHash << endl;
		cout << endl;
		cout << "Updating input settings." << endl;
		OCLSettings* settings = program->GetCore()->GetSettingsObject();
		settings->SetTargetSalt(targetSalt);
		settings->SetTargetHash(targetHash);
		settings->SetHashOutputBytes(32);
		settings->SetAlgorithm(PBKDF2);
		cout << "Serialising to disk..." << endl;
		settings->Save(settings->GetDefaultFileLocation());
		
		//Re-initialise Salt / Hash data in wrapper:
		program->RefreshWrapper();

		cout << "New settings: " << endl;
		cout << *settings << endl;
	}
}

void ConsoleApp::DisplaySettings()
{
}

void ConsoleApp::DisplayKeySpaceSize()
{
}

void ConsoleApp::DisplayKeyspaceStats()
{
	try
	{
		//Test if already initialised:
		program->GetCore()->DisplayPasswordKeyspaceStats();
	}
	catch (OCLCore::PasswordGeneratorException)
	{
		//Error if not.
		cout << "Initialising Password Generation Module..." << endl;
		//Initialise Program with default platform & device:
		program->GetCore()->SetupPasswordGenerator();
		program->GetCore()->DisplayPasswordKeyspaceStats();
	}
}

void ConsoleApp::SelectPlatform()
{
	cout << "Enter Platform ID:" << endl;
	cout << ">> ";
	cin >> selectedPlatformId;
}

void ConsoleApp::SelectDevice()
{
	cout << "Enter Device ID:" << endl;
	cout << ">> ";
	cin >> selectedDeviceId;
}

void ConsoleApp::ExecuteProgram()
{
	bool isRainbowMode = program->GetCore()->GetSettingsObject()->GetGenerateRainbowTableFlag();
	HashAlgorithms algo = program->GetCore()->GetSettingsObject()->GetAlgorithm();

	SelectPlatform();
	SelectDevice();
	cin.ignore();

	program->InitialiseOCLCore(selectedPlatformId, selectedDeviceId);

	if (isRainbowMode)
	{
		switch (algo)
		{
			case SHA1:
				program->BuildSHA1Rainbow();
				break;
			case HMAC_SHA1:
				program->BuildHMACSHA1Rainbow();
				break;
			case PBKDF2:
				program->BuildPBKDF2Rainbow();
				break;
			default:
				break;
		}
	}
	else
	{
		//Crack Mode:
		switch (algo)
		{
			case SHA1:
				program->ExecuteSHA1Crack();
				break;
			case HMAC_SHA1:
				program->ExecuteHMACSHA1Crack();
				break;
			case PBKDF2:
				program->ExecutePBKDF2Crack();
				break;
			default:
				break;
		}
	}
}

void ConsoleApp::SearchRainbowTable(string hashToFind)
{
	cout << program->LookupHashInRainbowTable(hashToFind) << endl;
}