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
#include "Password.h"


Password::Password(void)
{
	password = new string();
}

Password::Password(CrackingAlphabet* passwordAlphabet, string* passwordIn, int passwordLength)
	: passwordLength(passwordLength), alphabet(passwordAlphabet) 
{ 
	//password = passwordIn;
	//Deep copy password string:
	password = new string(*passwordIn);
}

Password::Password(const Password& pswIn)
{
	//Deep copy password string:
	password = new string(*(pswIn.GetPassword()));
	//Reference copy is fine for other fields:
	alphabet = pswIn.GetCrackingAlphabet();
	passwordLength = pswIn.GetPasswordLength();
}

Password::~Password(void)
{
	//Delete Password buffer:
	if (password) { delete password; }
}

//Getters:
string* Password::GetPassword() const
{
	return password;
}

CrackingAlphabet* Password::GetCrackingAlphabet() const
{
	return alphabet;
}

int Password::GetPasswordLength() const
{
	return passwordLength;
}

string* Password::GetInitialPasswordCombo() const
{
	string* initialCombination = new string();

	int i;
	for (i = 0; i < passwordLength; i++)
	{
		initialCombination->at(i) = alphabet->GetAlphabet()->at(0);
	}

	return initialCombination;
}

int Password::GetPasswordBase() const
{
	return alphabet->GetAlphabetSize();
}

//Setters:

void Password::SetPassword(string& passwordIn)
{
	try
	{
		if (password) { delete password; }
		password = new string(passwordIn);
	}
	catch (...)
	{
		std::cout << "Exception in Password::SetPassword!" << endl;
	}
}

void Password::SetPasswordLength(const int& passwordLen)
{
	passwordLength = passwordLen;
}

//Operator Overloads:
Password& Password::operator++()
{
	increment(passwordLength - 1); //Much faster
	/*
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal + InfInt(1)).toString();
	//Set Password string:
	if (password) { delete password; }
	password = operatorResult(base10Result);
	*/
	return (*this);
}

Password& Password::operator--()
{
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal - InfInt(1)).toString();
	//Set Password string:
	if (password) { delete password; }
	password = operatorResult(base10Result);
	
	return (*this);
}

Password Password::operator++(int)
{
	Password result(*this);
	++(*this);
	return result;
}

Password Password::operator--(int)
{
	return operator-(1);
}

char& Password::operator[] (int index)
{
	return password->at(index);
}


Password Password::operator+(const int& rhs) const
{
	Password output = Password(*this);
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal + InfInt(rhs)).toString();
	//Set Password string:
	if (output.password) { delete output.password; }
	output.password = operatorResult(base10Result);
	
	return output;
}

Password Password::operator+(const InfInt& rhs) const
{
	Password output = Password(*this);
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal + rhs).toString();
	//Re-set Password string:
	if (output.password) { delete output.password; }
	output.password = operatorResult(base10Result);
	
	return output;
}

Password Password::operator-(const int& rhs) const
{
	Password output = Password(*this);
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal - InfInt(rhs)).toString();
	//Set Password string:
	if (output.password) { delete output.password; }
	output.password = operatorResult(base10Result);
	
	return output;
}

Password Password::operator-(const InfInt& rhs) const
{
	Password output = Password(*this);
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal - rhs).toString();
	//Set Password string:
	if (output.password) { delete output.password; }
	output.password = operatorResult(base10Result);
	
	return output;
}

Password Password::operator*(const int& rhs) const
{
	Password output = Password(*this);
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal * InfInt(rhs)).toString();
	//Set Password string:
	if (output.password) { delete output.password; }
	output.password = operatorResult(base10Result);
	
	return output;
}

Password Password::operator*(const InfInt& rhs) const
{
	Password output = Password(*this);
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal * rhs).toString();
	//Set Password string:
	if (output.password) { delete output.password; }
	output.password = operatorResult(base10Result);
	
	return output;
}

Password Password::operator/(const int& rhs) const
{
	Password output = Password(*this);
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal / InfInt(rhs)).toString();
	//Set Password string:
	if (output.password) { delete output.password; }
	output.password = operatorResult(base10Result);
	
	return output;
}

Password Password::operator/(const InfInt& rhs) const
{
	Password output = Password(*this);
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal / rhs).toString();
	//Set Password string:
	if (output.password) { delete output.password; }
	output.password = operatorResult(base10Result);
	
	return output;
}

Password Password::operator%(const int& rhs) const
{
	Password output = Password(*this);
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal % InfInt(rhs)).toString();
	//Set Password string:
	if (output.password) { delete output.password; }
	output.password = operatorResult(base10Result);
	
	return output;
}

Password Password::operator%(const InfInt& rhs) const
{
	Password output = Password(*this);
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal % rhs).toString();
	//Set Password string:
	if (output.password) { delete output.password; }
	output.password = operatorResult(base10Result);
	
	return output;
}

const Password& Password::operator+=(const int& rhs) 
{
	try
	{
		//Convert password to base 10:
		InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
		//Add input value:
		string base10Result = (passwordVal + InfInt(rhs)).toString();
		//Set Password string:
		if (password) { delete password; }
		password = operatorResult(base10Result);
	}
	catch (const std::exception& e)
	{
		std::cout << "Exception in PasswordGenerator::GenerateBlockSection!" << e.what() << endl;
	}

	return (*this);
}

const Password& Password::operator+=(const InfInt& rhs)
{
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal + rhs).toString();
	//Set Password string:
	if (password) { delete password; }
	password = operatorResult(base10Result);

	return (*this);
}

const Password& Password::operator-=(const int& rhs) 
{
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal - InfInt(rhs)).toString();
	//Set Password string:
	if (password) { delete password; }
	password = operatorResult(base10Result);

	return (*this);
}

const Password& Password::operator-=(const InfInt& rhs) 
{
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal - rhs).toString();
	//Set Password string:
	if (password) { delete password; }
	password = operatorResult(base10Result);

	return (*this);
}

const Password& Password::operator*=(const int& rhs) 
{ 
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal * InfInt(rhs)).toString();
	//Set Password string:
	if (password) { delete password; }
	password = operatorResult(base10Result);

	return (*this);
}

const Password& Password::operator*=(const InfInt& rhs) 
{ 
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal * rhs).toString();
	//Set Password string:
	if (password) { delete password; }
	password = operatorResult(base10Result);

	return (*this);
}

const Password& Password::operator/=(const int& rhs) 
{ 
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal / InfInt(rhs)).toString();
	//Set Password string:
	if (password) { delete password; }
	password = operatorResult(base10Result);

	return (*this);
}

const Password& Password::operator/=(const InfInt& rhs) 
{ 
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal / rhs).toString();
	//Set Password string:
	if (password) { delete password; }
	password = operatorResult(base10Result);

	return (*this);
}

const Password& Password::operator%=(const int& rhs) 
{ 
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal % InfInt(rhs)).toString();
	//Set Password string:
	if (password) { delete password; }
	password = operatorResult(base10Result);

	return (*this);
}

const Password& Password::operator%=(const InfInt& rhs) 
{ 
	//Convert password to base 10:
	InfInt passwordVal = InfInt(alphabet->ConvertToBase10String(*password));
	//Add input value:
	string base10Result = (passwordVal % rhs).toString();
	//Set Password string:
	if (password) { delete password; }
	password = operatorResult(base10Result);

	return (*this);
}

bool Password::operator==(const Password& passwordIn) const
{
	return password->compare(*passwordIn.GetPassword()) == 0;
}

bool Password::operator==(const string& passwordIn) const
{
	return password->compare(passwordIn) == 0;
}

//OStream overload:
ostream& operator<< (ostream& outStream, Password& passwordIn)
{
	outStream << *passwordIn.password;

	return outStream;
}