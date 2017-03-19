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
#ifndef PASSWORD_H_
#define PASSWORD_H_

#include "CrackingAlphabet.h"
//LGPL Library, obtained: http://code.google.com/p/infint/:
//LGPL Lib .h file. - Can only include once at top level, else it banjaxes 
//the compilation unit as a result of external linkage errors. :-/
#include "InfInt.h" 

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>

using std::ostream;
using std::string;
using std::endl;
using std::size_t;

/*
	This class provides string manipulation functions over
	an arbitraty set of characters.  Allowing brute force 
	operations over password combinations.  Such as password++
	to increase to the next available iteration of a given 
	brute force attack.

	Uses some of the base 10 to base n (and vice-versa) methods
	that are defined within the CrackingAlphabet class.
 */
class Password
{
public:
	Password(void);
	Password(CrackingAlphabet* passwordAlphabet, string* password, int passwordLength);
	Password(const Password& pswIn);
	~Password(void);

	//Getters:
	string*				GetPassword()				const;
	CrackingAlphabet*	GetCrackingAlphabet()		const;
	int					GetPasswordLength()			const;
	string*				GetInitialPasswordCombo()	const;
	int					GetPasswordBase()			const;

	//Setters:
	void SetPassword(string& passwordIn);
	void SetPasswordLength(const int& passwordLen);

	//Operator Overloads:
	//Array Access overload:
	char& operator[] (int index);

	//Mathematical Operators:
	Password operator+(const int&	 rhs)		const;
	Password operator-(const int&	 rhs)		const;
	Password operator*(const int&	 rhs)		const;
	Password operator/(const int&	 rhs)		const;	
	Password operator%(const int&	 rhs)		const;

	Password operator+(const InfInt& rhs)		const;
	Password operator-(const InfInt& rhs)		const;
	Password operator*(const InfInt& rhs)		const;
	Password operator/(const InfInt& rhs)		const;
	Password operator%(const InfInt& rhs)		const;

	const Password& operator+=(const int&	 rhs);
	const Password& operator-=(const int&	 rhs);
	const Password& operator*=(const int&	 rhs);
	const Password& operator/=(const int&	 rhs);
	const Password& operator%=(const int&	 rhs);

	const Password& operator+=(const InfInt& rhs);
	const Password& operator-=(const InfInt& rhs);
	const Password& operator*=(const InfInt& rhs);
	const Password& operator/=(const InfInt& rhs);
	const Password& operator%=(const InfInt& rhs);

	//pre/postfix increment/decrement:
    Password& operator++();
    Password& operator--();
    Password operator++(int);
    Password operator--(int);

	//Equals Overload:
	bool operator==(const Password& password) const;
	bool operator==(const string&   password) const;

	//IO overloads:
	friend ostream& operator<<(ostream& outStream, Password& password);

protected:
private:
	//Member Variables:
	string*				password;
	CrackingAlphabet*	alphabet;
	int					passwordLength;

	//Inline Functions:

	/*
		Increments a given password by a single digit.
	 */
	inline void increment(int index)
	{
		string* alpha		 = alphabet->GetAlphabet();
		int alphaln			 = alphabet->GetAlphabetSize();

		int i;
		int pswInd = index;
		//Find current character in the alphabet:
		for (i = 0; i < alphaln; i++)
		{
			if (password->at(pswInd) == alpha->at(i))
			{
				//Set current character to the next one (in Z(N)*):
				password->at(pswInd) = alpha->at(((i + 1) % alphaln));
				
				//If we surpassed the group order, we need to check prev char:
				if ((password->at(pswInd) == alpha->at(0)) && ((pswInd - 1) >= 0))
				{
					//Need to increment next char:
					increment(--pswInd);
				}
				//Break loop execution (for speed):
				break;
			}
		}
	}

	/* 
		This Method is broken.  
		Replaced with a non-recursive algorithm. 
	*/
	//inline void decrement(int index)
	//{
	//	string* alpha	= alphabet->GetAlphabet();
	//	int alphaln		= alphabet->GetAlphabetSize();
	//	std::cout << *password << std::endl;
	//	int i;
	//	int pswInd = index;
	//	//Find current character in the alphabet:
	//	for (i = 0; i < alphaln; i++)
	//	{
	//		if (password->at(pswInd) == alpha->at(i))
	//		{
	//			//Prevent falling off the start of the array:
	//			if (i == 0)
	//			{
	//				//Set current character to the previous one (in Z(N)*):
	//				password->at(pswInd) = alpha->at(alphaln - 1);
	//			}
	//			else
	//			{
	//				//Set current character to the previous one (in Z(N)*):
	//				password->at(pswInd) = alpha->at((i - 1));
	//			}
	//			
	//			//If we surpassed the group order, we need to check prev char:
	//			if ((password->at(pswInd) == alpha->at(0)) && ((pswInd - 1) >= 0))
	//			{
	//				decrement(--pswInd);
	//			}
	//			//Break loop execution (for speed):
	//			break;
	//		}
	//	}
	//}

	inline string* operatorResult(string& base10Result) const
	{
		//Convert result back to base n:
		string operatorResult = string(alphabet->ConvertBase10ToAlphaBase(base10Result));

		//Create output string prefixed to correct password length with initial alphabet character:
		string* result = new string(passwordLength, alphabet->GetAlphabet()->at(0));

		//Ensure we haven't wrapped the complete keyspace (Prevents error on last round):
		if (operatorResult.size() <= (unsigned)passwordLength)
		{
			result->replace((passwordLength - operatorResult.size()), operatorResult.size(), operatorResult);
		}

		return result;
	}

};
#endif