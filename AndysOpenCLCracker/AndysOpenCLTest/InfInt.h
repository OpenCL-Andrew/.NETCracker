/*
 * InfInt - Arbitrary-Precision Integer Arithmetic Library
 * Copyright (C) 2013 Sercan Tutar
 *
 * Modified by Andrew Ruddick 2014.
 * -Code decomposed into .h and .cpp files to prevent external linkage errors.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 *
 * USAGE:
 *   It is pretty straight forward to use the library. Just create an instance of
 *   InfInt class and start using it.
 *
 *   Useful methods:
 *      intSqrt:        integer square root operation
 *      digitAt:        returns digit at index
 *      numberOfDigits: returns number of digits
 *      size:           returns size in bytes
 *      toString:       converts it to a string
 *
 *   There are also conversion methods which allow conversion to primitive types:
 *   toInt, toLong, toLongLong, toUnsignedInt, toUnsignedLong, toUnsignedLongLong.
 *
 *   You may define INFINT_USE_EXCEPTIONS and library methods will start raising
 *   InfIntException in case of error instead of writing error messages using
 *   std::cerr.
 *
 *   See ReadMe.txt for more info.
 *
 *
 * No overflows, happy programmers!
 *
 */

#ifndef INFINT_H_
#define INFINT_H_

#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>

#include <limits.h>
#include <stdlib.h>

//#include "Profiler.h"

#ifdef _WIN32
#define LONG_LONG_MIN LLONG_MIN
#define LONG_LONG_MAX LLONG_MAX
#define ULONG_LONG_MIN ULLONG_MIN
#define ULONG_LONG_MAX ULLONG_MAX
#endif

//#define INFINT_USE_EXCEPTIONS
//#define INFINT_USE_SHORT_BASE

#ifdef INFINT_USE_EXCEPTIONS
#include <exception>
#endif

//inline bool check_pos(int n)
//{
//    return n >= 0;
//}
//inline bool check_neg(int n)
//{
//    return n <= 0;
//}

#ifdef INFINT_USE_SHORT_BASE // uses 10^4 (short) as the base
typedef short ELEM_TYPE;
typedef int PRODUCT_TYPE;
static const ELEM_TYPE BASE = 10000;
static const ELEM_TYPE UPPER_BOUND = 9999;
static const ELEM_TYPE DIGIT_COUNT = 4;
static const int powersOfTen[] = { 1, 10, 100, 1000};
#else // uses 10^9 (int) as the base
typedef int ELEM_TYPE;
typedef long long PRODUCT_TYPE;
static const ELEM_TYPE BASE = 1000000000;
static const ELEM_TYPE UPPER_BOUND = 999999999;
static const ELEM_TYPE DIGIT_COUNT = 9;
static const int powersOfTen[] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
#endif

#ifdef INFINT_USE_EXCEPTIONS
class InfIntException: public std::exception
{
public:
    InfIntException(const std::string& txt) throw ();
    ~InfIntException() throw ();
    const char* what() const throw ();
private:
    std::string txt;
};

InfIntException::InfIntException(const std::string& txt) throw () :
std::exception(), txt(txt)
{
}

InfIntException::~InfIntException() throw ()
{
}

const char* InfIntException::what() const throw ()
{
    return txt.c_str();
}
#endif

class InfInt
{
    friend std::ostream& operator<<(std::ostream &s, const InfInt &n);
    friend std::istream& operator>>(std::istream &s, InfInt &val);

public:
    /* some constants */
    static const InfInt zero;
    static const InfInt one;
    static const InfInt two;

    /* constructors */
    InfInt();
    InfInt(const char* c);
    InfInt(const std::string& s);
    InfInt(int l);
    InfInt(long l);
    InfInt(long long l);
    InfInt(unsigned int l);
    InfInt(unsigned long l);
    InfInt(unsigned long long l);

    /* assignment operators */
    const InfInt& operator=(const char* c);
    const InfInt& operator=(const std::string& s);
    const InfInt& operator=(int l);
    const InfInt& operator=(long l);
    const InfInt& operator=(long long l);
    const InfInt& operator=(unsigned int l);
    const InfInt& operator=(unsigned long l);
    const InfInt& operator=(unsigned long long l);

    /* unary increment/decrement operators */
    const InfInt& operator++();
    const InfInt& operator--();
    InfInt operator++(int);
    InfInt operator--(int);

    /* operational assignments */
    const InfInt& operator+=(const InfInt& rhs);
    const InfInt& operator-=(const InfInt& rhs);
    const InfInt& operator*=(const InfInt& rhs);
    const InfInt& operator/=(const InfInt& rhs); // throw
    const InfInt& operator%=(const InfInt& rhs); // throw
    const InfInt& operator*=(ELEM_TYPE rhs);

    /* operations */
    InfInt operator-() const;
    InfInt operator+(const InfInt& rhs) const;
    InfInt operator-(const InfInt& rhs) const;
    InfInt operator*(const InfInt& rhs) const;
    InfInt operator/(const InfInt& rhs) const; // throw
    InfInt operator%(const InfInt& rhs) const; // throw
    InfInt operator*(ELEM_TYPE rhs) const;

    /* relational operations */
    bool operator==(const InfInt& rhs) const;
    bool operator!=(const InfInt& rhs) const;
    bool operator<(const InfInt& rhs) const;
    bool operator<=(const InfInt& rhs) const;
    bool operator>(const InfInt& rhs) const;
    bool operator>=(const InfInt& rhs) const;

    /* integer square root */
    InfInt intSqrt() const; // throw

    /* digit operations */
    char digitAt(size_t i) const; // throw
    size_t numberOfDigits() const;

    /* size in bytes */
    size_t size() const;

    /* string conversion */
    std::string toString() const;

    /* conversion to primitive types */
    int toInt() const; // throw
    long toLong() const; // throw
    long long toLongLong() const; // throw
    unsigned int toUnsignedInt() const; // throw
    unsigned long toUnsignedLong() const; // throw
    unsigned long long toUnsignedLongLong() const; // throw

private:
    static ELEM_TYPE dInR(const InfInt& R, const InfInt& D);
    static void multiplyByDigit(ELEM_TYPE factor, std::vector<ELEM_TYPE>& val);

    void correct(bool justCheckLeadingZeros = false, bool hasValidSign = false);
    void fromString(const std::string& s);
    void optimizeSqrtSearchBounds(InfInt& lo, InfInt& hi) const;
    void truncateToBase();
    bool equalizeSigns();
    void removeLeadingZeros();

    std::vector<ELEM_TYPE> val; // number with base FACTOR
    bool pos; // true if number is positive
};
#endif
