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
#include "InfInt.h"

const InfInt InfInt::zero = 0;
const InfInt InfInt::one = 1;
const InfInt InfInt::two = 2;

InfInt::InfInt() : pos(true)
{
    val.push_back((ELEM_TYPE) 0);
}

InfInt::InfInt(const char* c)
{
    fromString(c);
}

InfInt::InfInt(const std::string& s)
{
    fromString(s);
}

InfInt::InfInt(int l) : pos(l >= 0)
{
    if (!pos)
    {
        l = -l;
    }
    do
    {
        div_t dt = div(l, BASE);
        val.push_back((ELEM_TYPE) dt.rem);
        l = dt.quot;
    } while (l > 0);
}

InfInt::InfInt(long l) : pos(l >= 0)
{
    if (!pos)
    {
        l = -l;
    }
    do
    {
        ldiv_t dt = ldiv(l, BASE);
        val.push_back((ELEM_TYPE) dt.rem);
        l = dt.quot;
    } while (l > 0);
}

InfInt::InfInt(long long l) : pos(l >= 0)
{
    if (!pos)
    {
        l = -l;
    }
    do
    {
#ifndef _WIN32
        lldiv_t dt = lldiv(l, BASE);
        val.push_back((ELEM_TYPE) dt.rem);
        l = dt.quot;
#else
        val.push_back((ELEM_TYPE) (l % BASE));
        l = l / BASE;
#endif
    } while (l > 0);
}

InfInt::InfInt(unsigned int l) : pos(true)
{
    do
    {
        val.push_back((ELEM_TYPE) (l % BASE));
        l = l / BASE;
    } while (l > 0);
}

InfInt::InfInt(unsigned long l) : pos(true)
{
    do
    {
        val.push_back((ELEM_TYPE) (l % BASE));
        l = l / BASE;
    } while (l > 0);
}

InfInt::InfInt(unsigned long long l) : pos(true)
{
    do
    {
        val.push_back((ELEM_TYPE) (l % BASE));
        l = l / BASE;
    } while (l > 0);
}

const InfInt& InfInt::operator=(const char* c)
{
    fromString(c);
    return *this;
}

const InfInt& InfInt::operator=(const std::string& s)
{
    fromString(s);
    return *this;
}

const InfInt& InfInt::operator=(int l)
{
    pos = l >= 0;
    val.clear();
    if (!pos)
    {
        l = -l;
    }
    do
    {
        div_t dt = div(l, BASE);
        val.push_back((ELEM_TYPE) dt.rem);
        l = dt.quot;
    } while (l > 0);
    return *this;
}

const InfInt& InfInt::operator=(long l)
{
    pos = l >= 0;
    val.clear();
    if (!pos)
    {
        l = -l;
    }
    do
    {
        ldiv_t dt = ldiv(l, BASE);
        val.push_back((ELEM_TYPE) dt.rem);
        l = dt.quot;
    } while (l > 0);
    return *this;
}

const InfInt& InfInt::operator=(long long l)
{
    pos = l >= 0;
    val.clear();
    if (!pos)
    {
        l = -l;
    }
    do
    {
#ifndef _WIN32
        lldiv_t dt = lldiv(l, BASE);
        val.push_back((ELEM_TYPE) dt.rem);
        l = dt.quot;
#else
        val.push_back((ELEM_TYPE) (l % BASE));
        l = l / BASE;
#endif
    } while (l > 0);
    return *this;
}

const InfInt& InfInt::operator=(unsigned int l)
{
    pos = true;
    val.clear();
    do
    {
        val.push_back((ELEM_TYPE) (l % BASE));
        l = l / BASE;
    } while (l > 0);
    return *this;
}

const InfInt& InfInt::operator=(unsigned long l)
{
    pos = true;
    val.clear();
    do
    {
        val.push_back((ELEM_TYPE) (l % BASE));
        l = l / BASE;
    } while (l > 0);
    return *this;
}

const InfInt& InfInt::operator=(unsigned long long l)
{
    pos = true;
    val.clear();
    do
    {
        val.push_back((ELEM_TYPE) (l % BASE));
        l = l / BASE;
    } while (l > 0);
    return *this;
}

const InfInt& InfInt::operator++()
{
    val[0] += (pos ? 1 : -1);
    this->correct(false, true);
    return *this;
}

const InfInt& InfInt::operator--()
{
    val[0] -= (pos ? 1 : -1);
    this->correct(false, true);
    return *this;
}

InfInt InfInt::operator++(int)
{
    InfInt result = *this;
    val[0] += (pos ? 1 : -1);
    this->correct(false, true);
    return result;
}

InfInt InfInt::operator--(int)
{
    InfInt result = *this;
    val[0] -= (pos ? 1 : -1);
    this->correct(false, true);
    return result;
}

const InfInt& InfInt::operator+=(const InfInt& rhs)
{
    if (rhs.val.size() > val.size())
    {
        val.resize(rhs.val.size(), 0);
    }
    for (size_t i = 0; i < val.size(); ++i)
    {
        val[i] = (pos ? val[i] : -val[i]) + (i < rhs.val.size() ? (rhs.pos ? rhs.val[i] : -rhs.val[i]) : 0);
    }
    correct();
    return *this;
}

const InfInt& InfInt::operator-=(const InfInt& rhs)
{
    if (rhs.val.size() > val.size())
    {
        val.resize(rhs.val.size(), 0);
    }
    for (size_t i = 0; i < val.size(); ++i)
    {
        val[i] = (pos ? val[i] : -val[i]) - (i < rhs.val.size() ? (rhs.pos ? rhs.val[i] : -rhs.val[i]) : 0);
    }
    correct();
    return *this;
}

const InfInt& InfInt::operator*=(const InfInt& rhs)
{
    // TODO: optimize (do not use operator*)
    *this = *this * rhs;
    return *this;
}

const InfInt& InfInt::operator/=(const InfInt& rhs)
{
    if (rhs == zero)
    {
#ifdef INFINT_USE_EXCEPTIONS
        throw InfIntException("division by zero");
#else
        std::cerr << "Division by zero!" << std::endl;
        return *this;
#endif
    }
    InfInt R, D = (rhs.pos ? rhs : -rhs), N = (pos ? *this : -*this);
    bool oldpos = pos;
    val.clear();
    val.resize(N.val.size(), 0);
    for (int i = (int) N.val.size() - 1; i >= 0; --i)
    {
        R.val.insert(R.val.begin(), (ELEM_TYPE) 0);
        R.val[0] = N.val[i];
        R.correct(true);
        ELEM_TYPE cnt = dInR(R, D);
        R -= D * cnt;
        val[i] += cnt;
    }
    correct();
    pos = (val.size() == 1 && val[0] == 0) ? true : (oldpos == rhs.pos);
    return *this;
}

const InfInt& InfInt::operator%=(const InfInt& rhs)
{
    if (rhs == zero)
    {
#ifdef INFINT_USE_EXCEPTIONS
        throw InfIntException("division by zero");
#else
        std::cerr << "Division by zero!" << std::endl;
        return zero;
#endif
    }
    InfInt D = (rhs.pos ? rhs : -rhs), N = (pos ? *this : -*this);
    bool oldpos = pos;
    val.clear();
    for (int i = (int) N.val.size() - 1; i >= 0; --i)
    {
        val.insert(val.begin(), (ELEM_TYPE) 0);
        val[0] = N.val[i];
        correct(true);
        *this -= D * dInR(*this, D);
    }
    correct();
    pos = (val.size() == 1 && val[0] == 0) ? true : oldpos;
    return *this;
}

const InfInt& InfInt::operator*=(ELEM_TYPE rhs)
{
    ELEM_TYPE factor = rhs < 0 ? -rhs : rhs;
    bool oldpos = pos;
    multiplyByDigit(factor, val);
    correct();
    pos = (val.size() == 1 && val[0] == 0) ? true : (oldpos == (rhs >= 0));
    return *this;
}

InfInt InfInt::operator-() const
{//PROFILED_SCOPE
    InfInt result = *this;
    result.pos = !pos;
    return result;
}

InfInt InfInt::operator+(const InfInt& rhs) const
{//PROFILED_SCOPE
    InfInt result;
    result.val.resize(val.size() > rhs.val.size() ? val.size() : rhs.val.size(), 0);
    for (size_t i = 0; i < val.size() || i < rhs.val.size(); ++i)
    {
        result.val[i] = (i < val.size() ? (pos ? val[i] : -val[i]) : 0) + (i < rhs.val.size() ? (rhs.pos ? rhs.val[i] : -rhs.val[i]) : 0);
    }
    result.correct();
    return result;
}

InfInt InfInt::operator-(const InfInt& rhs) const
{//PROFILED_SCOPE
    InfInt result;
    result.val.resize(val.size() > rhs.val.size() ? val.size() : rhs.val.size(), 0);
    for (size_t i = 0; i < val.size() || i < rhs.val.size(); ++i)
    {
        result.val[i] = (i < val.size() ? (pos ? val[i] : -val[i]) : 0) - (i < rhs.val.size() ? (rhs.pos ? rhs.val[i] : -rhs.val[i]) : 0);
    }
    result.correct();
    return result;
}

InfInt InfInt::operator*(const InfInt& rhs) const
{//PROFILED_SCOPE
    InfInt result;
    result.val.resize(val.size() + rhs.val.size(), 0);
    PRODUCT_TYPE carry = 0;
    size_t digit = 0;
    for (;; ++digit)
    {//PROFILED_SCOPE
        //result.val[digit] = (ELEM_TYPE) (carry % BASE);
        //carry /= BASE;

        PRODUCT_TYPE oldcarry = carry;
        carry /= BASE;
        result.val[digit] = (ELEM_TYPE) (oldcarry - carry * BASE);

        bool found = false;
        for (size_t i = digit < rhs.val.size() ? 0 : digit - rhs.val.size() + 1; i < val.size() && i <= digit; ++i)
        {//PROFILED_SCOPE
            PRODUCT_TYPE pval = result.val[digit] + val[i] * (PRODUCT_TYPE) rhs.val[digit - i];
            if (pval >= BASE || pval <= -BASE)
            {//PROFILED_SCOPE
                //carry += pval / BASE;
                //pval %= BASE;

                PRODUCT_TYPE quot = pval / BASE;
                carry += quot;
                pval -= quot * BASE;
            }
            result.val[digit] = (ELEM_TYPE) pval;
            found = true;
        }
        if (!found)
        {//PROFILED_SCOPE
            break;
        }
    }
    for (; carry > 0; ++digit)
    {//PROFILED_SCOPE
        result.val[digit] = (ELEM_TYPE) (carry % BASE);
        carry /= BASE;
    }
    result.correct();
    result.pos = (result.val.size() == 1 && result.val[0] == 0) ? true : (pos == rhs.pos);
    return result;
}

InfInt InfInt::operator/(const InfInt& rhs) const
{//PROFILED_SCOPE
    if (rhs == zero)
    {
#ifdef INFINT_USE_EXCEPTIONS
        throw InfIntException("division by zero");
#else
        std::cerr << "Division by zero!" << std::endl;
        return zero;
#endif
    }
    InfInt Q, R, D = (rhs.pos ? rhs : -rhs), N = (pos ? *this : -*this);
    Q.val.resize(N.val.size(), 0);
    for (int i = (int) N.val.size() - 1; i >= 0; --i)
    {//PROFILED_SCOPE
        R.val.insert(R.val.begin(), (ELEM_TYPE) 0);
        R.val[0] = N.val[i];
        R.correct(true);
        ELEM_TYPE cnt = dInR(R, D);
        R -= D * cnt;
        Q.val[i] += cnt;
    }
    Q.correct();
    Q.pos = (Q.val.size() == 1 && Q.val[0] == 0) ? true : (pos == rhs.pos);
    return Q;
}

InfInt InfInt::operator%(const InfInt& rhs) const
{//PROFILED_SCOPE
    if (rhs == zero)
    {
#ifdef INFINT_USE_EXCEPTIONS
        throw InfIntException("division by zero");
#else
        std::cerr << "Division by zero!" << std::endl;
        return zero;
#endif
    }
    InfInt R, D = (rhs.pos ? rhs : -rhs), N = (pos ? *this : -*this);
    for (int i = (int) N.val.size() - 1; i >= 0; --i)
    {
        R.val.insert(R.val.begin(), (ELEM_TYPE) 0);
        R.val[0] = N.val[i];
        R.correct(true);
        R -= D * dInR(R, D);
    }
    R.correct();
    R.pos = (R.val.size() == 1 && R.val[0] == 0) ? true : pos;
    return R;
}

InfInt InfInt::operator*(ELEM_TYPE rhs) const
{//PROFILED_SCOPE
    InfInt result = *this;
    ELEM_TYPE factor = rhs < 0 ? -rhs : rhs;
    multiplyByDigit(factor, result.val);
    result.correct();
    result.pos = (result.val.size() == 1 && result.val[0] == 0) ? true : (pos == (rhs >= 0));
    return result;
}

bool InfInt::operator==(const InfInt& rhs) const
{//PROFILED_SCOPE
    if (pos != rhs.pos || val.size() != rhs.val.size())
    {
        return false;
    }
    for (int i = (int) val.size() - 1; i >= 0; --i)
    {
        if (val[i] != rhs.val[i])
        {
            return false;
        }
    }
    return true;
}

bool InfInt::operator!=(const InfInt& rhs) const
{//PROFILED_SCOPE
    if (pos != rhs.pos || val.size() != rhs.val.size())
    {
        return true;
    }
    for (int i = (int) val.size() - 1; i >= 0; --i)
    {
        if (val[i] != rhs.val[i])
        {
            return true;
        }
    }
    return false;
}

bool InfInt::operator<(const InfInt& rhs) const
{//PROFILED_SCOPE
    if (pos && !rhs.pos)
    {
        return false;
    }
    if (!pos && rhs.pos)
    {
        return true;
    }
    if (val.size() > rhs.val.size())
    {
        return pos ? false : true;
    }
    if (val.size() < rhs.val.size())
    {
        return pos ? true : false;
    }
    for (int i = (int) val.size() - 1; i >= 0; --i)
    {
        if (val[i] < rhs.val[i])
        {
            return pos ? true : false;
        }
        if (val[i] > rhs.val[i])
        {
            return pos ? false : true;
        }
    }
    return false;
}

bool InfInt::operator<=(const InfInt& rhs) const
{//PROFILED_SCOPE
    if (pos && !rhs.pos)
    {
        return false;
    }
    if (!pos && rhs.pos)
    {
        return true;
    }
    if (val.size() > rhs.val.size())
    {
        return pos ? false : true;
    }
    if (val.size() < rhs.val.size())
    {
        return pos ? true : false;
    }
    for (int i = (int) val.size() - 1; i >= 0; --i)
    {
        if (val[i] < rhs.val[i])
        {
            return pos ? true : false;
        }
        if (val[i] > rhs.val[i])
        {
            return pos ? false : true;
        }
    }
    return true;
}

bool InfInt::operator>(const InfInt& rhs) const
{//PROFILED_SCOPE
    if (pos && !rhs.pos)
    {
        return true;
    }
    if (!pos && rhs.pos)
    {
        return false;
    }
    if (val.size() > rhs.val.size())
    {
        return pos ? true : false;
    }
    if (val.size() < rhs.val.size())
    {
        return pos ? false : true;
    }
    for (int i = (int) val.size() - 1; i >= 0; --i)
    {
        if (val[i] < rhs.val[i])
        {
            return pos ? false : true;
        }
        if (val[i] > rhs.val[i])
        {
            return pos ? true : false;
        }
    }
    return false;
}

bool InfInt::operator>=(const InfInt& rhs) const
{//PROFILED_SCOPE
    if (pos && !rhs.pos)
    {
        return true;
    }
    if (!pos && rhs.pos)
    {
        return false;
    }
    if (val.size() > rhs.val.size())
    {
        return pos ? true : false;
    }
    if (val.size() < rhs.val.size())
    {
        return pos ? false : true;
    }
    for (int i = (int) val.size() - 1; i >= 0; --i)
    {
        if (val[i] < rhs.val[i])
        {
            return pos ? false : true;
        }
        if (val[i] > rhs.val[i])
        {
            return pos ? true : false;
        }
    }
    return true;
}

void InfInt::optimizeSqrtSearchBounds(InfInt& lo, InfInt& hi) const
{//PROFILED_SCOPE
    InfInt hdn = one;
    for (int i = (int) this->numberOfDigits() / 2; i >= 2; --i)
    {
        hdn *= 10;
    }
    if (lo < hdn)
    {
        lo = hdn;
    }
    hdn *= 100;
    if (hi > hdn)
    {
        hi = hdn;
    }
}

InfInt InfInt::intSqrt() const
{//PROFILED_SCOPE
    if (*this < zero)
    {
#ifdef INFINT_USE_EXCEPTIONS
        throw InfIntException("intSqrt called for negative integer");
#else
        std::cerr << "intSqrt called for negative integer: " << *this << std::endl;
        return zero;
#endif
    }
    InfInt hi = *this / two, lo = zero, mid, mid2;
    optimizeSqrtSearchBounds(lo, hi);
    do
    {
        mid = (hi + lo) / two; // 8 factor
        mid2 = mid * mid; // 1 factor
        if (mid2 == *this)
        {
            lo = mid;
            break;
        }
        else if (mid2 < *this)
        {
            lo = mid;
        }
        else
        {
            hi = mid;
        }
    } while (lo < hi - one && mid2 != *this);
    return lo;
}

char InfInt::digitAt(size_t i) const
{//PROFILED_SCOPE
    if (numberOfDigits() <= i)
    {
#ifdef INFINT_USE_EXCEPTIONS
        throw InfIntException("invalid digit index");
#else
        std::cerr << "Invalid digit index: " << i << std::endl;
        return -1;
#endif
    }
    return (val[i / DIGIT_COUNT] / powersOfTen[i % DIGIT_COUNT]) % 10;
}

size_t InfInt::numberOfDigits() const
{//PROFILED_SCOPE
    return (val.size() - 1) * DIGIT_COUNT
#ifdef INFINT_USE_SHORT_BASE
    + (val.back() > 999 ? 4 : (val.back() > 99 ? 3 : (val.back() > 9 ? 2 : 1)));
#else
    + (val.back() > 99999999 ? 9 : (val.back() > 9999999 ? 8 : (val.back() > 999999 ? 7 : (val.back() > 99999 ? 6 :
                                                                                           (val.back() > 9999 ? 5 : (val.back() > 999 ? 4 : (val.back() > 99 ? 3 : (val.back() > 9 ? 2 : 1))))))));
#endif
}

std::string InfInt::toString() const
{//PROFILED_SCOPE
    std::ostringstream oss;
    oss << *this;
    return oss.str();
}

size_t InfInt::size() const
{//PROFILED_SCOPE
    return val.size() * sizeof(ELEM_TYPE) + sizeof(bool);
}

int InfInt::toInt() const
{//PROFILED_SCOPE
    if (*this > INT_MAX || *this < INT_MIN)
#ifdef INFINT_USE_EXCEPTIONS
        throw InfIntException("out of bounds");
#else
    std::cerr << "Out of INT bounds: " << *this << std::endl;
#endif
    int result = 0;
    for (int i = (int) val.size() - 1; i >= 0; --i)
    {
        result = result * BASE + val[i];
    }
    return pos ? result : -result;
}

long InfInt::toLong() const
{//PROFILED_SCOPE
    if (*this > LONG_MAX || *this < LONG_MIN)
#ifdef INFINT_USE_EXCEPTIONS
        throw InfIntException("out of bounds");
#else
    std::cerr << "Out of LONG bounds: " << *this << std::endl;
#endif
    long result = 0;
    for (int i = (int) val.size() - 1; i >= 0; --i)
    {
        result = result * BASE + val[i];
    }
    return pos ? result : -result;
}

long long InfInt::toLongLong() const
{//PROFILED_SCOPE
    if (*this > LONG_LONG_MAX || *this < LONG_LONG_MIN)
#ifdef INFINT_USE_EXCEPTIONS
        throw InfIntException("out of bounds");
#else
    std::cerr << "Out of LLONG bounds: " << *this << std::endl;
#endif
    long long result = 0;
    for (int i = (int) val.size() - 1; i >= 0; --i)
    {
        result = result * BASE + val[i];
    }
    return pos ? result : -result;
}

unsigned int InfInt::toUnsignedInt() const
{//PROFILED_SCOPE
    if (!pos || *this > UINT_MAX)
#ifdef INFINT_USE_EXCEPTIONS
        throw InfIntException("out of bounds");
#else
    std::cerr << "Out of UINT bounds: " << *this << std::endl;
#endif
    unsigned int result = 0;
    for (int i = (int) val.size() - 1; i >= 0; --i)
    {
        result = result * BASE + val[i];
    }
    return result;
}

unsigned long InfInt::toUnsignedLong() const
{//PROFILED_SCOPE
    if (!pos || *this > ULONG_MAX)
#ifdef INFINT_USE_EXCEPTIONS
        throw InfIntException("out of bounds");
#else
    std::cerr << "Out of ULONG bounds: " << *this << std::endl;
#endif
    unsigned long result = 0;
    for (int i = (int) val.size() - 1; i >= 0; --i)
    {
        result = result * BASE + val[i];
    }
    return result;
}

unsigned long long InfInt::toUnsignedLongLong() const
{//PROFILED_SCOPE
    if (!pos || *this > ULONG_LONG_MAX)
#ifdef INFINT_USE_EXCEPTIONS
        throw InfIntException("out of bounds");
#else
    std::cerr << "Out of ULLONG bounds: " << *this << std::endl;
#endif
    unsigned long long result = 0;
    for (int i = (int) val.size() - 1; i >= 0; --i)
    {
        result = result * BASE + val[i];
    }
    return result;
}

void InfInt::truncateToBase()
{//PROFILED_SCOPE
    for (size_t i = 0; i < val.size(); ++i) // truncate each
    {
        if (val[i] >= BASE || val[i] <= -BASE)
        {//PROFILED_SCOPE
            div_t dt = div(val[i], BASE);
            val[i] = dt.rem;
            if (i + 1 >= val.size())
            {//PROFILED_SCOPE
                val.push_back(dt.quot);
            }
            else
            {//PROFILED_SCOPE
                val[i + 1] += dt.quot;
            }
        }
    }
}

bool InfInt::equalizeSigns()
{//PROFILED_SCOPE
    bool isPositive = true;
    int i = (int) ((val.size())) - 1;
    for (; i >= 0; --i)
    {
        if (val[i] != 0)
        {
            isPositive = val[i--] > 0;
            break;
        }
    }

    if (isPositive)
    {
        for (; i >= 0; --i)
        {
            if (val[i] < 0)
            {
                int k = 0, index = i + 1;
                for (; (size_t)(index) < val.size() && val[index] == 0; ++k, ++index); // count adjacent zeros on left
                //if ((size_t)(index) < val.size() && val[index] > 0)
                { // number on the left is positive
                    val[index] -= 1;
                    val[i] += BASE;
                    for (; k > 0; --k)
                    {
                        val[i + k] = UPPER_BOUND;
                    }
                }
            }
        }
    }
    else
    {
        for (; i >= 0; --i)
        {
            if (val[i] > 0)
            {
                int k = 0, index = i + 1;
                for (; (size_t)(index) < val.size() && val[index] == 0; ++k, ++index); // count adjacent zeros on right
                //if ((size_t)(index) < val.size() && val[index] < 0)
                { // number on the left is negative
                    val[index] += 1;
                    val[i] -= BASE;
                    for (; k > 0; --k)
                    {
                        val[i + k] = -UPPER_BOUND;
                    }
                }
            }
        }
    }
    
    return isPositive;
}

void InfInt::removeLeadingZeros()
{//PROFILED_SCOPE
    for (int i = (int) (val.size()) - 1; i > 0; --i) // remove leading 0's
    {
        if (val[i] != 0)
        {
            return;
        }
        else
        {
            val.erase(val.begin() + i);
        }
    }
}

void InfInt::correct(bool justCheckLeadingZeros, bool hasValidSign)
{//PROFILED_SCOPE
    if (!justCheckLeadingZeros)
    {
        truncateToBase();
        
        if (equalizeSigns())
        {
            pos = ((val.size() == 1 && val[0] == 0) || !hasValidSign) ? true : pos;
        }
        else
        {
            pos = hasValidSign ? !pos : false;
            for (size_t i = 0; i < val.size(); ++i)
            {
                val[i] = abs(val[i]);
            }
        }
    }
    
    removeLeadingZeros();
}

void InfInt::fromString(const std::string& s)
{//PROFILED_SCOPE
    pos = true;
    val.clear();
    // TODO use resize
    val.reserve(s.size() / DIGIT_COUNT + 1);
    int i = (int) s.size() - DIGIT_COUNT;
    for (; i >= 0; i -= DIGIT_COUNT)
    {
        val.push_back(atoi(s.substr(i, DIGIT_COUNT).c_str()));
    }
    if (i > -DIGIT_COUNT)
    {
        std::string ss = s.substr(0, i + DIGIT_COUNT);
        if (ss.size() == 1 && ss[0] == '-')
        {
            pos = false;
        }
        else
        {
            val.push_back(atoi(ss.c_str()));
        }
    }
    if (val.back() < 0)
    {
        val.back() = -val.back();
        pos = false;
    }
    correct(true);
}

ELEM_TYPE InfInt::dInR(const InfInt& R, const InfInt& D)
{//PROFILED_SCOPE
    ELEM_TYPE min = 0, max = UPPER_BOUND;
    while (max - min > 0)
    {
        ELEM_TYPE avg = max + min;
        //div_t dt = div(avg, 2);
        //avg = dt.rem ? (dt.quot + 1) : dt.quot;
        ELEM_TYPE havg = avg / 2;
        avg = avg - havg * 2 ? (havg + 1) : havg;
        InfInt prod = D * avg;
        if (R == prod)
        {//PROFILED_SCOPE
            return avg;
        }
        else if (R > prod)
        {//PROFILED_SCOPE
            min = avg;
        }
        else
        {//PROFILED_SCOPE
            max = avg - 1;
        }
    }
    return min;
}

void InfInt::multiplyByDigit(ELEM_TYPE factor, std::vector<ELEM_TYPE>& val)
{//PROFILED_SCOPE
    ELEM_TYPE carry = 0;
    for (size_t i = 0; i < val.size(); ++i)
    {
        PRODUCT_TYPE pval = val[i] * (PRODUCT_TYPE) factor + carry;
        if (pval >= BASE || pval <= -BASE)
        {
            //carry = (ELEM_TYPE) (pval / BASE);
            //pval %= BASE;

            carry = (ELEM_TYPE) (pval / BASE);
            pval -= carry * BASE;
        }
        else
        {
            carry = 0;
        }
        val[i] = (ELEM_TYPE) pval;
    }
    if (carry > 0)
    {
        val.push_back(carry);
    }
}

/**************************************************************/
/******************** NON-MEMBER OPERATORS ********************/
/**************************************************************/

std::istream& operator>>(std::istream &s, InfInt &n)
{//PROFILED_SCOPE
    std::string str;
    s >> str;
    n.fromString(str);
    return s;
}

std::ostream& operator<<(std::ostream &s, const InfInt &n)
{//PROFILED_SCOPE
    if (!n.pos)
    {
        s << '-';
    }
    bool first = true;
    for (int i = (int) n.val.size() - 1; i >= 0; --i)
    {
        if (first)
        {
            s << n.val[i];
            first = false;
        }
        else
        {
            s << std::setfill('0') << std::setw(DIGIT_COUNT) << n.val[i];
        }
    }
    return s;
}