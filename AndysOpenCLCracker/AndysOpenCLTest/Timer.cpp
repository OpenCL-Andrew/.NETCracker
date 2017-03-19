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
#include "Timer.h"

Timer::Timer(void) { }
Timer::~Timer(void) { }

void Timer::StartTimer()
{
	cpuStart = clock();
	elapsedStart = high_resolution_clock::now();
}

void Timer::StopTimer()
{
	cpuEnd = clock();
	elapsedEnd = high_resolution_clock::now();
}

string Timer::TimeElapsed()
{
	stringstream output;

	output << "CPU runtime used: " << (1000.0 * (cpuEnd - cpuStart) / CLOCKS_PER_SEC) << " ms" << endl;
	output << "Physical Duration: " << duration_cast<milliseconds>(elapsedEnd - elapsedStart).count() << "ms" << endl;
		
	return output.str();
}

