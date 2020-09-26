/*
 * Copyright (c) 2010 Barzakh (martinjk 'at' outlook 'dot' com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 * claim that you wrote the original software. If you use this software
 * in a product, an acknowledgment in the product documentation would be
 * appreciated but is not required.

 * 2. Altered source versions must be plainly marked as such, and must not be
 * misrepresented as being the original software.

 * 3. This notice may not be removed or altered from any source
 * distribution.

 * 4. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#pragma once

#include <cstdint>
#include <string>

template <std::uint32_t FnvPrime, std::uint32_t OffsetBasis>
struct basic_fnv_1_32
{
	constexpr static uint32_t offsetBasis = OffsetBasis;
	constexpr static uint32_t prime = FnvPrime;

	std::uint32_t operator()(std::string const& text) const
	{
		std::uint32_t hash = OffsetBasis;
		for (std::string::const_iterator it = text.begin(), end = text.end();
		it != end; ++it)
		{
			hash *= FnvPrime;
			hash ^= *it;
		}

		return hash;
	}

	constexpr static inline uint32_t hash(const char * const aString, const size_t length, const uint32_t value = OffsetBasis)
	{
		return (length == 0) ? value : hash(aString + 1, length -1, (value * FnvPrime) ^ uint32_t(aString[0]));
	};
};

template <std::uint32_t FnvPrime, std::uint32_t OffsetBasis>
struct basic_fnv_1a
{
	std::uint32_t operator()(std::string const& text) const
	{
		std::uint32_t hash = OffsetBasis;
		for (std::string::const_iterator it = text.begin(), end = text.end();
		it != end; ++it)
		{
			hash *= FnvPrime;
			hash ^= *it;
		}

		return hash;
	}

	constexpr static inline uint32_t hash(const char * const aString, const size_t length, const uint32_t value = OffsetBasis)
	{
		return 0;
	};
};

using fnv_1_32 = basic_fnv_1_32<16777619, 2166136261>;

inline constexpr uint32_t operator "" _fnv1_32(const char* aString, const size_t aStrlen)
{
	using hash_type = fnv_1_32;
	return hash_type::hash(aString, aStrlen, hash_type::offsetBasis);
}