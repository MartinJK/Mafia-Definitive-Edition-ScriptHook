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
#include "../singleton.h"
#include "../fnv1.h"
#include "hooking.h"
#include <unordered_map>

class PatternPool : public singleton<PatternPool>
{
private:
	std::unordered_map<uint32_t, hooking::patterns::pattern*> _patterns = {};
#if DEBUG
	std::map<uint32_t, std::string> _patternStrs;
#endif

	static void nullsub() {};

public:
	PatternPool()
	{
		_patterns.clear();
#if DEBUG
		_patternStrs.clear();
#endif
	}

	virtual ~PatternPool()
	{
		for (auto& i : _patterns) {
			delete i.second; // delete heap allocated pattern
		}

		this->_patterns.clear();
#if DEBUG
		_patternStrs.clear();
#endif
	}

	hooking::pattern* Get(uint32_t identifier, bool count = false)
	{
		auto& result = _patterns[identifier];
		if (result)
			return result;
		else
			return nullptr;
	}
	std::unordered_map<uint32_t, hooking::patterns::pattern*>& GetAll()
	{
		return _patterns;
	}

	size_t Count(uint32_t identifier)
	{
		auto& result = _patterns[identifier];
		if (result) {
			return result->matches().size();
		}
		else {
			return 0;
		}
	}

	uintptr_t Adjust(uint32_t identifier, int32_t adjust)
	{
		auto& result = _patterns[identifier];
		if (result) {
			return (uintptr_t)result->get(0).adjust(adjust).cast<void*>();
		}
		else {
			return (uintptr_t)nullsub;
		}
	}

	uintptr_t GetRelativeAddress(uint32_t identifier, int32_t instructionRelativeAddressPosition, int32_t instructionSize)
	{
		auto& result = _patterns[identifier];
		if (result)
		{
			auto addr = result->get(0).origaddr();
			return static_cast<uintptr_t>(addr + *(int32_t*)(addr + instructionRelativeAddressPosition) + instructionSize);
		}
		else {
			return (uintptr_t)nullsub;
		}
	}

	uintptr_t GetAddr(uint32_t identifier)
	{
		auto& result = _patterns[identifier];
		if (result)
		{
#if DEBUG
			if (!(void*)&result->get(0))
			{
				__debugbreak();
			}
#endif
			return result->get(0).origaddr();
		}
		else {
			return (uintptr_t)nullsub;
		}
	}

	uintptr_t GetAdjAddr(uint32_t identifier, int32_t adjust)
	{
		auto& result = _patterns[identifier];
		auto returnaddr = (uintptr_t)nullsub;
		if (result)
		{
			returnaddr = result->get(0).origaddr();
			returnaddr += adjust;
		}
		return returnaddr;
	}

	void Add(uint32_t hash, const std::string& pattern)
	{
		hooking::patterns::pattern* _pat = new hooking::pattern(pattern);
		_patterns.insert(std::pair<uint32_t, hooking::patterns::pattern*>(hash, _pat));

#if DEBUG
		_patternStrs[hash] = pattern;
#endif
	}

	void Add(const std::string& hash, const std::string& pattern)
	{
		hooking::patterns::pattern* _pat = new hooking::pattern(pattern);
		_patterns.insert(std::pair<uint32_t, hooking::patterns::pattern*>(fnv_1_32{}(hash.c_str()), _pat));

#if DEBUG
		_patternStrs[fnv_1_32{}(hash)] = pattern;
#endif
	}

	void Remove(uint32_t ident) // can be pattern or string identifier
	{
		for (auto& i : _patterns)
		{
			if (i.first == ident)
			{
				_patterns.erase(ident); // std::remove(_patterns.begin(), _patterns.end(), i), _patterns.end());
				delete i.second;
				break;
			}
		}
	}

#if DEBUG
	std::string GetPattern(uint32_t hash)
	{
		return _patternStrs[hash];
	}
#endif
};