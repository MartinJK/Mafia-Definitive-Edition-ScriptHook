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

#include "jitasm.h"
#include "udis86.h"
#include <vector>
#include <locale>
#include <sstream>
#include <memory>

#ifdef _WIN32
#include <WinNT.h>
#endif

#if _WIN64 || __x86_64__ || __ppc64__
#define _x64 1
#else
#define _x64 0
#endif

/*
Copyright(c) 2014 Bas Timmer / NTAuthority et al.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files(the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions :

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "../singleton.h"

#include <immintrin.h>

#include <unordered_map>
#include <future>
#include <algorithm>
#include <type_traits>

template <std::uint64_t FnvPrime, std::uint64_t OffsetBasis>
struct basic_fnv_1
{
	std::uint64_t operator()(std::string const& text) const
	{
		std::uint64_t hash = OffsetBasis;
		for (std::string::const_iterator it = text.begin(), end = text.end();
			it != end; ++it)
		{
			hash *= FnvPrime;
			hash ^= *it;
		}

		return hash;
	}
};

const std::uint64_t fnv_prime = 1099511628211u;
const std::uint64_t fnv_offset_basis = 14695981039346656037u;

typedef basic_fnv_1<fnv_prime, fnv_offset_basis> fnv_1;


#if defined(_MSC_VER)
//  Microsoft
#define EXPORT __declspec(dllexport)
#define IMPORT __declspec(dllimport)
#elif defined(_GCC)
//  GCC
#define EXPORT __attribute__((visibility("default")))
#define IMPORT
#else
//  do nothing and hope for the best?
#define EXPORT
#define IMPORT
#pragma warning Unknown dynamic link import/export semantics.
#endif

#undef min

namespace hooking
{
	namespace hooking_helpers
	{
		// Just some put some code to address and address calculation
		/*extern "C" __declspec(dllimport)*/ void SetExecutableAddress(uintptr_t address);
		/*extern "C" __declspec(dllimport)*/ uintptr_t GetExecutableAddress();
		/*extern "C" __declspec(dllimport)*/ void* AllocInHookSection(size_t size);

		inline uintptr_t SetImageSize(uintptr_t address)
		{
			static uintptr_t executableAddress = 0;

			if (address == 0)
			{
				return executableAddress;
			}

			executableAddress = address;
			return executableAddress;
		}

		class section_info
		{
		private:
			uintptr_t _begin = 0;
			uintptr_t _end = 0;

		public:
			decltype(auto) begin() { return _begin; }
			decltype(auto) end() { return _end; }

			section_info(uintptr_t begin, uintptr_t end)
				: _begin(begin),
				_end(end)
			{}
		};

		class executable_info
		{
		private:
			uintptr_t m_begin = 0;
			uintptr_t m_end = 0;
			uintptr_t _imageSize = 0;
			uintptr_t _executableAddress = 0;
			bool _ssePatternSearching = false;
			std::wstring _workingPath;

			std::vector<section_info> sections = {};

		public:
			executable_info()
				: m_begin(0), m_end(0)
			{}

			void SetExecutableAddress(uintptr_t addr)
			{
				_executableAddress = addr;
			}

			uintptr_t GetExecutableAddress()
			{
				return _executableAddress;
			}

			void SetWorkingPath(const std::wstring& str)
			{
				_workingPath = str;
			}

			const std::wstring& GetWorkingPath()
			{
				if (!_workingPath.empty())
				{
					return _workingPath;
				}

				wchar_t szExePath[MAX_PATH] = { 0 };
				GetModuleFileNameW(GetModuleHandle(NULL), szExePath, MAX_PATH);

				// Fix path in string
				for (size_t i = wcslen(szExePath); i > 0; --i)
				{
					if (szExePath[i] == '\\')
					{
						szExePath[i + 1] = '\0';
						break;
					}
				}
				_workingPath = szExePath;
				return _workingPath;
			}

			void SetSSEPatternSearching(bool t)
			{
				_ssePatternSearching = t;
			}

			bool IsSSEPatternSearchingEnabled()
			{
				return _ssePatternSearching;
			}

			void EnsureInit(uintptr_t executableAddress = 0)
			{
				if ((m_begin && executableAddress == _executableAddress) || executableAddress == 0)
				{
					return;
				}

				_executableAddress = executableAddress;
				m_begin = _executableAddress;

				PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(_executableAddress);
				if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
				{
					throw std::runtime_error("Invalid DOS Signature");
				}

				PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)((_executableAddress + (dosHeader->e_lfanew * sizeof(char))));
				if (header->Signature != IMAGE_NT_SIGNATURE)
				{
					throw std::runtime_error("Invalid NT Signature");
				}

				m_end = m_begin + header->OptionalHeader.BaseOfCode + header->OptionalHeader.SizeOfCode;
				_imageSize = header->OptionalHeader.SizeOfImage;

				PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(header);

				for (int32_t i = 0; i < header->FileHeader.NumberOfSections; i++, section++)
				{
					bool executable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
					bool readable = (section->Characteristics & IMAGE_SCN_MEM_READ) != 0;
					//bool writeable = (section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

					if (readable && executable)
					{
						auto beg = (header->OptionalHeader.ImageBase + section->VirtualAddress);

						uint32_t sizeOfData = std::min(section->SizeOfRawData, section->Misc.VirtualSize);

						sections.emplace_back(beg, beg + sizeOfData);
					}
				}

				SetImageSize(_imageSize);
			}

			decltype(auto) begin() { return sections.begin(); }
			decltype(auto) end() { return sections.end(); }

			uintptr_t imageSize() { return _imageSize; };
		};

		inline void* AllocateFunctionStub(void *function)
		{
			char *code = reinterpret_cast<char*>(AllocInHookSection(20));
			*(uint8_t*)code = 0x48;
			*(uint8_t*)(code + 1) = 0xb8;
			*(uint64_t*)(code + 2) = (uint64_t)function;
			*(uint16_t*)(code + 10) = 0xE0FF;
			*(uint64_t*)(code + 12) = 0xCCCCCCCCCCCCCCCC;
			return code;
		}

		template<typename ValueType, typename AddressType>
		uintptr_t *detour_func(AddressType address, ValueType target)
		{
			char *code = reinterpret_cast<char*>(AllocateFunctionStub(target));

			ud_t ud;
			ud_init(&ud);

			ud_set_mode(&ud, 64);

			uint64_t k = address;
			ud_set_pc(&ud, k);
			ud_set_input_buffer(&ud, reinterpret_cast<uint8_t*>(address), INT64_MAX);

			auto opsize = ud_disassemble(&ud);
			while (opsize <= 20)
			{
				opsize += ud_disassemble(&ud);
			}

			opsize += 20;

			auto orig_code = reinterpret_cast<char*>(AllocInHookSection(opsize));

			orig_code = orig_code;

			opsize -= 20;

			memcpy(orig_code, (void*)address, opsize);
			auto code2 = orig_code + opsize;
			*(uint8_t*)code2 = 0x48;
			*(uint8_t*)(code2 + 1) = 0xb8;
			*(uint64_t*)(code2 + 2) = (uint64_t)(address + opsize);
			*(uint16_t*)(code2 + 10) = 0xE0FF;
			*(uint64_t*)(code2 + 12) = 0xCCCCCCCCCCCCCCCC;

			DWORD oldProtect;
			VirtualProtect((void*)address, 20, PAGE_EXECUTE_READWRITE, &oldProtect);

			memcpy((void*)address, code, 20);

			VirtualProtect((void*)address, 20, oldProtect, &oldProtect);

			return (uintptr_t *)orig_code;
		}

		class AssemblyGen
		{
		private:
			void *m_code = nullptr;
			size_t _size = 0;
		public:
			inline AssemblyGen(jitasm::Frontend &frontend)
			{
				frontend.Assemble();

				void *code = nullptr;
				// We want our code to work with all allocation locations
				code = AllocInHookSection(frontend.GetCodeSize());

				if (!code)
				{
					OutputDebugStringA("Warning Allocating using 0. This could/will break the rel offset calls");
					code = VirtualAlloc(0, frontend.GetCodeSize(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				}

				memcpy(code, frontend.GetCode(), frontend.GetCodeSize());
				_size = frontend.GetCodeSize();

				m_code = code;
			}

			inline ~AssemblyGen()
			{
				VirtualFree(m_code, 0, MEM_RELEASE);
			}

			inline void *GetCode()
			{
				return m_code;
			}

			inline size_t GetSize()
			{
				return _size;
			}
		};

		struct passed
		{
			template<typename ...T> passed(T...) {}
		};

		template<typename R, typename... Args>
		struct CallStub : jitasm::function<void, CallStub<R, Args...>>
		{
		private:
			void *m_target = nullptr;

		public:
			CallStub(void* target)
				: m_target(target)
			{ }

			void naked_main()
			{
				nop();
#if _x64==0
				uint32_t stackOffset = 0;
				uint32_t argOffset = sizeof(uintptr_t); // as frame pointers are also kept here
				uint32_t argCleanup = 0;

				passed{ ([&]
				{
					int size = static_cast<int>(std::min(sizeof(Args), sizeof(uintptr_t)));

					argOffset += size;
				}(), 1)... };

				// as this is the end, and the last argument isn't past the end
				argOffset -= sizeof(uintptr_t);

				passed{ ([&]
				{
					/*mov(rax, qword_ptr[rsp + stackOffset + argOffset]);
					push(rax);*/

					int size = static_cast<int>(std::max(sizeof(Args), sizeof(uintptr_t)));

					stackOffset += size;
					argCleanup += size;
					argOffset -= size;
				}(), 1)... };

				mov(eax, (uintptr_t)m_target);
				call(eax);
				add(esp, argCleanup);
#else
				mov(rax, reinterpret_cast<uintptr_t>(m_target));
				call(rax);
#endif
			}
		};

		template<typename R, typename... Args>
		struct JumpStub : jitasm::function<void, JumpStub<R, Args...>>
		{
		private:
			void *m_target = nullptr;

		public:
			JumpStub(void* target)
				: m_target(target)
			{ }

			void naked_main()
			{
				nop();
#if _x64==0
				uint32_t stackOffset = 0;
				uint32_t argOffset = sizeof(uintptr_t); // as frame pointers are also kept here
				uint32_t argCleanup = 0;

				passed{ ([&]
				{
					int size = static_cast<int>(std::min(sizeof(Args), sizeof(uintptr_t)));

					argOffset += size;
				}(), 1)... };

				// as this is the end, and the last argument isn't past the end
				argOffset -= sizeof(uintptr_t);

				passed{ ([&]
				{
					/*mov(rax, qword_ptr[rsp + stackOffset + argOffset]);
					push(rax);*/

					int size = static_cast<int>(std::max(sizeof(Args), sizeof(uintptr_t)));

					stackOffset += size;
					argCleanup += size;
					argOffset -= size;
				}(), 1)... };

				mov(eax, (uintptr_t)m_target);
				call(eax);
				add(esp, argCleanup);
#else
				mov(rax, reinterpret_cast<uintptr_t>(m_target));
				call(rax);
#endif
			}
		};

		template<typename ValueType, typename AddressType>
		inline void put(AddressType address, ValueType value)
		{
			DWORD oldProtect;
			VirtualProtect((void*)address, sizeof(value), PAGE_EXECUTE_READWRITE, &oldProtect);

			memcpy((void*)address, &value, sizeof(value));

			VirtualProtect((void*)address, sizeof(value), oldProtect, &oldProtect);
		}
	};

	using hooking_helpers::put;

	template<typename AddressType>
	inline void nop(AddressType address, size_t length)
	{
		memset((void*)address, 0x90, length);
	}

	template<typename AddressType>
	inline void retn(AddressType address)
	{
		memset((void*)address, 0xC3, 1);
	}

	template<typename AddressType>
	inline void return_function(AddressType address, uint16_t stackSize = 0)
	{
		if (stackSize == 0)
		{
			hooking_helpers::put<uint8_t>(address, 0xC3);
		}
		else
		{
			hooking_helpers::put<uint8_t>(address, 0xC2);
			hooking_helpers::put<uint16_t>((uintptr_t)address + 1, stackSize);
		}
	}

	template<typename T, typename AT>
	inline void jump(AT address, T func)
	{
		LPVOID funcStub = hooking_helpers::AllocateFunctionStub((void*)func);

		hooking_helpers::put<uint8_t>(address, 0xE9);
		hooking_helpers::put<int64_t>(static_cast<int64_t>((uintptr_t)address + 1), static_cast<int32_t>((intptr_t)funcStub - (intptr_t)address - 5));
	}

	template<typename T, typename AT>
	inline void call(AT address, T func)
	{
		LPVOID funcStub = hooking_helpers::AllocateFunctionStub((void*)func);

		hooking_helpers::put<uint8_t>(address, 0xE8);
		hooking_helpers::put<int64_t>(static_cast<int64_t>((uintptr_t)address + 1), static_cast<int32_t>((intptr_t)funcStub - (intptr_t)address - 5));
	}

	template<typename T>
	inline T get_call(T address)
	{
		intptr_t target = *(uintptr_t*)(address + 1);
		target += (address + 5);

		return (T)target;
	}

	template<typename TTarget, typename T>
	inline void set_call(TTarget* target, T address)
	{
		*(T*)target = get_call(address);
	}

	template<typename R, typename... Args>
	class inject_jump
	{
	private:
		R(*m_origAddress)(Args...);

		uintptr_t _address = 0;

		std::unique_ptr<hooking_helpers::AssemblyGen> _assembly;

	public:
		inject_jump(uintptr_t address)
		{
#if _x64
			if (*(uint8_t*)address != 0xE9)
			{
				throw std::exception("not a jump");
			}
#else
			if (*(uint8_t*)address != 0xE9)
			{
				throw std::exception("not a call");
			}
#endif
			_address = address;
		}

		void inject(R(*target)(Args...))
		{
			hooking_helpers::CallStub<R, Args...> stub(target);

			_assembly = std::make_unique<hooking_helpers::AssemblyGen>(stub);

			uintptr_t addressOffset = 1;

			// store original
			int64_t origAddress = *(int32_t*)(_address + addressOffset);
			origAddress += (4 + addressOffset);
			origAddress += _address;

			m_origAddress = (R(*)(Args...))origAddress;
#pragma warning(push)
#pragma warning(disable : 4311 4302)
#if _x64
			ud_t ud;
			ud_init(&ud);

			ud_set_mode(&ud, 64);

			intptr_t addressPtr = ((intptr_t)_assembly->GetCode() - (intptr_t)_address - (4 + addressOffset));
			int32_t address = static_cast<int32_t>((intptr_t)_assembly->GetCode() - (intptr_t)_address - (4 + addressOffset));

			if (addressPtr != address)
			{
				assert(false);
			}
			else
			{
				// Write a jump rax to the end instead of the call
				uint16_t data = 0xE0FF;
				memcpy((void*)((uintptr_t)_assembly->GetCode() + (uintptr_t)_assembly->GetSize() - 2), (void*)&data, 2);

				// Just replace a nop with a int 3 to debug the hook call assembly code
				//BYTE bData = 0xCC;
				//memcpy((void*)((uintptr_t)_assembly->GetCode()), (void*)&bData, 1);

				// Patch call opcode so its not a call to another DLL
				hooking_helpers::put<int32_t>(_address + addressOffset, address);
			}
#else
			// TODO: add all the checks
			intptr_t addressPtr = ((intptr_t)_assembly->GetCode() - (intptr_t)_address - (4 + addressOffset));
			hooking_helpers::put<int32_t>(_address + addressOffset, address);
#endif
#pragma warning(pop)
		}

		R call()
		{
			return ((R(*)())m_origAddress)();
		}

		R call(Args... args)
		{
			return m_origAddress(args...);
		}
	};

	template<typename R, typename... Args>
	class inject_call
	{
	private:
		R(*m_origAddress)(Args...);

		uintptr_t _address = 0;

		std::unique_ptr<hooking_helpers::AssemblyGen> _assembly;
	public:
		inject_call(uintptr_t address)
		{
#if _x64
			if (*(uint16_t*)address != 0x15FF && (*(uint8_t*)address != 0xE8))
			{
				throw std::exception("not a call");
			}
#else
			if (*(uint8_t*)address != 0xE8)
			{
				throw std::exception("not a call");
			}
#endif
			_address = address;
		}

		void inject(R(*target)(Args...))
		{
			hooking_helpers::CallStub<R, Args...> stub(target);

			_assembly = std::make_unique<hooking_helpers::AssemblyGen>(stub);

			uintptr_t addressOffset = 1;

			if (*(uint8_t*)_address != 0xE8)
			{
				addressOffset = 2;
			}

			// store original
			int64_t origAddress = *(int32_t*)(_address + addressOffset);
			origAddress += (4 + addressOffset);
			origAddress += _address;

			m_origAddress = (R(*)(Args...))origAddress;
#pragma warning(push)
#pragma warning(disable : 4311 4302)
#if _x64
			ud_t ud;
			ud_init(&ud);

			ud_set_mode(&ud, 64);

			intptr_t addressPtr = ((intptr_t)_assembly->GetCode() - (intptr_t)_address - (4 + addressOffset));
			int32_t address = static_cast<int32_t>((intptr_t)_assembly->GetCode() - (intptr_t)_address - (4 + addressOffset));

			if (addressPtr != address)
			{
				assert(false);
			}
			else
			{
				// Write a jump rax to the end instead of the call
				WORD data = 0xE0FF;
				memcpy((void*)((uintptr_t)_assembly->GetCode() + (uintptr_t)_assembly->GetSize() - 2), (void*)&data, 2);

				// Just replace a nop with a int 3 to debug the hook call assembly code
				//BYTE bData = 0xCC;
				//memcpy((void*)((uintptr_t)_assembly->GetCode()), (void*)&bData, 1);

				// Patch call opcode so its not a call to another DLL
				if (*(uint16_t*)_address == 0x15FF)
				{
					uint16_t d = 0xE890;
					hooking_helpers::put<int16_t>(_address, d);
				}

				hooking_helpers::put<int32_t>(_address + addressOffset, address);
			}
#else
			// TODO: add all the checks
			intptr_t addressPtr = ((intptr_t)_assembly->GetCode() - (intptr_t)_address - (4 + addressOffset));
			hooking_helpers::put<int32_t>(_address + addressOffset, address);
#endif
#pragma warning(pop)
		}

		template<size_t _Args = sizeof...(Args)>
		typename std::enable_if < (_Args > 0), R > ::type
			call()
		{
			return ((R(*)())m_origAddress)();
		}

		R call(Args... args)
		{
			return m_origAddress(args...);
		}
	};

	inline void set_import(const std::string &name, uintptr_t func)
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(hooking::hooking_helpers::GetExecutableAddress());
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			throw std::runtime_error("Invalid DOS Signature");
		}

		PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)((hooking::hooking_helpers::GetExecutableAddress() + (dosHeader->e_lfanew * sizeof(char))));
		if (header->Signature != IMAGE_NT_SIGNATURE)
		{
			throw std::runtime_error("Invalid NT Signature");
		}

		//BuildImportTable
		PIMAGE_DATA_DIRECTORY directory = &header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		if (directory->Size > 0)
		{
			PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(header->OptionalHeader.ImageBase + directory->VirtualAddress);
			for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++)
			{
				HMODULE handle = LoadLibraryA((LPCSTR)(header->OptionalHeader.ImageBase + importDesc->Name));

				if (handle == NULL)
				{
					SetLastError(ERROR_MOD_NOT_FOUND);
					break;
				}

				uintptr_t *thunkRef = (uintptr_t *)(header->OptionalHeader.ImageBase + importDesc->OriginalFirstThunk);
				FARPROC *funcRef = (FARPROC *)(header->OptionalHeader.ImageBase + importDesc->FirstThunk);

				if (!importDesc->OriginalFirstThunk) // no hint table
				{
					thunkRef = (uintptr_t *)(header->OptionalHeader.ImageBase + importDesc->FirstThunk);
				}


				for (; *thunkRef, *funcRef; thunkRef++, funcRef++)
				{
					if (!IMAGE_SNAP_BY_ORDINAL(*thunkRef))
					{
						std::string import = (LPCSTR)&((PIMAGE_IMPORT_BY_NAME)(header->OptionalHeader.ImageBase + (*thunkRef)))->Name;

						if (import == name)
						{
							DWORD oldProtect;
							VirtualProtect((void*)funcRef, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect);

							*funcRef = (FARPROC)func;

							VirtualProtect((void*)funcRef, sizeof(FARPROC), oldProtect, &oldProtect);


						}
					}
				}
			}
		}
	}

	template<typename R, typename...Args>
	static R func_call(uint64_t addr, Args... args)
	{
		return ((R(*)(Args...))(addr))(args...);
	}

	static std::multimap<uint64_t, uintptr_t> g_hints;

	// Patterns
	inline namespace patterns
	{
		// should be in another include
		namespace pattern_helpers
		{
			static void GenerateMaskAndData(const std::string &pattern, std::string &mask, std::string &data)
			{
				const static std::locale loc;

				std::stringstream dataStream;
				std::stringstream maskStream;
#pragma warning(push)
#pragma warning(disable: 4239)
				for (auto &ch = pattern.begin(); ch != pattern.end(); ++ch)
				{
					if (*ch == '?')
					{
						dataStream << '\x00';
						maskStream << '?';
					}
					else if (std::isalnum(*ch, loc))
					{
						auto ch1 = *ch;
						auto ch2 = *(++ch);
						char str[] = { ch1,  ch2 };
						char digit = static_cast<char>(strtol(str, nullptr, 16));
						dataStream << digit;
						maskStream << 'x';
					}
				}
#pragma warning(pop)

				data = dataStream.str();
				mask = maskStream.str();
			}
		};

		class match
		{
		private:
			void *_address = nullptr;
			intptr_t _offset = 0;

		public:
			match(void *address)
				: _address(address)
			{ }

			match& adjust(intptr_t offset)
			{
				_offset = offset;
				return *this;
			}

			template<typename T>
			T* cast()
			{
				return reinterpret_cast<T*>(static_cast<char*>(_address) + _offset);
			}

			template<>
			void* cast()
			{
				return reinterpret_cast<void*>(static_cast<char*>(_address) + _offset);
			}

			intptr_t origaddr()
			{
				return reinterpret_cast<intptr_t>(_address);
			}

			intptr_t addr()
			{
				return reinterpret_cast<intptr_t>(static_cast<char*>(_address) + _offset);
			}
		};

		class pattern_cache : public singleton<pattern_cache>
		{
		private:
			std::unordered_map<std::string, std::vector<match>> _cache;

		public:
			void add(const std::string &pattern, const std::vector<match> &matches)
			{
				_cache[pattern] = matches;
			}

			bool contains(const std::string &pattern)
			{
				return (_cache.find(pattern) != _cache.end());
			}

			std::vector<match> & get(const std::string &pattern)
			{
				if (!contains(pattern))
				{
					return _cache[pattern];
				}
				else
				{
					return _cache[pattern];
				}
			}
		};

		class ExecutableInfo : public singleton<ExecutableInfo>
		{
		private:
			hooking_helpers::executable_info exe_info;

		public:
			ExecutableInfo() = default;
			virtual ~ExecutableInfo() = default;

			void EnsureExecutableInfo()
			{
				exe_info.EnsureInit(hooking::hooking_helpers::GetExecutableAddress());
			}

			hooking_helpers::executable_info& GetExecutableInfo()
			{
				return exe_info;
			}

			void SetExecutableInfo(hooking_helpers::executable_info& info)
			{
				exe_info = info;
				hooking::hooking_helpers::SetExecutableAddress(info.GetExecutableAddress());
			}
		};

		static hooking_helpers::executable_info exe_info;

		/*extern "C" void __declspec(dllimport) */void PatternSaveHint(uint64_t hash, uintptr_t hint);
		/*extern "C" void __declspec(dllimport) */void SetPatternSavePath(const std::wstring& path);

		class pattern
		{
		private:
			std::string _data;
			std::string _mask;
			std::string _pattern;
			uint64_t _hash = 0;
			bool _matched = false;
			size_t _size = 0;
			std::vector<match> _matches;

			static void _hint(uint64_t hash, uintptr_t address)
			{
				auto range = g_hints.equal_range(hash);

				for (auto it = range.first; it != range.second; it++)
				{
					if (it->second == address)
					{
						return;
					}
				}

				g_hints.insert(std::make_pair(hash, address));
			}
		public:
			pattern(const std::string &_pattern)
				: _pattern(_pattern)
			{
				ExecutableInfo::instance()->EnsureExecutableInfo();

				static bool first = true;
				if (first)
				{
					std::wstring hintsFile = ExecutableInfo::instance()->GetExecutableInfo().GetWorkingPath();
					hintsFile += L"hints.dat";

					FILE *hints = nullptr;
					_wfopen_s(&hints, hintsFile.c_str(), L"rb");

					if (hints)
					{
						while (!feof(hints))
						{
							uint64_t hash;
							uintptr_t hint;

							fread(&hash, 1, sizeof(hash), hints);
							fread(&hint, 1, sizeof(hint), hints);

							_hint(hash, hint);
						}

						fclose(hints);
					}
					first = false;
				}


				pattern_helpers::GenerateMaskAndData(_pattern, _mask, _data);

				_hash = fnv_1()(_pattern);

				// if there's hints, try those first
				auto range = g_hints.equal_range(_hash);

				if (range.first != range.second)
				{
					std::for_each(range.first, range.second, [&](const std::pair<uint64_t, uintptr_t>& hint)
					{
						for (auto& section : ExecutableInfo::instance()->GetExecutableInfo())
						{
							if (section.begin() <= hint.second && hint.second < (section.end() - _mask.size()))
							{
								doMatch(hint.second);
							}
						}
					});

					// if the hints succeeded, we don't need to do anything more
					if (_matches.size() > 0)
					{
						_matched = true;
						return;
					}
				}
			}

			pattern(const std::string &data, const std::string &mask)
				: _data(data),
				_mask(mask)
			{
				ExecutableInfo::instance()->EnsureExecutableInfo();
			}

			bool doMatch(uintptr_t offset)
			{
				const char *pattern_ = _data.c_str();
				const char *mask = _mask.c_str();

				char *ptr = reinterpret_cast<char*>(offset);

				for (size_t i = 0; i < _mask.size(); i++)
				{
					if (mask[i] == '?')
					{
						continue;
					}

					if (_data.length() < i || pattern_[i] != ptr[i])
					{
						return false;
					}
				}

				_matches.push_back(match(ptr));

				return true;
			}

			bool search(bool onlyFirst)
			{
				UNREFERENCED_PARAMETER(onlyFirst);
				// check if SSE 4.2 is supported
				int32_t cpuid[4];
				__cpuid(cpuid, 0);

				bool sse42 = false;

				if (_mask.size() <= 16)
				{
					if (cpuid[0] >= 1)
					{
						__cpuidex(cpuid, 1, 0);

#pragma warning(push)
#pragma warning(disable : 4800)
						sse42 = static_cast<bool>((cpuid[2] & (1 << 20)));
#pragma warning(pop)
					}
				}

				if (!ExecutableInfo::instance()->GetExecutableInfo().IsSSEPatternSearchingEnabled())
				{
					sse42 = false;
				}

				std::vector<std::future<std::vector<match>>> futureHandles;

				if (!sse42)
				{
					OutputDebugStringA("Slow mode\n");
					for (auto& section : ExecutableInfo::instance()->GetExecutableInfo())
					{
						auto secSize = section.end() - section.begin();
						if (secSize > 1)
						{
							auto partSize = secSize / 8;
							if (partSize < 1) {
								partSize = 1;
							}
							auto rest = secSize % partSize;
							for (uintptr_t i = section.begin(); i < section.end() - rest; i += partSize)
							{
								auto handle = std::async(std::launch::async, [&](uintptr_t start, uintptr_t end) -> std::vector<match> {
									std::vector<match> vecMatches;
									for (uintptr_t offset = start; offset < end; ++offset)
									{
										if (doMatch(offset))
										{
											vecMatches.push_back(match(reinterpret_cast<char*>(offset)));
										}
									}
									return vecMatches;
								}, i, i + partSize);

								futureHandles.push_back(std::move(handle));
							}
						}
					}
				}
				else
				{
					__declspec(align(16)) char desiredMask[16] = { 0 };

					for (int i = 0; i < _mask.size(); i++)
					{
						desiredMask[i / 8] |= ((_mask[i] == '?') ? 0 : 1) << (i % 8);
					}

					__m128i mask = _mm_load_si128(reinterpret_cast<const __m128i*>(desiredMask));
					__m128i comparand = _mm_loadu_si128(reinterpret_cast<const __m128i*>(_data.c_str()));

					// We ignore onlyFirst here, as we try to optimize it using threads :D

					for (auto& section : ExecutableInfo::instance()->GetExecutableInfo())
					{
						auto secSize = section.end() - section.begin();

						auto partSize = secSize / 8;
						auto rest = secSize % partSize;
						for (uintptr_t i = section.begin(); i < (section.end() - rest); i += partSize)
						{
							auto _end = i + partSize;
							if (_end > (section.end() - 16))
								_end = section.end() - 16;

							auto handle = std::async(std::launch::async, [&](uintptr_t start, uintptr_t end) -> std::vector<match> {
								std::vector<match> vecMatches;
								for (uintptr_t offset = start; offset < end; ++offset)
								{
									__m128i value = _mm_loadu_si128(reinterpret_cast<const __m128i*>(offset));
									__m128i result = _mm_cmpestrm(value, 16, comparand, static_cast<int>(_data.size()), _SIDD_CMP_EQUAL_EACH);

									// as the result can match more bits than the mask contains
									__m128i matches = _mm_and_si128(mask, result);
									__m128i equivalence = _mm_xor_si128(mask, matches);

									if (_mm_test_all_zeros(equivalence, equivalence))
									{
										//PatternSaveHint(_hash, offset);
										vecMatches.push_back(match(reinterpret_cast<char*>(offset)));
									}
								}

								return vecMatches;
							}, i, _end);

							futureHandles.push_back(std::move(handle));
						}
					}
				}


				_matches.clear();

				for (auto &handle : futureHandles)
				{
					auto matches = handle.get();

					for (auto &match : matches)
					{
						SetPatternSavePath(ExecutableInfo::instance()->GetExecutableInfo().GetWorkingPath());
						PatternSaveHint(_hash, match.addr());
					}

					_matches.insert(_matches.end(), matches.begin(), matches.end());
				}

				return true;
			}


			match& get(int index)
			{
				if (pattern_cache::instance()->contains(_pattern))
				{
					return pattern_cache::instance()->get(_pattern)[index];
				}
				else
				{
					if (!_matched)
					{
						search(index == 0);
					}

					pattern_cache::instance()->add(_pattern, _matches);

					if (matches().size() == 0)
					{
						MessageBoxA(NULL, "Could not find pattern! Game will crash now!", "Exception", MB_OK);
						throw std::runtime_error("Could not find pattern!");
					}

					return pattern_cache::instance()->get(_pattern)[index];
				}
			}

			std::vector<match> matches()
			{
				if (pattern_cache::instance()->contains(_pattern))
				{
					return pattern_cache::instance()->get(_pattern);
				}
				else 
				{
					if (!_matched)
					{
						search(false);
					}

					pattern_cache::instance()->add(_pattern, _matches);
					return pattern_cache::instance()->get(_pattern);
				}
			}
		};
	};
};