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
#include <Winsock2.h>
#include <Windows.h>
#include <cstdint>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <wchar.h>
#include <string>
#include <hooking/hooking.h>

namespace hooking
{
	namespace patterns
	{
		static std::wstring savePath;
		/*extern "C" __declspec(dllexport) */void SetPatternSavePath(const std::wstring &path)
		{
			savePath = path;
		}

		/*extern "C" __declspec(dllexport) */void PatternSaveHint(uint64_t hash, uintptr_t hint)
		{
			if (savePath.empty())
			{
				savePath = hooking::ExecutableInfo::instance()->GetExecutableInfo().GetWorkingPath();
			}

			std::wstring hintsFile = savePath;
			hintsFile += L"hints.dat";

			FILE* hints = nullptr;
			_wfopen_s(&hints, hintsFile.c_str(), L"ab");

			if (hints)
			{
				fwrite(&hash, 1, sizeof(hash), hints);
				fwrite(&hint, 1, sizeof(hint), hints);

				fclose(hints);
			}
		}
	}

	namespace hooking_helpers
	{
		static uintptr_t executableAddress = 0;
		static const uintptr_t hookSectionOffset = 0x6000000;

		/*extern "C" EXPORT */void  SetExecutableAddress(uintptr_t address)
		{
			executableAddress = address;
		}

		/*extern "C" EXPORT */uintptr_t  GetExecutableAddress()
		{
			return executableAddress;
		}

		/*extern "C" EXPORT */void*  AllocInHookSection(size_t size)
		{
			static bool firstCall = true;

			auto addr = executableAddress + hookSectionOffset;
			if (firstCall)
			{
				DWORD oldProtect;
				VirtualProtect((LPVOID)(addr), size, PAGE_READWRITE, &oldProtect);
				*(uint32_t*)(addr) = sizeof(uint32_t);
				firstCall = false;
			}

			auto code = (LPVOID)(addr + *(uint32_t*)(addr));
			DWORD oldProtect;
			VirtualProtect(code, size, PAGE_EXECUTE_READWRITE, &oldProtect);
			*(uint32_t*)(addr) += static_cast<uint32_t>(size);
			return code;
		}
	}
}