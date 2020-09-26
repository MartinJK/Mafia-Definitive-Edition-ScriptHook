// Base Application taken from Klusark (GPLv2)
// https://code.google.com/archive/p/mafia2injector/

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

#include <Common.h>
#include <psapi.h>
#include <fstream>
#include <sstream>

#pragma comment(lib, "Psapi.lib")

uint32_t GetHandleByProcessName(const std::string &name)
{
	uint32_t result = 0;
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i = 0;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
		return 0;
	}

	cProcesses = cbNeeded / sizeof(DWORD);

	for (i = 0; i < cProcesses; ++i) {
		if (aProcesses[i] == 0) {
			continue;
		}

		DWORD processID = aProcesses[i];
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
		TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

		if (NULL != hProcess) {
			HMODULE hMod = NULL;
			DWORD cbNeeded_;

			if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded_)) {
				GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
			}

			if (strcmp(ToLower(szProcessName).c_str(), ToLower(name).c_str()) == 0) {
				result = processID;
				break;
			}
		}
		CloseHandle(hProcess);
	}

	return result;
}

std::string ToLower(const std::string &str)
{
	std::string output;
	int32_t len = static_cast<int32_t>(str.length());
	for (int32_t i = 0; i < len; ++i) {
		output += (uint8_t)tolower(str[i]);
	}
	return output;
}

void log(std::string message)
{
	std::fstream file("ScriptHook.log", std::ios::out | std::ios::app);
	file << message;
	file << "\n";
	file.close();
}

HMODULE InjectDll(HANDLE hProcess, const char *DllName)
{
	size_t DllNameLength = strlen(DllName) + 1;
	PVOID mem = VirtualAllocEx(hProcess, NULL, DllNameLength, MEM_COMMIT, PAGE_READWRITE);
	
	if (mem == NULL)
	{
		log("can't allocate memory in that pid");
		CloseHandle(hProcess);
		return 0;
	}

	if (WriteProcessMemory(hProcess, mem, (void*)DllName, DllNameLength, NULL) == 0)
	{
		log("can't write to memory in that pid\n");
		VirtualFreeEx(hProcess, mem, DllNameLength, MEM_RELEASE);
		CloseHandle(hProcess);
		return 0;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "LoadLibraryA"), mem, 0, NULL);
	if (hThread == INVALID_HANDLE_VALUE)
	{
		log("can't create a thread in that pid\n");
		VirtualFreeEx(hProcess, mem, DllNameLength, MEM_RELEASE);
		CloseHandle(hProcess);
		return 0;
	}

	HMODULE hLibrary = NULL;
	if (!GetExitCodeThread(hThread, (LPDWORD)&hLibrary))
	{
		std::stringstream ss;
		ss << "can't get exit code for thread GetLastError() = ";
		ss << GetLastError();
		log(ss.str());
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, mem, DllNameLength, MEM_RELEASE);
		CloseHandle(hProcess);
		return 0;
	}

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, mem, DllNameLength, MEM_RELEASE);

	if (hLibrary == NULL)
	{
		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "GetLastError"), 0, 0, NULL);
		if (hThread == INVALID_HANDLE_VALUE)
		{
			log("LoadLibraryA returned NULL and can't get last error.");
			CloseHandle(hProcess);
			return 0;
		}

		WaitForSingleObject(hThread, INFINITE);
		DWORD error;
		GetExitCodeThread(hThread, &error);

		CloseHandle(hThread);

		std::stringstream ss;
		ss << "LoadLibrary return NULL, GetLastError() is ";
		ss << error;
		log(ss.str());
		CloseHandle(hProcess);
		return false;
	}

	return hLibrary;
}