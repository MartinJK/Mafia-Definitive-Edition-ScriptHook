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

#include <windows.h>
#include <stdio.h>
#include <Common.h>

int main()
{
	uint32_t pid = GetHandleByProcessName("mafiadefinitiveedition.exe");
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	if (pid) {
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	}
	else {
		STARTUPINFO si;
		PROCESS_INFORMATION pi;

		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));

		CreateProcess(0, "mafiadefinitiveedition.exe", 0, 0, false, NORMAL_PRIORITY_CLASS, 0, 0, &si, &pi);

		hProcess = pi.hProcess;
	}

	if (hProcess == INVALID_HANDLE_VALUE) {
		log("Process could not be opened. Did you use  administrator privileges (run as administrator)?");
		return 1;
	}

	HMODULE hLibrary = InjectDll(hProcess, "M1DEScriptHook.dll");
	if(!hLibrary) {
		log("Library could not be loaded into process.");
		return 1;
	}

	CloseHandle(hProcess);
	return 0;
}

