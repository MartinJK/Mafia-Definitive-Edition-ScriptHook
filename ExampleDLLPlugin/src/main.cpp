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

#include <Export.h>
#include <Windows.h>
#include <map>
#include <vector>
#include <main.h>

#include <thread>
#include <chrono>

#include <hooking/hooking.h>

ExampleDLLPlugin::ExampleDLLPlugin()
{
	// This code is necessary for every plugin, as it has its own hooking instance!!
	hooking::hooking_helpers::SetExecutableAddress((uintptr_t)GetModuleHandle(0));
	hooking::ExecutableInfo::instance()->EnsureExecutableInfo();
	hooking::ExecutableInfo::instance()->GetExecutableInfo().SetSSEPatternSearching(false); // common issues with steam..
}

uint32_t WINAPI ExampleDLLPlugin::ProcessThread(LPVOID)
{
	static ExampleDLLPlugin* instance = ExampleDLLPlugin::instance(); // calls ctor
	while (instance->GetRunState())
	{
		static auto init = false;
		if (!init)
		{
			init = true;
		//	ExampleDLLPlugin::instance()->Patch(); // Disabled as not everybody wants to patch that..
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		std::this_thread::yield();
	}

	return 0;
}

void ExampleDLLPlugin::Patch()
{
	auto loadingScreenPatch = hooking::pattern("40 55 53 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ?");
	auto matches = loadingScreenPatch.matches().size();
	if (matches == 1) { // Check match count because if the plugin got reloaded, the pattern does no longer exist because we have overwritten it...
		auto addr = loadingScreenPatch.get(0).origaddr();
		hooking::put<uint32_t>(addr, 0x90C300B0);
	}
}

void ExampleDLLPlugin::Shutdown()
{
	this->m_bRunning = false;
}

bool ExampleDLLPlugin::GetRunState()
{
	return this->m_bRunning;
}

extern "C" {
	__declspec(dllexport) bool StartPlugin(lua_State *)
	{
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ExampleDLLPlugin::ProcessThread, 0, 0, 0);
		return true;
	}

	__declspec(dllexport) bool StopPlugin()
	{
		ExampleDLLPlugin::instance()->Shutdown();
		return true;
	}
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
	return TRUE;
}