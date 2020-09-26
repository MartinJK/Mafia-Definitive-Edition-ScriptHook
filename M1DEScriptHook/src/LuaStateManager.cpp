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

#include <LuaStateManager.h>
#include <Windows.h>
#include <LuaFunctions.h>
#include <M1DEScriptHook.h>
#include <ScriptSystem.h>
#include <chrono>
#include <thread>

LuaStateManager::LuaStateManager()
{
	m_pLuaState = nullptr;
	m_bEnded = false;
}

LuaStateManager::~LuaStateManager()
{
	m_bEnded = true;
}

void LuaStateManager::StartThread()
{
	M1DEScriptHook::instance()->Log(__FUNCTION__);
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)LuaStateManager::WatcherThread, 0, 0, 0);
}

void LuaStateManager::StateChanged(lua_State *L)
{
	M1DEScriptHook::instance()->Log(__FUNCTION__);

	++this->m_stateChangeCount;
	this->m_pLuaState = L;

	LuaFunctions::instance()->Setup();

	this->m_stateChangeCount == 1 ? PluginSystem::instance()->StartPlugins() :PluginSystem::instance()->RelaunchPlugins();
	ScriptSystem::instance()->ReloadScripts();
}

lua_State* LuaStateManager::GetState()
{
	if (this->m_pLuaState) {
		return lua_newthread_(this->m_pLuaState);
	}
	else {
		return nullptr;
	}
}

bool LuaStateManager::IsStateGood(lua_State *L)
{
	return L != nullptr;
}

bool LuaStateManager::HasEnded()
{
	return this->m_bEnded;
}

uint32_t WINAPI LuaStateManager::WatcherThread(LPVOID) {
	do {
		std::this_thread::sleep_for(std::chrono::seconds(1));
	} while (!LuaFunctions::instance()->IsMainScriptMachineReady());

	static lua_State *lastState = nullptr;
	static C_ScriptGameMachine *machine = nullptr;
	static LuaStateManager *instance = LuaStateManager::instance();

	while (!instance->HasEnded()) {
		lua_State* nstate = GetL(machine);
		if (nstate != lastState && nstate) {
			instance->StateChanged(nstate);
			lastState = nstate;
		}

		std::this_thread::sleep_for(std::chrono::seconds(10));
		std::this_thread::yield();
	}
	return 0;
}
