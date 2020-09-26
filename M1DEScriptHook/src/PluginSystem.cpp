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

#include <PluginSystem.h>
#include <Windows.h>
#include <string>
#include <Common.h>
#include <M1DEScriptHook.h>

void PluginSystem::LoadPlugins()
{
	M1DEScriptHook::instance()->Log(__FUNCTION__);

	WIN32_FIND_DATA data;
	HANDLE file = FindFirstFileEx("plugins\\*.dll", FindExInfoStandard, &data, FindExSearchNameMatch, 0, 0);

	if (file >= (HANDLE)0xFFFFFFFFFFFFFFFF) {
		return;
	}

	do {
		std::string path = "plugins\\";
		path += data.cFileName;

		HMODULE lib = LoadLibraryA(path.c_str());
		if (!lib) {
			M1DEScriptHook::instance()->Log(std::string(__FUNCTION__ " failed to load plugin (LoadLibrary) " + path).c_str());
			continue;
		}

		StartPlugin_t pStartPlugin = (StartPlugin_t)GetProcAddress(lib, "StartPlugin");
		if (!pStartPlugin) {
			M1DEScriptHook::instance()->Log(std::string(__FUNCTION__ " failed to find start routine in plugin " + path).c_str());
			continue;
		}

		StopPlugin_t pStopPlugin = (StopPlugin_t)GetProcAddress(lib, "StopPlugin");
		if (!pStopPlugin) {
			M1DEScriptHook::instance()->Log(std::string(__FUNCTION__ " failed to find stop routine in plugin " + path).c_str());
			continue;
		}

		Plugin plugin;
		plugin.name = data.cFileName;
		plugin.pStartPlugin = pStartPlugin;
		plugin.pStopPlugin = pStopPlugin;
		plugins.push_back(plugin);

		M1DEScriptHook::instance()->Log(std::string(__FUNCTION__ " loaded plugin " + plugin.name).c_str());

	} while (file && FindNextFile(file, &data));
}

void PluginSystem::UnloadPlugins()
{
	M1DEScriptHook::instance()->Log(__FUNCTION__);
	this->StopPlugins();

	for (auto& plugin : this->plugins) {
		M1DEScriptHook::instance()->Log(std::string(__FUNCTION__ " unloaded plugin " + plugin.name).c_str());
		FreeLibrary(GetModuleHandleA(plugin.name.c_str()));
	}

	this->plugins.clear();
}

void PluginSystem::ReloadPlugins()
{
	M1DEScriptHook::instance()->Log(__FUNCTION__);
	if (this->plugins.size() != 0) {
		this->UnloadPlugins();
	}

	this->LoadPlugins();
	this->StartPlugins();
}

void PluginSystem::StartPlugins()
{
	M1DEScriptHook::instance()->Log(__FUNCTION__);
#if 0
	for (auto& plugin : this->plugins) {
		plugin.pStartPlugin(LuaStateManager::instance()->GetState());
	}
#else
	for (uint32_t i = 0; i < plugins.size(); ++i) {
		plugins[i].pStartPlugin(LuaStateManager::instance()->GetState());
	}
#endif
}

void PluginSystem::StopPlugins()
{
	M1DEScriptHook::instance()->Log(__FUNCTION__);
#if 0
	for (auto& plugin : this->plugins) {
		plugin.pStopPlugin();
	}
#else
	for (uint32_t i = 0; i < plugins.size(); ++i) {
		plugins[i].pStopPlugin();
	}
#endif
}

void PluginSystem::RelaunchPlugins()
{
	this->StopPlugins();
	this->StartPlugins();
}
