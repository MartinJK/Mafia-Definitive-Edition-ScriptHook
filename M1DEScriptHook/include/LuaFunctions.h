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

#include <M1DEScriptHook.h>
#include <Export.h>
#include <singleton.h>

class LuaFunctions : public singleton<LuaFunctions> {
private:
	bool m_mainScriptMachineReady = false;
	C_ScriptGameMachine *m_pMainGameScriptMachine = nullptr;
	std::map<unsigned char, std::string> keyBinds = {};

	static int32_t PrintToLog(lua_State*);
	static int32_t BindKey(lua_State*);
	static int32_t UnbindKey(lua_State*);
	static int32_t DelayBuffer(lua_State*);
	static int32_t FNV32a(lua_State*);
public:
	LuaFunctions();
	virtual ~LuaFunctions() = default;

	C_ScriptGameMachine *GetMainGameScriptMachine();
	bool IsMainScriptMachineReady();
	bool LoadPointers();
	bool Setup();
	void Process();
};

__declspec(dllexport) int luaL_loadbuffer_(lua_State *L, char *buff, size_t size, char *name);
__declspec(dllexport) int lua_pcall_(lua_State *L, int nargs, int nresults, int errfunc);
__declspec(dllexport) const char *lua_tostring_(lua_State *L, int32_t idx);
__declspec(dllexport) uint32_t lua_isstring_(lua_State *L, int32_t idx);
__declspec(dllexport) lua_State *lua_newthread_(lua_State *L);
__declspec(dllexport) void logPointer(std::string name, uint64_t pointer);
