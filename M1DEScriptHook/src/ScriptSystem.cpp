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

#include <ScriptSystem.h>
#include <Windows.h>
#include <string>
#include <Common.h>
#include <M1DEScriptHook.h>

void ScriptSystem::LoadScripts()
{
	//scripts.clear(); // only add this when we unload scripts..

	M1DEScriptHook::instance()->Log(__FUNCTION__);

	WIN32_FIND_DATA data;
	HANDLE file = FindFirstFileEx("scripts\\*.lua", FindExInfoStandard, &data, FindExSearchNameMatch, 0, 0);

	if (file >= (HANDLE)0xFFFFFFFFFFFFFFFF) {
		return;
	}

	do {
		std::string filename = data.cFileName;
		std::string path = "scripts/" + filename;

		// Ignore the file if it starts with _ (underscore)
		if (filename[0] == '_') {
			M1DEScriptHook::instance()->Log(__FUNCTION__ " ignored script " + filename);
		}
		else {
			scripts.push_back(path);

			M1DEScriptHook::instance()->LoadScript(path);

			M1DEScriptHook::instance()->Log(__FUNCTION__ " loaded script " + filename);
		}
	} while (file && FindNextFile(file, &data));
}

void ScriptSystem::UnloadScripts()
{
	M1DEScriptHook::instance()->Log(__FUNCTION__);
	// TBD
}

void ScriptSystem::ReloadScripts()
{
	M1DEScriptHook::instance()->Log(__FUNCTION__);
	if (this->scripts.size() != 0) {
		this->UnloadScripts();
	}

	this->LoadScripts();
}
