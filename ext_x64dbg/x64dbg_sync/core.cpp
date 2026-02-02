/*
Copyright (C) 2016-2021, Alexandre Gazet.

Copyright (C) 2014-2015, Quarkslab.

This file is part of ret-sync.

ret-sync is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "core.h"
#include <windows.h>
#include <stdio.h>
#include <map>
#include <psapi.h>
#include <strsafe.h>
#include "tunnel.h"

#include "json.hpp"


// Default host value is locahost
static const CHAR *g_DefaultHost = "127.0.0.1";
static const CHAR *g_DefaultPort = "9190";
static const BOOL g_EnableHyperSyncByDefault = TRUE;

// Command polling feature
static HANDLE g_hPollTimer = INVALID_HANDLE_VALUE;
static HANDLE g_hSyncTimer = INVALID_HANDLE_VALUE;
static HANDLE g_hPollCompleteEvent = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_CritSectPollRelease;

// Auto-connect feature
static HANDLE g_hAutoConnectTimer = INVALID_HANDLE_VALUE;
BOOL g_AutoConnectEnabled = TRUE;  // Enabled by default
static BOOL g_UserDisabledSync = FALSE;  // Track if user explicitly disabled sync

// Debuggee's state;
ULONG_PTR g_Offset = NULL;
ULONG_PTR g_Base = NULL;
REGDUMP_AVX512 regs;

// Synchronisation mode
static BOOL g_SyncAuto = true;

// HyperSync state
BOOL g_HyperSyncEnabled = FALSE;
static BOOL g_RemoteLocationChange = FALSE;

// Buffer used to solve symbol's name
static CHAR g_NameBuffer[MAX_MODULE_SIZE];

// Buffer used generate commands
static CHAR g_CommandBuffer[MAX_COMMAND_LINE_SIZE];

static std::map<std::string, std::pair<ULONG64,ULONG64>> g_LastModBaseRVAMap = std::map<std::string, std::pair<ULONG64,ULONG64>>();
HRESULT
LoadConfigurationFile()
{
	DWORD count = 0;
	HRESULT hRes = S_OK;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	CHAR lpProfile[MAX_PATH] = { 0 };
	LPTSTR lpConfHost = NULL;
	LPTSTR lpConfPort = NULL;

	count = GetEnvironmentVariable("userprofile", lpProfile, MAX_PATH);
	if (count == 0 || count > MAX_PATH) {
		return E_FAIL;
	}

	hRes = StringCbCat(lpProfile, MAX_PATH, CONF_FILE);
	if FAILED(hRes) {
		return E_FAIL;
	}

	hFile = CreateFile(lpProfile, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		_plugin_logprintf("[sync] Configuration file not present, using default values\n");
		return E_FAIL;
	}

	_plugin_logprintf("[sync] Loading configuration file: \"%s\"\n", lpProfile);
	CloseHandle(hFile);

	lpConfHost = (LPTSTR)malloc(MAX_PATH);
	lpConfPort = (LPTSTR)malloc(MAX_PATH);
	if (lpConfHost == NULL || lpConfPort == NULL) {
		goto failed;
	}

	count = GetPrivateProfileString("INTERFACE", "host", "127.0.0.1", lpConfHost, MAX_PATH, lpProfile);
	if ((count > 0) && (count < (MAX_PATH - 2))) {
		g_DefaultHost = lpConfHost;
		_plugin_logprintf("[sync]    -> set HOST to %s\n", g_DefaultHost);
	}

	count = GetPrivateProfileString("INTERFACE", "port", "9190", lpConfPort, MAX_PATH, lpProfile);
	if ((count > 0) && (count < (MAX_PATH - 2))) {
		g_DefaultPort = lpConfPort;
		_plugin_logprintf("[sync]    -> set PORT to %s\n", g_DefaultPort);
	}

	return hRes;

failed:
	if (lpConfHost != NULL) { free(lpConfHost); }
	if (lpConfPort != NULL) { free(lpConfPort); }

	return E_FAIL;
}


// mimic IDebugRegisters::GetInstructionOffset
// returns the location of the current thread's current instruction.
HRESULT 
GetInstructionOffset(ULONG_PTR *cip)
{
	bool bRes = FALSE;
	*cip = 0;

	bRes = DbgGetRegDumpEx(&regs, sizeof(regs));
	if (!bRes) {
		_plugin_logprintf("[sync] failed to DbgGetRegDumpEx\n");
		return E_FAIL;
	}

	*cip = regs.regcontext.cip;
	return S_OK;
}

// Handle incoming RVA from IDA in HyperSync mode
HRESULT HandleRemoteRVA(PSTR modName, ULONG64 rva)
{
	HRESULT hRes = S_OK;
	ULONG_PTR modBase = 0;
	ULONG_PTR targetVA = 0;

	if (!g_HyperSyncEnabled)
		return hRes;

	modBase = DbgFunctions()->ModBaseFromName(modName);
	if (!modBase) {
		_plugin_logprintf("[sync] HyperSync: module %s not loaded\n", modName);
		return E_FAIL;
	}

	targetVA = modBase + (ULONG_PTR)rva;

	// Set flag to prevent echoing this back to IDA
	g_RemoteLocationChange = TRUE;

	// Navigate to the address in the disassembly window
	GuiDisasmAt(targetVA, targetVA);

#if VERBOSE >= 2
	_plugin_logprintf("[sync] HyperSync: navigated to %s+%llx (VA: %p)\n", 
		modName, rva, targetVA);
#endif

	return hRes;
}


// Update state and send info to client: eip module's base address, offset, name
HRESULT
UpdateState()
{
	HRESULT hRes = E_FAIL;
	DWORD dwRes = 0;
	ULONG_PTR PrevBase = g_Base;
	HANDLE hProcess = INVALID_HANDLE_VALUE;

	hRes = GetInstructionOffset(&g_Offset);
	if (FAILED(hRes))
		goto UPDATE_FAILURE;

	g_Base = DbgFunctions()->ModBaseFromAddr((duint)g_Offset);
	if (!g_Base)
	{
		_plugin_logprintf("[sync] UpdateState(%p): could not get module base...\n", g_Offset);
		goto UPDATE_FAILURE;
	}

#if VERBOSE >= 2
	_plugin_logprintf("[sync] UpdateState(%p): module base %p\n", g_Offset, g_Base);
#endif

	// Check if we are in a new module
	if ((g_Base != PrevBase) && g_SyncAuto)
	{
		hProcess = DbgGetProcessHandle();

		dwRes = GetModuleBaseNameA(hProcess, (HMODULE)g_Base, g_NameBuffer, MAX_MODULE_SIZE);
		if (dwRes == 0)
		{
			_plugin_logprintf("[sync] UpdateState(%p): could not get module name...\n", g_Offset);
			goto UPDATE_FAILURE;
		}

#if VERBOSE >= 2
		_plugin_logprintf("[sync] UpdateState(%p): module : \"%s\"\n", g_Offset, g_NameBuffer);
#endif

		hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", g_NameBuffer);
		if (FAILED(hRes)) {
			return hRes;
		}
	}

	hRes = TunnelSend("[sync]{\"type\":\"loc\",\"base\":%llu,\"offset\":%llu}\n", (ULONG64)g_Base, (ULONG64)g_Offset);

	return hRes;

UPDATE_FAILURE:
	// Inform the dispatcher that an error occured in the state update
	if (g_Base != NULL)
	{
		TunnelSend("[notice]{\"type\":\"dbg_err\"}\n");
		g_Base = NULL;
	}

	return hRes;
}


// Poll socket for incoming commands
HRESULT
PollCmd()
{
	BOOL bRes = FALSE;
	HRESULT hRes = S_OK;
	int NbBytesRecvd = 0;
	const int ch = 0xA;
	char *msg, *next, *orig = NULL;

	hRes = TunnelPoll(&NbBytesRecvd, &msg);

	if (FAILED(hRes)) {
		// Only print once a second
		static DWORD lastPrint = 0;
		if (lastPrint == 0 || GetTickCount() - lastPrint > 60000) {
			_plugin_logprintf("[sync] TunnelPoll failed\n");
			lastPrint = GetTickCount();
		}
		return hRes;
	}

	if (SUCCEEDED(hRes) && (NbBytesRecvd > 0) && (msg != NULL))
	{
		orig = msg;

		while ((msg - orig) < NbBytesRecvd)
		{
			next = strchr(msg, ch);
			if (next != NULL)
				*next = 0;

			// Check if this is a JSON sync message
			if (strncmp(msg, "[sync]", 6) == 0) {
				const char* json_start = msg + 6; // Skip "[sync]" prefix
				
				try {
					// Parse JSON
					nlohmann::json j = nlohmann::json::parse(json_start);
					std::string msg_type = j.value("type", "");
					
					// Check if this is an RVA message
					if (msg_type == "rva") {
						// Check if message is from IDA Pro (ignore our own messages)
						std::string source_id = j.value("id", "");
						if (source_id == "idapro") {
							// Extract fields
							std::string modName = j.value("modname", "");
							ULONG64 base = j.value("base", 0ULL);
							ULONG64 rva = j.value("rva", 0ULL);
							
							// Validate and handle
							if (!modName.empty() && rva != 0) {
#if VERBOSE >= 2
								_plugin_logprintf("[sync] HyperSync RVA: %s+0x%llx (base: 0x%llx)\n", 
									modName.c_str(), rva, base);
#endif
								// Convert std::string to char array for handler
								char modNameBuf[MAX_MODULE_SIZE] = {0};
								strncpy_s(modNameBuf, MAX_MODULE_SIZE, modName.c_str(), _TRUNCATE);
								
								HandleRemoteRVA(modNameBuf, rva);
							}
							else {
								_plugin_logprintf("[sync] Invalid RVA message: missing modname or rva\n");
							}
						}
						else {
							_plugin_logprintf("[sync] Ignoring RVA from source: %s\n", source_id.c_str());
						}
					}
					// Check if this is a HyperSync state response from IDA
					else if (msg_type == "hyper_sync_state") {
						bool ida_enabled = j.value("enabled", false);
						
#if VERBOSE >= 2
						_plugin_logprintf("[sync] Received HyperSync state from IDA: %s\n", 
							ida_enabled ? "enabled" : "disabled");
#endif
						
						// Check if IDA's state matches what we want
						if (g_EnableHyperSyncByDefault && !ida_enabled) {
							// We want it enabled but IDA reports disabled - send enable request
							_plugin_logputs("[sync] HyperSync mismatch: requesting enable\n");
							TunnelSend("[sync]{\"type\":\"hyper_sync\",\"enabled\":true}\n");
						}
						else if (!g_EnableHyperSyncByDefault && ida_enabled) {
							// We want it disabled but IDA reports enabled - send disable request
							_plugin_logputs("[sync] HyperSync mismatch: requesting disable\n");
							TunnelSend("[sync]{\"type\":\"hyper_sync\",\"enabled\":false}\n");
						}
						else {
							// States match
							g_HyperSyncEnabled = ida_enabled;
#if VERBOSE >= 2
							_plugin_logprintf("[sync] HyperSync state confirmed: %s\n", 
								ida_enabled ? "enabled" : "disabled");
#endif
						}
					}
					else {
						_plugin_logprintf("[sync] Unknown JSON message type: %s\n", msg_type.c_str());
					}
				}
				catch (nlohmann::json::parse_error& e) {
					_plugin_logprintf("[sync] JSON parse error: %s\n", e.what());
					_plugin_logprintf("[sync] Invalid JSON: %s\n", json_start);
				}
				catch (nlohmann::json::exception& e) {
					_plugin_logprintf("[sync] JSON error: %s\n", e.what());
				}
			}
			else {
				// Regular x64dbg command
				bRes = DbgCmdExec(msg);
				if (!bRes) {
#if VERBOSE >= 2
					_plugin_logprintf("[sync] received command: %s (not yet implemented)\n", msg);
#endif
				}
			}

			// No more command
			if (next == NULL)
				break;

			msg = next + 1;
		}

		free(orig);
	}

	return hRes;
}


void ReleasePollTimer()
{
	BOOL bRes = FALSE;
	DWORD dwErr = 0;

	EnterCriticalSection(&g_CritSectPollRelease);

#if VERBOSE >= 2
	_plugin_logputs("[sync] ReleasePollTimer called\n");
#endif

	if (!(g_hPollTimer == INVALID_HANDLE_VALUE))
	{
		ResetEvent(g_hPollCompleteEvent);
		bRes = DeleteTimerQueueTimer(NULL, g_hPollTimer, g_hPollCompleteEvent);
		if (!bRes)
		{
			// msdn: If the error code is ERROR_IO_PENDING, it is not necessary to
			// call this function again. For any other error, you should retry the call.
			dwErr = GetLastError();

			if (dwErr != ERROR_IO_PENDING) {
				bRes = DeleteTimerQueueTimer(NULL, g_hPollTimer, g_hPollCompleteEvent);
				if (!bRes) {
#if VERBOSE >= 2
					_plugin_logputs("[sync] ReleasePollTimer failed\n");
#endif
				}

			}
		}

		g_hPollTimer = INVALID_HANDLE_VALUE;
	}

	LeaveCriticalSection(&g_CritSectPollRelease);
}


// Poll timer callback implementation: call PollCmd and set completion event
VOID
CALLBACK PollTimerCb(PVOID lpParameter, BOOL TimerOrWaitFired)
{
	HRESULT hRes = S_FALSE;
	UNREFERENCED_PARAMETER(lpParameter);
	UNREFERENCED_PARAMETER(TimerOrWaitFired);

	// If tunnel is down, prevent callback from running
	if (FAILED(TunnelIsUp())) {
#if VERBOSE >= 2
		_plugin_logputs("[sync] PollTimerCb: tunnel is down\n");
#endif
		goto INHIBIT_TIMER_CB;
	}

	hRes = PollCmd();

	// If an error occured in PollCmd() the timer callback is deleted.
	// (typically happens when client has closed the connection)
	if (FAILED(hRes)) {
#if VERBOSE >= 2
		_plugin_logputs("[sync] PollTimerCb: PollCmd failed\n");
#endif
		goto INHIBIT_TIMER_CB;
	}

	return;

INHIBIT_TIMER_CB:
	ReleasePollTimer();
	// Restart auto-connect if enabled and not manually disabled
	if (g_AutoConnectEnabled && !g_UserDisabledSync) {
		StartAutoConnect();
	}
}


// Setup poll timer callback
VOID
CreatePollTimer()
{
	BOOL bRes;

	bRes = CreateTimerQueueTimer(&g_hPollTimer, NULL, (WAITORTIMERCALLBACK)PollTimerCb,
		NULL, TIMER_PERIOD, TIMER_PERIOD, WT_EXECUTEINTIMERTHREAD);

	if (!(bRes)) {
		g_hPollTimer = INVALID_HANDLE_VALUE;
		_plugin_logputs("[sync] CreatePollTimer failed\n");
	}
}


// Sync connection timer callback, run after a 1s timeout
VOID
CALLBACK SyncTimerCb(PVOID lpParameter, BOOL TimerOrWaitFired)
{
	UNREFERENCED_PARAMETER(lpParameter);
	UNREFERENCED_PARAMETER(TimerOrWaitFired);

	//_plugin_logputs("[sync] detecting possible connect timeout\n");
}


// Setup poll timer callback
VOID
CreateSyncTimer()
{
	BOOL bRes;

	bRes = CreateTimerQueueTimer(&g_hSyncTimer, NULL, (WAITORTIMERCALLBACK)SyncTimerCb,
		NULL, SYNC_TIMER_DELAY, 0, WT_EXECUTEONLYONCE);

	if (!(bRes)) {
		g_hSyncTimer = INVALID_HANDLE_VALUE;
		_plugin_logputs("[sync] CreateSyncTimer failed\n");
	}
}


void ReleaseSyncTimer()
{
	BOOL bRes = FALSE;
	DWORD dwErr = 0;

#if VERBOSE >= 2
	_plugin_logputs("[sync] ReleaseSyncTimer called\n");
#endif

	if (g_hSyncTimer != INVALID_HANDLE_VALUE)
	{
		bRes = DeleteTimerQueueTimer(NULL, g_hSyncTimer, NULL);
		if (!bRes)
		{
			// msdn: If the error code is ERROR_IO_PENDING, it is not necessary to
			// call this function again. For any other error, you should retry the call.
			dwErr = GetLastError();

			if (dwErr != ERROR_IO_PENDING) {
				bRes = DeleteTimerQueueTimer(NULL, g_hSyncTimer, NULL);
				if (!bRes) {
#if VERBOSE >= 2
					_plugin_logputs("[sync] ReleaseSyncTimer failed\n");
#endif
				}
			}
		}
	}

	g_hSyncTimer = INVALID_HANDLE_VALUE;
}


// Auto-connect timer callback
VOID CALLBACK AutoConnectTimerCb(PVOID lpParameter, BOOL TimerOrWaitFired)
{
	UNREFERENCED_PARAMETER(lpParameter);
	UNREFERENCED_PARAMETER(TimerOrWaitFired);

	// Don't try to connect if sync is already active or user disabled it
	if (g_Synchronized || g_UserDisabledSync || !g_AutoConnectEnabled) {
		return;
	}

	// Try to connect
	HRESULT hRes = sync(NULL);
	
	if (SUCCEEDED(hRes)) {
		_plugin_logprintf("[sync] Auto-connect successful\n");
		// Stop the auto-connect timer as we're now connected
		StopAutoConnect();
	}
	// If failed, timer will continue trying
}


// Start the auto-connect timer
void StartAutoConnect()
{
	BOOL bRes;

	// Don't start if already running or if sync is active
	if (g_hAutoConnectTimer != INVALID_HANDLE_VALUE || g_Synchronized) {
		return;
	}

#if VERBOSE >= 2
	_plugin_logputs("[sync] Starting auto-connect timer\n");
#endif

	bRes = CreateTimerQueueTimer(&g_hAutoConnectTimer, NULL, 
		(WAITORTIMERCALLBACK)AutoConnectTimerCb,
		NULL, AUTO_CONNECT_RETRY_DELAY, AUTO_CONNECT_RETRY_DELAY, 
		WT_EXECUTEINTIMERTHREAD);

	if (!bRes) {
		g_hAutoConnectTimer = INVALID_HANDLE_VALUE;
		_plugin_logputs("[sync] StartAutoConnect: CreateTimerQueueTimer failed\n");
	}
}


// Stop the auto-connect timer
void StopAutoConnect()
{
	BOOL bRes = FALSE;
	DWORD dwErr = 0;

	if (g_hAutoConnectTimer == INVALID_HANDLE_VALUE) {
		return;
	}

#if VERBOSE >= 2
	_plugin_logputs("[sync] Stopping auto-connect timer\n");
#endif

	bRes = DeleteTimerQueueTimer(NULL, g_hAutoConnectTimer, NULL);
	if (!bRes)
	{
		dwErr = GetLastError();
		if (dwErr != ERROR_IO_PENDING) {
			bRes = DeleteTimerQueueTimer(NULL, g_hAutoConnectTimer, NULL);
			if (!bRes) {
#if VERBOSE >= 2
				_plugin_logputs("[sync] StopAutoConnect: DeleteTimerQueueTimer failed\n");
#endif
			}
		}
	}

	g_hAutoConnectTimer = INVALID_HANDLE_VALUE;
}


// sync command implementation
HRESULT sync(PSTR Args, const bool do_log)
{
	HRESULT hRes = S_OK;

	// Reset global state
	g_Base = NULL;
	g_Offset = NULL;

	if (g_Synchronized)
	{
		if (do_log) _plugin_logputs("[sync] sync update\n");
		UpdateState();
		goto Exit;
	}

	if (do_log) _plugin_logprintf("[sync] attempting to connect to %s:%s\n", g_DefaultHost, g_DefaultPort);

	CreateSyncTimer();

	hRes = TunnelCreate(g_DefaultHost, g_DefaultPort, do_log);
	if (FAILED(hRes))
	{
		if (do_log) _plugin_logputs("[sync] sync failed\n");
		ReleaseSyncTimer();
		goto Exit;
	}

	ReleaseSyncTimer();

	if (do_log) _plugin_logputs("[sync] probing connection\n");

	hRes = TunnelSend("[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - x64_dbg\",\"dialect\":\"x64_dbg\"}\n");
	if (FAILED(hRes))
	{
		_plugin_logputs("[sync] probe failed, is IDA/Ghidra plugin listening?\n");
		goto Exit;
	}

	_plugin_logprintf("[sync] sync is now enabled with host %s\n", g_DefaultHost);
	UpdateState();
	CreatePollTimer();
	
	// Request HyperSync state from IDA to sync up
	// IDA will respond with hyper_sync_state message, and we'll verify/correct
	if (g_EnableHyperSyncByDefault) {
		Sleep(1000);  // Small delay to ensure IDB is enabled
		_plugin_logputs("[sync] Requesting HyperSync state from IDA\n");
		TunnelSend("[sync]{\"type\":\"hyper_sync_request\"}\n");
	}
	
	// Clear the user-disabled flag since we're now connected
	g_UserDisabledSync = FALSE;

Exit:
	return hRes;
}


// syncoff command implementation
HRESULT syncoff()
{
	HRESULT hRes = S_OK;

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced\n");
		return hRes;
	}

	// Mark that user explicitly disabled sync
	g_UserDisabledSync = TRUE;

	// Disable HyperSync if active
	if (g_HyperSyncEnabled) {
		g_HyperSyncEnabled = FALSE;
		TunnelSend("[sync]{\"type\":\"hyper_sync\",\"enabled\":false}\n");
	}

	ReleasePollTimer();
	hRes = TunnelClose();
	_plugin_logputs("[sync] sync is now disabled\n");

	// Stop auto-connect when user manually disables
	StopAutoConnect();

	return hRes;
}


HRESULT synchelp()
{
	HRESULT hRes = S_OK;

	_plugin_logputs("[sync] extension commands help:\n"
		" > !sync                          = synchronize with <host from conf> or the default value\n"
		" > !syncoff                       = stop synchronization\n"
		" > !syncmodauto <on | off>        = enable / disable idb auto switch based on module name\n"
		" > !synchelp                      = display this help\n"
		" > !cmt <string>                  = add comment at current eip in IDA\n"
		" > !rcmt <string>                 = reset comments at current eip in IDA\n"
		" > !idblist                       = display list of all IDB clients connected to the dispatcher\n"
		" > !idb <module name>             = set given module as the active idb (see !idblist)\n"
		" > !idbn <n>                      = set active idb to the n_th client. n should be a valid decimal value\n"
		" > !translate <base> <addr> <mod> = rebase an address with respect to local module's base\n"
		" > !insync                        = synchronize the selected instruction block in the disassembly window\n"
		" > !hypersync                     = enable HyperSync mode (syncs selected instructions)\n"
		" > !hypersyncoff                  = disable HyperSync mode\n\n");

	return hRes;
}


HRESULT syncmodauto(PSTR Args)
{
	HRESULT hRes = S_OK;
	char* param = NULL;
	char* context = NULL;

	// strip command and trailing whitespaces
	strtok_s(Args, " ", &param);
	strtok_s(param, " ", &context);

	if (param != NULL)
	{
		if (strcmp("on", param) == 0)
		{
			g_SyncAuto = true;
			goto LBL_NOTICE;
		}
		else if (strcmp("off", param) == 0)
		{
			g_SyncAuto = false;
			goto LBL_NOTICE;
		}
	}

	_plugin_logputs("[sync] !syncmodauto parameter should be in <on|off> \n");
	return E_FAIL;

LBL_NOTICE:
	hRes = TunnelSend("[notice]{\"type\":\"sync_mode\",\"auto\":\"%s\"}\n", param);
	if (FAILED(hRes)) {
		_plugin_logputs("[sync] !syncmodauto failed to send notice\n");
		return E_FAIL;
	}

	return hRes;
}


// idblist command implementation
HRESULT idblist()
{
	HRESULT hRes = S_OK;
	int NbBytesRecvd = 0;
	LPSTR msg = NULL;

	ReleasePollTimer();

	hRes = TunnelSend("[notice]{\"type\":\"idb_list\"}\n");
	if (FAILED(hRes)) {
		_plugin_logputs("[sync] !idblist failed\n");
		goto RESTORE_TIMER;
	}

	hRes = TunnelReceive(&NbBytesRecvd, &msg);
	if (SUCCEEDED(hRes) && (NbBytesRecvd > 0) && (msg != NULL)) {
		_plugin_logputs(msg);
		free(msg);
	}

RESTORE_TIMER:
	CreatePollTimer();
	return hRes;
}


// insync command implementation
HRESULT InsSync()
{
	HRESULT hRes = E_FAIL;
	DWORD dwRes = 0;
	ULONG_PTR PrevBase = g_Base;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	SELECTIONDATA sel;

	hRes = GuiSelectionGet(GUI_DISASSEMBLY, &sel);
	if (FAILED(hRes))
		goto INSYNC_FAILURE;

	g_Base = DbgFunctions()->ModBaseFromAddr(sel.start);
	if (!g_Base)
	{
		_plugin_logprintf("[insync] InsSync(%p): could not get module base...\n", sel.start);
		goto INSYNC_FAILURE;
	}

#if VERBOSE >= 2
	_plugin_logprintf("[insync] InsSync(%p): module base %p\n", sel.start, g_Base);
#endif

	// Check if we are in a new module
	if ((g_Base != PrevBase) && g_SyncAuto)
	{
		hProcess = DbgGetProcessHandle();

		dwRes = GetModuleBaseNameA(hProcess, (HMODULE)g_Base, g_NameBuffer, MAX_MODULE_SIZE);
		if (dwRes == 0)
		{
			_plugin_logprintf("[insync] InsSync(%p): could not get module name...\n", sel.start);
			goto INSYNC_FAILURE;
		}

#if VERBOSE >= 2
		_plugin_logprintf("[insync] InsSync(%p): module : \"%s\"\n", sel.start, g_NameBuffer);
#endif

		hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", g_NameBuffer);
		if (FAILED(hRes)) {
			return hRes;
		}
	}

	hRes = TunnelSend("[sync]{\"type\":\"loc\",\"base\":%llu,\"offset\":%llu}\n", (ULONG64)g_Base, (ULONG64)sel.start);

	return hRes;

INSYNC_FAILURE:
	// Inform the dispatcher that an error occured in the instruction sync
	if (g_Base != NULL)
	{
		TunnelSend("[notice]{\"type\":\"dbg_err\"}\n");
		g_Base = NULL;
	}

	return hRes;
}


// HyperSync command implementation - enable HyperSync mode
HRESULT hypersync()
{
	HRESULT hRes = S_OK;

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !hypersync command unavailable\n");
		return E_FAIL;
	}

	if (g_HyperSyncEnabled) {
		_plugin_logputs("[sync] HyperSync already enabled\n");
		return hRes;
	}

	g_HyperSyncEnabled = TRUE;
	g_RemoteLocationChange = FALSE;

	// Send HyperSync state to IDA plugin
	hRes = TunnelSend("[sync]{\"type\":\"hyper_sync\",\"enabled\":true}\n");
	if (FAILED(hRes)) {
		_plugin_logputs("[sync] failed to send HyperSync enable message\n");
		g_HyperSyncEnabled = FALSE;
		return hRes;
	}

	_plugin_logputs("[sync] HyperSync mode enabled\n");
	return hRes;
}


// HyperSync command implementation - disable HyperSync mode
HRESULT hypersyncoff()
{
	HRESULT hRes = S_OK;

	if (!g_HyperSyncEnabled) {
		_plugin_logputs("[sync] HyperSync not enabled\n");
		return hRes;
	}

	g_HyperSyncEnabled = FALSE;
	g_RemoteLocationChange = FALSE;

	// Send HyperSync state to IDA plugin
	hRes = TunnelSend("[sync]{\"type\":\"hyper_sync\",\"enabled\":false}\n");
	if (FAILED(hRes)) {
		_plugin_logputs("[sync] failed to send HyperSync disable message\n");
	}

	_plugin_logputs("[sync] HyperSync mode disabled\n");
	return hRes;
}


// Handle selection changes in HyperSync mode
HRESULT HandleSelectionChange(PLUG_CB_SELCHANGED* sel)
{
	HRESULT hRes = S_OK;
	ULONG_PTR va = 0;
	ULONG_PTR modBase = 0;
	CHAR modName[MAX_MODULE_SIZE] = { 0 };

	if (!g_HyperSyncEnabled)
		return hRes;

	// Only handle disassembly window selection changes
	// hWindow: 0 = Disassembly, 1 = Dump, 2 = Stack
	if (sel->hWindow != 0)  // 0 is disassembly window
		return hRes;

	// Ignore if this is a remote-triggered location change
	if (g_RemoteLocationChange) {
		g_RemoteLocationChange = FALSE;
		return hRes;
	}

	// Get the selected virtual address
	va = sel->VA;
	if (!va)
		return E_FAIL;

#if VERBOSE >= 2
	_plugin_logprintf("[sync] HyperSync: selection changed to VA=%p\n", va);
#endif

	// Get module base and name
	modBase = DbgFunctions()->ModBaseFromAddr(va);
	if (!modBase) {
#if VERBOSE >= 2
		_plugin_logprintf("[sync] HyperSync: could not get module base for VA %p\n", va);
#endif
		return E_FAIL;
	}

	if (!DbgFunctions()->ModNameFromAddr(va, modName, true)) {
#if VERBOSE >= 2
		_plugin_logprintf("[sync] HyperSync: could not get module name for VA %p\n", va);
#endif
		return E_FAIL;
	}

	const ULONG64 rva = (ULONG64)(va - modBase);

	// If the mod name is in g_LastModBaseRVAMap, and the mod base and last RVA match (as std::pair<ULONG64,ULONG64>), then we can skip sending the RVA
	if (g_LastModBaseRVAMap.find(modName) != g_LastModBaseRVAMap.end()) {
		const auto& entry = g_LastModBaseRVAMap[modName];
		if (entry.first == (ULONG64)modBase && entry.second == (ULONG64)rva) {
			return hRes;
		}
	}
	g_LastModBaseRVAMap[modName] = std::make_pair((ULONG64)modBase, (ULONG64)rva);

#if VERBOSE >= 2
	_plugin_logprintf("[sync] HyperSync: sending RVA for %s: base=%p, va=%p, rva=%p\n", 
		modName, modBase, va, (ULONG_PTR)rva);
#endif

	// Send relative address to IDA
	hRes = TunnelSend("[sync]{\"type\":\"rva\",\"modname\":\"%s\",\"base\":%llu,\"rva\":%llu,\"id\":\"x64dbg\"}\n", 
		modName, (ULONG64)modBase, (ULONG64)(rva));

	return hRes;
}

HRESULT idbn(PSTR Args)
{
	HRESULT hRes = S_OK;
	int NbBytesRecvd = 0;
	char* msg = NULL;
	char* param = NULL;
	char* img_name = NULL;
	char* context = NULL;
	ULONG_PTR modbase = NULL;

	// strip command and trailing whitespaces
	strtok_s(Args, " ", &param);
	strtok_s(param, " ", &context);

	ReleasePollTimer();

	hRes = TunnelSend("[notice]{\"type\":\"idb_n\",\"idb\":\"%s\"}\n", param);
	if (FAILED(hRes)) {
		_plugin_logputs("[sync] !idbn failed to send notice\n");
		return E_FAIL;
	}

	hRes = TunnelReceive(&NbBytesRecvd, &msg);
	if (FAILED(hRes))
		goto DBG_ERROR;

	// check if dispatcher answered with an error message
	// e.g. "> idb_n error: index %d is invalid (see idblist)"
	if (strstr(msg, "> idb_n error:") != NULL)
	{
		_plugin_logprintf("%s\n", msg);
		goto DBG_ERROR;
	}

	strtok_s(msg, "\"", &context);
	img_name = strtok_s(NULL, "\"", &context);
	if (img_name == NULL)
	{
		_plugin_logputs("[sync] idb_n notice: invalid answser - could not extract image name\n");
		goto DBG_ERROR;
	}

	_plugin_logprintf("idbn: %s\n", img_name);

	modbase = DbgFunctions()->ModBaseFromName(img_name);
	if (!modbase)
	{
		_plugin_logprintf("[sync] idbn: ModBaseFromName(%s) failed get module base...\n", img_name);
		return E_FAIL;
	}

	_plugin_logprintf("[sync] idbn: %s at %Ix\n", img_name, modbase);

	// Send this module its remote base address
	hRes = TunnelSend("[sync]{\"type\":\"rbase\",\"rbase\":%llu}\n", (UINT64)modbase);
	if (FAILED(hRes)) {
		goto DBG_ERROR;
	}

	goto TIMER_REARM_EXIT;

DBG_ERROR:
	// send dbg_err notice to disable the idb as its remote address base
	// was not properly resolved
	TunnelSend("[notice]{\"type\":\"dbg_err\"}\n");

TIMER_REARM_EXIT:
	CreatePollTimer();

	if (msg != NULL)
		free(msg);

	return hRes;
}


HRESULT idb(PSTR Args)
{
	HRESULT hRes = S_OK;
	char* context = NULL;
	char* param = NULL;
	ULONG_PTR modbase = NULL;

	// strip command and trailing whitespaces
	strtok_s(Args, " ", &param);
	strtok_s(param, " ", &context);

	hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", param);
	if (FAILED(hRes)) {
		_plugin_logputs("[sync] TunnelSend failed for module notice\n");
		return hRes;
	}

	modbase = DbgFunctions()->ModBaseFromName(param);
	if (!modbase)
	{
		_plugin_logprintf("[sync] idb: ModBaseFromName(%s) failed to get module base...\n", param);
		goto DBG_ERROR;
	}

	_plugin_logprintf("[sync] idb: %s at %Ix\n", param, modbase);

	// Send this module its remote base address
	hRes = TunnelSend("[sync]{\"type\":\"rbase\",\"rbase\":%llu}\n", (UINT64)modbase);
	if (FAILED(hRes)) {
		_plugin_logputs("[sync] TunnelSend failed for rbase message\n");
		goto DBG_ERROR;
	}

	return hRes;

DBG_ERROR:
	// send dbg_err notice to disable the idb as its remote address base
	// was not properly resolved
	TunnelSend("[notice]{\"type\":\"dbg_err\"}\n");
	return hRes;
}


// add comment (cmt) command implementation
HRESULT cmt(PSTR Args)
{
	BOOL bRes = FALSE;
	HRESULT hRes = S_OK;
	int res = 0;
	ULONG_PTR cip = NULL;
	char* token = NULL;

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !cmt command unavailable\n");
		return E_FAIL;
	}

	if (!strtok_s(Args, " ", &token))
	{
		_plugin_logputs("[sync] failed to tokenize comment\n");
		return E_FAIL;
	}

	hRes = GetInstructionOffset(&cip);
	if (FAILED(hRes))
		return E_FAIL;

	res = _snprintf_s(g_CommandBuffer, _countof(g_CommandBuffer), _TRUNCATE, "commentset %Ix, \"%s\"", cip, token);
	if (res == _TRUNCATE) {
		_plugin_logprintf("[sync] truncation occured in commentset command generation\n", g_CommandBuffer);
	}
	else
	{
		bRes = DbgCmdExec(g_CommandBuffer);
		if (!bRes) {
			_plugin_logprintf("[sync] failed to execute \"%s\" command\n", g_CommandBuffer);
		}
	}
	ZeroMemory(g_CommandBuffer, _countof(g_CommandBuffer));

	hRes = TunnelSend("[sync]{\"type\":\"cmt\",\"msg\":\"%s\",\"base\":%llu,\"offset\":%llu}\n", token, (ULONG64)g_Base, (ULONG64)g_Offset);
	if (FAILED(hRes))
	{
		_plugin_logputs("[sync] failed to send comment\n");
	}

	return hRes;
}


// reset comment (rcmt) command implementation
HRESULT rcmt()
{
	HRESULT hRes = S_OK;
	BOOL bRes = FALSE;
	int res = 0;
	ULONG_PTR cip = NULL;

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !cmt command unavailable\n");
		return E_FAIL;
	}

	hRes = GetInstructionOffset(&cip);
	if (FAILED(hRes))
		return E_FAIL;

	res = _snprintf_s(g_CommandBuffer, _countof(g_CommandBuffer), _TRUNCATE, "commentdel %Ix", cip);
	if (res == _TRUNCATE) {
		_plugin_logputs("[sync] truncation occured in commentdel command generation\n");
	}
	else
	{
		bRes = DbgCmdExec(g_CommandBuffer);
		if (!bRes) {
			_plugin_logprintf("[sync] failed to execute \"%s\" command\n", g_CommandBuffer);
		}
	}

	ZeroMemory(g_CommandBuffer, _countof(g_CommandBuffer));

	hRes = TunnelSend("[sync]{\"type\":\"rcmt\",\"msg\":\"%s\",\"base\":%llu,\"offset\":%llu}\n", "", (ULONG64)g_Base, (ULONG64)g_Offset);
	if (FAILED(hRes))
	{
		_plugin_logputs("[sync] failed to reset comment\n");
	}

	return hRes;
}


// reset comment (rcmt) command implementation
HRESULT translate(PSTR Args)
{
	HRESULT hRes = S_OK;
	BOOL bRes = FALSE;
	int res = 0;
	char* context = NULL;
	char* rbase = NULL;
	char* ea = NULL;
	char* mod = NULL;
	ULONG_PTR modbase = NULL;

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !translate command unavailable\n");
		return E_FAIL;
	}

	strtok_s(Args, " ", &context);
	rbase = strtok_s(NULL, " ", &context);
	ea = strtok_s(NULL, " ", &context);
	mod = strtok_s(NULL, " ", &context);

	if ((rbase == NULL) || (ea == NULL) || (mod == NULL)) {
		_plugin_logputs("[sync] !translate <base> <ea> <mod>   (this command is meant to be used by a disassembler plugin)\n");
	}

	modbase = DbgFunctions()->ModBaseFromName(mod);
	if (!modbase)
	{
		_plugin_logprintf("[sync] translate: ModBaseFromName(%s) failed to get module base...\n", mod);
		return E_FAIL;
	}

	res = _snprintf_s(g_CommandBuffer, _countof(g_CommandBuffer), _TRUNCATE, "disasm %#Ix-%s+%s", modbase, rbase, ea);
	if (res == _TRUNCATE) {
		_plugin_logputs("[sync] truncation occured in disasm command generation\n");
	}
	else
	{
		bRes = DbgCmdExec(g_CommandBuffer);
		if (!bRes) {
			_plugin_logprintf("[sync] failed to execute \"%s\" command\n", g_CommandBuffer);
		}
	}
	ZeroMemory(g_CommandBuffer, _countof(g_CommandBuffer));

	return hRes;
}


static bool cbSyncCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] sync command!");
	sync(NULL);
	return true;
}


static bool cbSyncoffCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] syncoff command!");
	syncoff();
	return true;
}


static bool cbSyncmodautoCommand(int argc, char* argv[])
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] syncmodauto command!");
#endif

	if (strlen(argv[0]) < _countof("!syncmodauto")) {
		_plugin_logputs("[sync] !syncmodauto missing parameter (<on|off>)\n");
		return false;
	}

	_plugin_logputs("[sync] syncmodauto command!");
	syncmodauto((PSTR)argv[0]);
	return true;
}


static bool cbSynchelpCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] synchelp command!");
	synchelp();
	return true;
}


static bool cbIdblistCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] idblist command!");

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !idblist command unavailable\n");
		return false;
	}

	idblist();
	return true;
}


static bool cbIdbnCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] idbn command!");

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !idbn command unavailable\n");
		return false;
	}

	if (strlen(argv[0]) < _countof("!idbn")) {
		_plugin_logputs("[sync] !idbn <idb num>\n");
		return false;
	}

	idbn((PSTR)argv[0]);
	return true;
}


static bool cbIdbCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] idb command!");

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !idb command unavailable\n");
		return false;
	}

	if (strlen(argv[0]) < _countof("!idb")) {
		_plugin_logputs("[sync] !idb <module name>\n");
		return false;
	}

	idb((PSTR)argv[0]);
	return true;
}


static bool cbCmtCommand(int argc, char* argv[])
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] cmt command!");
#endif

	if (strlen(argv[0]) < _countof("!cmt")) {
		_plugin_logputs("[sync] !cmt <comment to add>\n");
		return false;
	}

	cmt((PSTR)argv[0]);
	return true;
}


static bool cbRcmtCommand(int argc, char* argv[])
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] rcmt command!");
#endif

	rcmt();
	return true;
}


static bool cbInsyncCommand(int argc, char* argv[])
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] insync command!");
#endif

	InsSync();
	return true;
}


static bool cbHypersyncCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] hypersync command!");
	hypersync();
	return true;
}


static bool cbHypersyncoffCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] hypersyncoff command!");
	hypersyncoff();
	return true;
}


static bool cbTranslateCommand(int argc, char* argv[])
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] translate command!");
#endif

	if (strlen(argv[0]) < _countof("!translate")) {
		_plugin_logputs("[sync] !translate <base> <ea> <mod>   (this command is meant to be used by a disassembler plugin)\n");
		return false;
	}

	translate(argv[0]);
	return true;
}


extern "C" __declspec(dllexport) void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
{
	_plugin_logprintf("[sync] debugging of file %s started!\n", (const char*)info->szFileName);
	
	// Start auto-connect when debugging begins
	if (g_AutoConnectEnabled && !g_UserDisabledSync) {
		_plugin_logputs("[sync] Starting auto-connect...\n");
		StartAutoConnect();
	}
}


extern "C" __declspec(dllexport) void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{

#if VERBOSE >= 2
	_plugin_logputs("[sync] debugging stopped!");
#endif
	
	// Stop auto-connect when debugging stops
	StopAutoConnect();
	
	// Disconnect if connected
	if (g_Synchronized) {
		syncoff();
		// Reset user-disabled flag so auto-connect can work on next debug session
		g_UserDisabledSync = FALSE;
	}
}


extern "C" __declspec(dllexport) void CBPAUSEDEBUG(CBTYPE cbType, PLUG_CB_PAUSEDEBUG* info)
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] debugging paused!");
#endif

	if (SUCCEEDED(TunnelIsUp()))
	{
		UpdateState();
		CreatePollTimer();
	}

}


extern "C" __declspec(dllexport) void CBRESUMEDEBUG(CBTYPE cbType, PLUG_CB_RESUMEDEBUG* info)
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] debugging resumed!");
#endif

	ReleasePollTimer();
}


extern "C" __declspec(dllexport) void CBDEBUGEVENT(CBTYPE cbType, PLUG_CB_DEBUGEVENT* info)
{
	if (info->DebugEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
	{
		//_plugin_logprintf("[sync] DebugEvent->EXCEPTION_DEBUG_EVENT->%.8X\n", info->DebugEvent->u.Exception.ExceptionRecord.ExceptionCode);
	}
}


extern "C" __declspec(dllexport) void CBSELCHANGED(CBTYPE cbType, PLUG_CB_SELCHANGED* info)
{
	HandleSelectionChange(info);
}


extern "C" __declspec(dllexport) void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
	switch (info->hEntry)
	{
	case MENU_ENABLE_SYNC:
		// Clear the user-disabled flag when manually enabling
		g_UserDisabledSync = FALSE;
		cbSyncCommand(0, NULL);
		break;

	case MENU_DISABLE_SYNC:
		cbSyncoffCommand(0, NULL);
		break;

	case MENU_IDB_LIST:
		cbIdblistCommand(0, NULL);
		break;

	case MENU_SYNC_HELP:
		cbSynchelpCommand(0, NULL);
		break;

	case MENU_HYPER_SYNC:
		if (!g_HyperSyncEnabled)
			cbHypersyncCommand(0, NULL);
		else
			cbHypersyncoffCommand(0, NULL);
		break;

	default:
		break;
	}
}


void coreInit(PLUG_INITSTRUCT* initStruct)
{
	// register commands
#if VERBOSE >= 2
	_plugin_logprintf("[sync] pluginHandle: %d\n", pluginHandle);
#endif

	if (!_plugin_registercommand(pluginHandle, "!sync", cbSyncCommand, true))
		_plugin_logputs("[sync] error registering the \"!sync\" command!");

	if (!_plugin_registercommand(pluginHandle, "!syncoff", cbSyncoffCommand, true))
		_plugin_logputs("[sync] error registering the \"!syncoff\" command!");

	if (!_plugin_registercommand(pluginHandle, "!syncmodauto", cbSyncmodautoCommand, true))
		_plugin_logputs("[sync] error registering the \"!syncmodauto\" command!");

	if (!_plugin_registercommand(pluginHandle, "!synchelp", cbSynchelpCommand, false))
		_plugin_logputs("[sync] error registering the \"!synchelp\" command!");

	if (!_plugin_registercommand(pluginHandle, "!idblist", cbIdblistCommand, true))
		_plugin_logputs("[sync] error registering the \"!idblist\" command!");

	if (!_plugin_registercommand(pluginHandle, "!idbn", cbIdbnCommand, true))
		_plugin_logputs("[sync] error registering the \"!idbn\" command!");

	if (!_plugin_registercommand(pluginHandle, "!idb", cbIdbCommand, true))
		_plugin_logputs("[sync] error registering the \"!idb\" command!");

	if (!_plugin_registercommand(pluginHandle, "!cmt", cbCmtCommand, true))
		_plugin_logputs("[sync] error registering the \"!cmt\" command!");

	if (!_plugin_registercommand(pluginHandle, "!rcmt", cbRcmtCommand, true))
		_plugin_logputs("[sync] error registering the \"!rcmt\" command!");

	if (!_plugin_registercommand(pluginHandle, "!translate", cbTranslateCommand, true))
		_plugin_logputs("[sync] error registering the \"!translate\" command!");

	if (!_plugin_registercommand(pluginHandle, "!insync", cbInsyncCommand, true))
		_plugin_logputs("[sync] error registering the \"!insync\" command");

	if (!_plugin_registercommand(pluginHandle, "!hypersync", cbHypersyncCommand, true))
		_plugin_logputs("[sync] error registering the \"!hypersync\" command");

	if (!_plugin_registercommand(pluginHandle, "!hypersyncoff", cbHypersyncoffCommand, true))
		_plugin_logputs("[sync] error registering the \"!hypersyncoff\" command");

	// initialize globals
	g_Synchronized = FALSE;
	g_HyperSyncEnabled = FALSE;
	g_AutoConnectEnabled = TRUE;
	g_UserDisabledSync = FALSE;
	g_hAutoConnectTimer = INVALID_HANDLE_VALUE;

	g_hPollCompleteEvent = CreateEvent(NULL, true, false, NULL);
	if (g_hPollCompleteEvent == NULL)
	{
		_plugin_logputs("[sync] Command polling feature init failed\n");
		return;
	}

	InitializeCriticalSection(&g_CritSectPollRelease);

	if (SUCCEEDED(LoadConfigurationFile())) {
		_plugin_logprintf("[sync] Configuration file loaded\n");
	}
	
	_plugin_logputs("[sync] Auto-connect is enabled by default\n");
}


void coreStop()
{
	// Stop auto-connect timer
	StopAutoConnect();
	
	// close tunnel and release objects
	ReleasePollTimer();
	TunnelClose();
	DeleteCriticalSection(&g_CritSectPollRelease);
	CloseHandle(g_hPollCompleteEvent);

	// unregister plugin's commands and menu entries
	_plugin_unregistercommand(pluginHandle, "!sync");
	_plugin_unregistercommand(pluginHandle, "!syncoff");
	_plugin_unregistercommand(pluginHandle, "!synchelp");
	_plugin_unregistercommand(pluginHandle, "!syncmodauto");
	_plugin_unregistercommand(pluginHandle, "!idblist");
	_plugin_unregistercommand(pluginHandle, "!idbn");
	_plugin_unregistercommand(pluginHandle, "!idb");
	_plugin_unregistercommand(pluginHandle, "!cmt");
	_plugin_unregistercommand(pluginHandle, "!rcmt");
	_plugin_unregistercommand(pluginHandle, "!translate");
	_plugin_unregistercommand(pluginHandle, "!insync");
	_plugin_unregistercommand(pluginHandle, "!hypersync");
	_plugin_unregistercommand(pluginHandle, "!hypersyncoff");
	_plugin_menuclear(hMenu);
}


void coreSetup()
{
	_plugin_menuaddentry(hMenu, MENU_ENABLE_SYNC, "&Enable sync");
	_plugin_menuaddentry(hMenu, MENU_DISABLE_SYNC, "&Disable sync");
	_plugin_menuaddentry(hMenu, MENU_IDB_LIST, "&Retrieve idb list");
	_plugin_menuaddentry(hMenu, MENU_SYNC_HELP, "&Display sync commands help");
	_plugin_menuaddentry(hMenu, MENU_HYPER_SYNC, "&HyperSync mode");
}