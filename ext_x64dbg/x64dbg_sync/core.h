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

#ifndef _CORE_H
#define _CORE_H

#include "sync.h"

#define SYNC_TIMER_DELAY 1000
#define TIMER_PERIOD 25
#define CONF_FILE "\\.sync"
#define AUTO_CONNECT_RETRY_DELAY 2000  // Retry connection every 2 seconds

enum MENU_IDENTIFIERS {
	MENU_ENABLE_SYNC,
	MENU_DISABLE_SYNC,
	MENU_IDB_LIST,
	MENU_SYNC_HELP,
	MENU_HYPER_SYNC
};

//functions
HRESULT sync(PSTR Args);
HRESULT syncoff();
HRESULT syncmodauto(PSTR Args);
HRESULT synchelp();
HRESULT idblist();
HRESULT cmt(PSTR Args);
HRESULT rcmt();
HRESULT hypersync();
HRESULT hypersyncoff();

void coreInit(PLUG_INITSTRUCT* initStruct);
void coreStop();
void coreSetup();

// Auto-connect functions
void StartAutoConnect();
void StopAutoConnect();

// HyperSync state
extern BOOL g_HyperSyncEnabled;

// Auto-connect state
extern BOOL g_AutoConnectEnabled;

#endif // _CORE_H