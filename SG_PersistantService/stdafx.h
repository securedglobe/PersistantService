/*
SG_PersistantService
by Michael Haephrati haephrati@gmail.com
Secured Globe Persistant Windows Service
©2019-2022 Secured Globe, Inc.
https://www.securedglobe.net

Explained in https://www.codeproject.com/Articles/5345258/Thank-You-for-Your-Service-Creating-a-Persistent-I

version 2.0	Nov 2022
*/

#pragma once

#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <atlbase.h>
#include <atltime.h>
#include <codecvt>
#include <atlstr.h>
#include <WinInet.h>
#include <wtsapi32.h>
#include <Shlwapi.h>
#include <string>
#include <tlhelp32.h>
#include <Userenv.h>
#include <shellapi.h>
#include <bcrypt.h>

// Common Standard Headers
#include <cstdio>
#include <map>
#include <set>
#include <new>
#include <queue>
#include <sstream>


// Common Windows Headers
#include <Windows.h>
#include <objidl.h>
#include <gdiplus.h>
#include <shlobj.h>
#include <dshow.h>
#include <wincred.h>
#include <WinCrypt.h>
#include <LMCons.h>
#include <Psapi.h>

#include <string>
#include <Setupapi.h>
#include <WinUser.h>
#include <xlocbuf>

#include <windows.h>
#include <winternl.h>

#include <string>
#include <format>
#include <io.h>     // _open_osfhandle

#include <iostream>
#include <string>
#include <stdio.h>      
#include <time.h>  
#include <wchar.h>
#include <stdarg.h>
#include <windows.h>
#include <winevt.h>

#define _CRT_SECURE_NO_WARNINGS
