#pragma once

#include <Windows.h>
#include <LM.h>
#include <sddl.h>
#include "atlstr.h"
#include <NTSecAPI.h>

class NetApiLib
{
public:
	NetApiLib()
	{
		hLib = LoadLibrary(L"netapi32.dll");
		
		NetUserEnum = (NET_API_STATUS(*)(LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD))GetProcAddress(hLib, "NetUserEnum");
		NetLocalGroupEnum = (NET_API_STATUS(*)(LPCWSTR, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, PDWORD_PTR))GetProcAddress(hLib, "NetLocalGroupEnum");
		NetUserAdd = (NET_API_STATUS(*)(LPCWSTR, DWORD, LPBYTE, LPDWORD))GetProcAddress(hLib, "NetUserAdd");
		NetUserDel = (NET_API_STATUS(*)(LPCWSTR, LPCWSTR))GetProcAddress(hLib, "NetUserDel");
		NetLocalGroupAdd = (NET_API_STATUS(*)(LPCWSTR, DWORD, LPBYTE, LPDWORD))GetProcAddress(hLib, "NetLocalGroupAdd");
		NetLocalGroupDel = (NET_API_STATUS(*)(LPCWSTR, LPCWSTR))GetProcAddress(hLib, "NetLocalGroupDel");
		NetLocalGroupGetMembers = (NET_API_STATUS(*)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, PDWORD_PTR))GetProcAddress(hLib, "NetLocalGroupGetMembers");
		NetLocalGroupAddMembers = (NET_API_STATUS(*)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD))GetProcAddress(hLib, "NetLocalGroupAddMembers");
		NetLocalGroupDelMembers = (NET_API_STATUS(*)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD))GetProcAddress(hLib, "NetLocalGroupDelMembers");
		NetApiBufferFree = (NET_API_STATUS(*)(LPVOID))GetProcAddress(hLib, "NetApiBufferFree");
	}

	~NetApiLib()
	{
		FreeLibrary(hLib);
	}

	HINSTANCE hLib;
	
	NET_API_STATUS(*NetUserEnum)(LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD);
	NET_API_STATUS(*NetLocalGroupEnum)(LPCWSTR, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
	NET_API_STATUS(*NetUserAdd)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
	NET_API_STATUS(*NetUserDel)(LPCWSTR, LPCWSTR);
	NET_API_STATUS(*NetLocalGroupAdd)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
	NET_API_STATUS(*NetLocalGroupDel)(LPCWSTR, LPCWSTR);
	NET_API_STATUS(*NetLocalGroupGetMembers)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
	NET_API_STATUS(*NetLocalGroupAddMembers)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
	NET_API_STATUS(*NetLocalGroupDelMembers)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
	NET_API_STATUS(*NetApiBufferFree)(LPVOID);
};