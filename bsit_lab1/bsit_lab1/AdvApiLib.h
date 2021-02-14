#pragma once

#include <Windows.h>
#include <LM.h>
#include <sddl.h>
#include "atlstr.h"
#include <NTSecAPI.h>

class AdvApiLib
{
public:
	AdvApiLib()
	{
		hLib = LoadLibrary(L"Advapi32.dll");

		ConvertSidToStringSid = (BOOL(*)(PSID, LPWSTR*))GetProcAddress(hLib, "ConvertSidToStringSidW");
		LsaOpenPolicy = (NTSTATUS(*)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE))GetProcAddress(hLib, "LsaOpenPolicy");
		LsaEnumerateAccountRights = (NTSTATUS(*)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING*, PULONG))GetProcAddress(hLib, "LsaEnumerateAccountRights");
		LsaAddAccountRights = (NTSTATUS(*)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING, ULONG))GetProcAddress(hLib, "LsaAddAccountRights");
		LsaRemoveAccountRights = (NTSTATUS(*)(LSA_HANDLE, PSID, BOOLEAN, PLSA_UNICODE_STRING, ULONG))GetProcAddress(hLib, "LsaRemoveAccountRights");
		LookupAccountName = (NET_API_STATUS(*)(LPWSTR, LPWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE))GetProcAddress(hLib, "LookupAccountNameW");
	}

	HINSTANCE hLib;
	
	BOOL(*ConvertSidToStringSid)(PSID, LPWSTR*);
	NTSTATUS(*LsaOpenPolicy)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
	NTSTATUS(*LsaEnumerateAccountRights)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING*, PULONG);
	NTSTATUS(*LsaAddAccountRights)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING, ULONG);
	NTSTATUS(*LsaRemoveAccountRights)(LSA_HANDLE, PSID, BOOLEAN, PLSA_UNICODE_STRING, ULONG);
	NET_API_STATUS(*LookupAccountName)(LPWSTR, LPWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
};