#include <iostream>

#include "AdvApiLib.h"
#include "NetApiLib.h"

auto g_AdvApiLib = new AdvApiLib();
auto g_NetApiLib = new NetApiLib();

void ShowInfo();
LSA_HANDLE GetPolicyHandle();
PSID& FindSidByName(LPWSTR name);
void FindRightsBySid(PSID sid);

int main()
{
	ShowInfo();
	
	return 0;	
}

void ShowInfo()
{
	PSID sid = nullptr;
	DWORD struct_level = 0;
	DWORD prefmaxlen = 0xFFFFFFFF;
	DWORD entries_flag = 0;
	DWORD entries = 0;
	LPBYTE UserInfoPtr;
	LOCALGROUP_INFO_0* buffer;
	LPBYTE* buffptr;

	auto result = g_NetApiLib->NetLocalGroupEnum(nullptr, struct_level, (LPBYTE)&buffer, prefmaxlen, &entries_flag, &entries, nullptr);

	for (auto i = 0; i < entries; ++i)
	{
		DWORD user_entries_read;
		DWORD user_total_entries;
		LOCALGROUP_MEMBERS_INFO_0* memberbuff;
		wprintf(L"%d)%s\n", i + 1, (buffer + i)->lgrpi0_name);
		sid = FindSidByName((buffer + i)->lgrpi0_name);
		LPWSTR buf = nullptr;
		
		result = g_NetApiLib->NetLocalGroupGetMembers(
			nullptr, 
			(buffer + i)->lgrpi0_name, 
			0,
			(LPBYTE)&memberbuff, 
			MAX_PREFERRED_LENGTH, 
			&user_entries_read, 
			&user_total_entries, 
			nullptr
		);
		
		for (auto j = 0; j < user_total_entries; ++j)
		{
			LPWSTR str = nullptr;
			g_AdvApiLib->ConvertSidToStringSid((memberbuff + j)->lgrmi0_sid, &str);
			printf("User: ");
			wprintf(L"%s\n", str);
		}
		
		printf("\n");
	}
	
	sid = nullptr;

	DWORD dwlevel = 0;
	DWORD dwfilter = 0;
	USER_INFO_0* theEntries = new USER_INFO_0[20];
	DWORD dwprefmaxlen = 512;
	DWORD dwentriesread;
	DWORD dwtotalentries;

	result = g_NetApiLib->NetUserEnum(nullptr, dwlevel, dwfilter, (LPBYTE*)&theEntries, dwprefmaxlen, &dwentriesread, &dwtotalentries, nullptr);
	
	printf("USERS:\n");
	
	if (true)
	{
		for (int i = 0; i < dwentriesread; ++i)
		{
			wprintf(L"%i: %s\n", i + 1, theEntries[i].usri0_name);
			sid = FindSidByName(theEntries[i].usri0_name);
			printf("\n");
		}
	}
	
	g_NetApiLib->NetApiBufferFree(buffer);
}

PSID& FindSidByName(LPWSTR name)
{
	auto DomainName = (LPSTR)LocalAlloc(LPTR, sizeof(TCHAR) * 1024);
	
	SID_NAME_USE snu;
	DWORD cchRD = 0;
	LPWSTR rd = nullptr;
	BYTE sidbuf[SECURITY_MAX_SID_SIZE];
	PSID sid = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
	DWORD cbSid = SECURITY_MAX_SID_SIZE;
	LPWSTR buf = nullptr;

	auto result = g_AdvApiLib->LookupAccountName(nullptr, name, sid, &cbSid, rd, &cchRD, &snu);
	
	rd = (LPWSTR)LocalAlloc(LPTR, cchRD * sizeof(*rd));
	cbSid = sizeof(sidbuf);
	
	result = g_AdvApiLib->LookupAccountName(nullptr, name, sid, &cbSid, rd, &cchRD, &snu);
	result = g_AdvApiLib->ConvertSidToStringSid(sid, &buf);
	
	wprintf(L"%s\n", buf);
	
	FindRightsBySid(sid);
	
	return sid;
}

void FindRightsBySid(PSID sid)
{
	PLSA_UNICODE_STRING UserRights;
	ULONG CountofRights;
	
	g_AdvApiLib->LsaEnumerateAccountRights(GetPolicyHandle(), sid, &UserRights, &CountofRights);
	
	for (auto i = 0; i < CountofRights; ++i)
	{
		wprintf(L"Privilege: %d %s\n", i + 1, (UserRights + i)->Buffer);
	}
}

LSA_HANDLE GetPolicyHandle()
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	LSA_HANDLE lsaPolicyHandle;

	memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
	auto ntsResult = g_AdvApiLib->LsaOpenPolicy(nullptr, &ObjectAttributes, POLICY_ALL_ACCESS, &lsaPolicyHandle);
	
	if (ntsResult != 0)
	{
		wprintf(L"Error while getting policy,  %lu.\n", LsaNtStatusToWinError(ntsResult));
		
		exit(-1);
	}
	
	return lsaPolicyHandle;
}