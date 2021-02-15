#include <iostream>
#include <conio.h>

#include "AdvApiLib.h"
#include "NetApiLib.h"

void ShowInfo();
LSA_HANDLE GetPolicyHandle();
PSID& FindSidByName(LPWSTR name);
void FindRightsBySid(PSID sid);
void AddUser(std::string name, std::string pass);
void DelUser(std::string name);
void AddGroup(std::string groupName);
void DelGroup(std::string groupName);
void AddUserToGroup(std::string user, std::string group);
void DelUserFromGroup(std::string user, std::string group);
void AddUserGroupPrivilege(std::string name, std::string privilege);
void DelUserGroupPrivilege(std::string name, std::string privilege);
bool InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString);
void Menu();

int main()
{
	Menu();

	return 0;
}

void ShowInfo()
{
	auto advApiLib = new AdvApiLib();
	auto netApiLib = new NetApiLib();
	
	PSID sid = nullptr;
	DWORD struct_level = 0;
	DWORD prefmaxlen = 0xFFFFFFFF;
	DWORD entries_flag = 0;
	DWORD entries = 0;
	LPBYTE UserInfoPtr;
	LOCALGROUP_INFO_0* buffer;
	LPBYTE* buffptr;

	auto result = netApiLib->NetLocalGroupEnum(nullptr, struct_level, (LPBYTE)&buffer, prefmaxlen, &entries_flag, &entries, nullptr);

	for (auto i = 0; i < entries; ++i)
	{
		DWORD user_entries_read;
		DWORD user_total_entries;
		LOCALGROUP_MEMBERS_INFO_0* memberbuff;
		
		std::wcout << i + 1 << ") " << (buffer + i)->lgrpi0_name << std::endl;
		
		sid = FindSidByName((buffer + i)->lgrpi0_name);
		LPWSTR buf = nullptr;
		
		result = netApiLib->NetLocalGroupGetMembers(
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
			advApiLib->ConvertSidToStringSid((memberbuff + j)->lgrmi0_sid, &str);
			std::cout << "User: ";
			std::wcout << str << std::endl;
		}
		
		std::cout << std::endl;
	}
	
	sid = nullptr;

	DWORD dwlevel = 0;
	DWORD dwfilter = 0;
	USER_INFO_0* theEntries = new USER_INFO_0[20];
	DWORD dwprefmaxlen = 512;
	DWORD dwentriesread;
	DWORD dwtotalentries;

	result = netApiLib->NetUserEnum(nullptr, dwlevel, dwfilter, (LPBYTE*)&theEntries, dwprefmaxlen, &dwentriesread, &dwtotalentries, nullptr);
	
	std::cout << "USERS: " << std::endl;
	
	if (true)
	{
		for (int i = 0; i < dwentriesread; ++i)
		{
			std::wcout << i + 1 << ": " << theEntries[i].usri0_name << std::endl;
			sid = FindSidByName(theEntries[i].usri0_name);
			std::cout << std::endl;
		}
	}
	
	netApiLib->NetApiBufferFree(buffer);
}

PSID& FindSidByName(LPWSTR name)
{
	auto advApiLib = new AdvApiLib();
	
	auto DomainName = (LPSTR)LocalAlloc(LPTR, sizeof(TCHAR) * 1024);
	
	SID_NAME_USE snu;
	DWORD cchRD = 0;
	LPWSTR rd = nullptr;
	BYTE sidbuf[SECURITY_MAX_SID_SIZE];
	PSID sid = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
	DWORD cbSid = SECURITY_MAX_SID_SIZE;
	LPWSTR buf = nullptr;

	auto result = advApiLib->LookupAccountName(nullptr, name, sid, &cbSid, rd, &cchRD, &snu);
	
	rd = (LPWSTR)LocalAlloc(LPTR, cchRD * sizeof(*rd));
	cbSid = sizeof(sidbuf);
	
	result = advApiLib->LookupAccountName(nullptr, name, sid, &cbSid, rd, &cchRD, &snu);
	result = advApiLib->ConvertSidToStringSid(sid, &buf);
	
	std::wcout << buf << std::endl;
	
	FindRightsBySid(sid);
	
	return sid;
}

void FindRightsBySid(PSID sid)
{
	auto advApiLib = new AdvApiLib();
	
	PLSA_UNICODE_STRING UserRights;
	ULONG CountofRights;
	
	advApiLib->LsaEnumerateAccountRights(GetPolicyHandle(), sid, &UserRights, &CountofRights);
	
	for (auto i = 0; i < CountofRights; ++i)
	{
		std::wcout << "Privilege: " << i + 1 << " " << (UserRights + i)->Buffer << std::endl;
	}
}

LSA_HANDLE GetPolicyHandle()
{
	auto advApiLib = new AdvApiLib();
	
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	LSA_HANDLE lsaPolicyHandle;

	memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
	auto ntsResult = advApiLib->LsaOpenPolicy(nullptr, &ObjectAttributes, POLICY_ALL_ACCESS, &lsaPolicyHandle);
	
	if (ntsResult != 0)
	{
		std::wcout << "Error while getting policy, " << LsaNtStatusToWinError(ntsResult) << std::endl;
		exit(-1);
	}
	
	return lsaPolicyHandle;
}

void AddUser(std::string name, std::string pass)
{
	auto netApiLib = new NetApiLib();
	
	auto wc_name = new wchar_t[name.length() + 1];
	mbstowcs_s(nullptr, wc_name, name.length() + 1, name.c_str(), name.length());
	auto wc_pass = new wchar_t[pass.length() + 1];
	mbstowcs_s(nullptr, wc_pass, pass.length() + 1, pass.c_str(), pass.length());

	USER_INFO_1 user_info;

	user_info.usri1_name = wc_name;
	user_info.usri1_password = wc_pass;
	user_info.usri1_comment = nullptr;
	user_info.usri1_flags = UF_SCRIPT;
	user_info.usri1_home_dir = nullptr;
	user_info.usri1_priv = USER_PRIV_USER;
	user_info.usri1_script_path = nullptr;

	auto result = netApiLib->NetUserAdd(nullptr, 1, (LPBYTE)&user_info, nullptr);
	
	if (result != 0)
	{
		std::cout << "User cannot be added" << std::endl;
	}
}

void DelUser(std::string name)
{
	auto netApiLib = new NetApiLib();
	
	auto wc_name = new wchar_t[name.length() + 1];
	mbstowcs_s(nullptr, wc_name, name.length() + 1, name.c_str(), name.length());

	auto result = netApiLib->NetUserDel(nullptr, wc_name);
}

void AddGroup(std::string groupName)
{
	auto netApiLib = new NetApiLib();
	
	auto wc_gname = new wchar_t[groupName.length() + 1];
	mbstowcs_s(nullptr, wc_gname, groupName.length() + 1, groupName.c_str(), groupName.length());

	LOCALGROUP_INFO_0 new_group_info;
	new_group_info.lgrpi0_name = wc_gname;

	auto result = netApiLib->NetLocalGroupAdd(nullptr, 0, (LPBYTE)&new_group_info, nullptr);
	
	if (result != 0)
	{
		std::cout << "Group cannot be added" << std::endl;
	}
}

void DelGroup(std::string groupName)
{
	auto netApiLib = new NetApiLib();
	
	auto wc_gname = new wchar_t[groupName.length() + 1];
	mbstowcs_s(nullptr, wc_gname, groupName.length() + 1, groupName.c_str(), groupName.length());

	auto result = netApiLib->NetLocalGroupDel(nullptr, wc_gname);
}

void AddUserToGroup(std::string user, std::string group)
{
	auto netApiLib = new NetApiLib();
	
	auto wc_uname = new wchar_t[user.length() + 1];
	mbstowcs_s(nullptr, wc_uname, user.length() + 1, user.c_str(), user.length());
	auto wc_gname = new wchar_t[group.length() + 1];
	mbstowcs_s(nullptr, wc_gname, group.length() + 1, group.c_str(), group.length());

	_LOCALGROUP_MEMBERS_INFO_0 buf;

	buf.lgrmi0_sid = FindSidByName(wc_uname);
	NET_API_STATUS result = netApiLib->NetLocalGroupAddMembers(nullptr, wc_gname, 0, (LPBYTE)&buf, 1);
}

void DelUserFromGroup(std::string user, std::string group)
{
	auto netApiLib = new NetApiLib();

	auto wc_uname = new wchar_t[user.length() + 1];
	mbstowcs_s(nullptr, wc_uname, user.length() + 1, user.c_str(), user.length());
	auto wc_gname = new wchar_t[group.length() + 1];
	mbstowcs_s(nullptr, wc_gname, group.length() + 1, group.c_str(), group.length());

	_LOCALGROUP_MEMBERS_INFO_0 buf;

	buf.lgrmi0_sid = FindSidByName(wc_uname);
	NET_API_STATUS result = netApiLib->NetLocalGroupDelMembers(nullptr, wc_gname, 0, (LPBYTE)&buf, 1);
}

void AddUserGroupPrivilege(std::string name, std::string privilege)
{
	auto advApiLib = new AdvApiLib();
	
	auto wc_name = new wchar_t[name.length() + 1];
	mbstowcs_s(nullptr, wc_name, name.length() + 1, name.c_str(), name.length());
	auto wc_priv = new wchar_t[privilege.length() + 1];
	mbstowcs_s(nullptr, wc_priv, privilege.length() + 1, privilege.c_str(), privilege.length());

	LSA_UNICODE_STRING privilegeLsa;
	PSID sid = nullptr;

	if (!InitLsaString(&privilegeLsa, wc_priv))
	{
		std::cout << "Unknown privilege" << std::endl;
	}

	NTSTATUS result;
	sid = FindSidByName(wc_name);
	
	if (sid != nullptr)
	{
		LPWSTR buf = nullptr;
		ConvertSidToStringSidW(sid, &buf);
		result = advApiLib->LsaAddAccountRights(GetPolicyHandle(), sid, &privilegeLsa, 1);
	}
	
	if (result != 0)
	{
		std::wcout << "Error while adding group privilege: " << LsaNtStatusToWinError(result) << std::endl;
	}
}

void DelUserGroupPrivilege(std::string name, std::string privilege)
{
	auto advApiLib = new AdvApiLib();

	auto wc_name = new wchar_t[name.length() + 1];
	mbstowcs_s(nullptr, wc_name, name.length() + 1, name.c_str(), name.length());
	auto wc_priv = new wchar_t[privilege.length() + 1];
	mbstowcs_s(nullptr, wc_priv, privilege.length() + 1, privilege.c_str(), privilege.length());

	LSA_UNICODE_STRING privilegeLsa;

	PSID sid = FindSidByName(wc_name);
	InitLsaString(&privilegeLsa, wc_priv);
	
	if (sid != nullptr)
	{
		auto result = advApiLib->LsaRemoveAccountRights(GetPolicyHandle(), sid, FALSE, &privilegeLsa, 1);
		{
			printf("Error in removing privilege!!!!\n");
		}
	}
}

bool InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
	DWORD dwLen = 0;

	if (nullptr == pLsaString)
		return FALSE;

	if (nullptr != pwszString)
	{
		dwLen = wcslen(pwszString);
		if (dwLen > 0x7ffe)   // String is too large
			return FALSE;
	}

	// Store the string.
	pLsaString->Buffer = (WCHAR*)pwszString;
	pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

	return TRUE;
}

void Menu()
{
	auto menuItem = 0;

	while (menuItem != 12)
	{
		std::cout << "1. Show all info" << std::endl;
		std::cout << "2. Add user privilege" << std::endl;
		std::cout << "3. Delete user privilege" << std::endl;
		std::cout << "4. Add group privilege" << std::endl;
		std::cout << "5. Delete group privilege" << std::endl;
		std::cout << "6. Add user" << std::endl;
		std::cout << "7. Delete user" << std::endl;
		std::cout << "8. Add group" << std::endl;
		std::cout << "9. Delete group" << std::endl;
		std::cout << "10. Add user to group" << std::endl;
		std::cout << "11. Delete user from group" << std::endl;
		std::cout << "12. Exit" << std::endl;
		std::cout << "Choice: ";

		std::cin >> menuItem;

		if (menuItem == 1)
		{
			ShowInfo();
		}
		
		if (menuItem == 2 || menuItem == 4)
		{
			std::string name;
			std::string privilege;

			std::cin >> name >> privilege;

			AddUserGroupPrivilege(name, privilege);
		}

		if (menuItem == 3 || menuItem == 5)
		{
			std::string name;
			std::string privilege;

			std::cin >> name >> privilege;

			DelUserGroupPrivilege(name, privilege);
		}

		if (menuItem == 6)
		{
			std::string name;
			std::string password;

			std::cin >> name >> password;

			AddUser(name, password);
		}

		if (menuItem == 7)
		{
			std::string name;

			std::cin >> name;

			DelUser(name);
		}

		if (menuItem == 8)
		{
			std::string name;

			std::cin >> name;

			AddGroup(name);
		}

		if (menuItem == 9)
		{
			std::string name;

			std::cin >> name;

			DelGroup(name);
		}

		if (menuItem == 10)
		{
			std::string user;
			std::string group;

			std::cin >> user >> group;

			AddUserToGroup(user, group);
		}

		if (menuItem == 11)
		{
			std::string user;
			std::string group;

			std::cin >> user >> group;

			DelUserFromGroup(user, group);
		}

		if (menuItem == 12)
		{
			return;
		}

		_getch();
		system("cls");
	}
}