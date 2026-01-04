/*
 * AGTR Anti-Cheat - Shared Header
 * ================================
 * Tüm DLL proxy'leri bu header'ı kullanır.
 * Mutex ile sadece BİR DLL'in AGTR thread'i çalışır.
 */

#ifndef AGTR_SHARED_H
#define AGTR_SHARED_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdarg.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// ============================================
// CONFIG
// ============================================
#define API_HOST        L"185.171.25.137"
#define API_PORT        5000
#define CLIENT_VERSION  "12.0"
#define LOG_FILE        "agtr_client.log"
#define MUTEX_NAME      "Global\\AGTR_AntiCheat_Mutex"

// ============================================
// GLOBALS
// ============================================
static char g_szHWID[65] = {0};
static char g_szLogPath[MAX_PATH] = {0};
static HANDLE g_hMutex = NULL;
static HANDLE g_hThread = NULL;
static bool g_bAGTROwner = false;  // Bu DLL AGTR'yi başlattı mı?

// ============================================
// LOGGING
// ============================================
static void LogWrite(const char* trigger, const char* fmt, ...) {
    if (g_szLogPath[0] == 0) {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        char* slash = strrchr(path, '\\');
        if (slash) *(slash + 1) = 0;
        sprintf(g_szLogPath, "%s%s", path, LOG_FILE);
    }
    
    FILE* f = fopen(g_szLogPath, "a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%02d:%02d:%02d][%s] ", st.wHour, st.wMinute, st.wSecond, trigger);
        
        va_list args;
        va_start(args, fmt);
        vfprintf(f, fmt, args);
        va_end(args);
        
        fprintf(f, "\n");
        fclose(f);
    }
}

// ============================================
// HWID GENERATION
// ============================================
static void GenerateHWID() {
    if (g_szHWID[0] != 0) return;  // Zaten oluşturulmuş
    
    char volumeSerial[32] = {0};
    DWORD serial = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0)) {
        sprintf(volumeSerial, "%08X", serial);
    }
    
    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    
    char userName[256] = {0};
    size = sizeof(userName);
    GetUserNameA(userName, &size);
    
    char combined[512];
    sprintf(combined, "%s-%s-%s-AGTR", volumeSerial, computerName, userName);
    
    unsigned int hash1 = 0, hash2 = 0;
    for (int i = 0; combined[i]; i++) {
        hash1 = hash1 * 31 + combined[i];
        hash2 = hash2 * 37 + combined[i];
    }
    
    sprintf(g_szHWID, "%08X%08X%08X%08X", hash1, hash2, hash1 ^ hash2, hash1 + hash2);
}

// ============================================
// HTTP POST
// ============================================
static bool HttpPost(const wchar_t* path, const char* data, char* response, int respSize) {
    HINTERNET hSession = WinHttpOpen(L"AGTR/12.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
    
    HINTERNET hConnect = WinHttpConnect(hSession, API_HOST, API_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    
    DWORD timeout = 5000;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    
    const wchar_t* headers = L"Content-Type: application/json\r\n";
    BOOL result = WinHttpSendRequest(hRequest, headers, -1, (LPVOID)data, strlen(data), strlen(data), 0);
    
    if (result) result = WinHttpReceiveResponse(hRequest, NULL);
    
    if (result && response && respSize > 0) {
        DWORD bytesRead = 0;
        WinHttpReadData(hRequest, response, respSize - 1, &bytesRead);
        response[bytesRead] = 0;
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return result == TRUE;
}

// ============================================
// GAME STATE
// ============================================
static bool IsInServer() {
    char title[256];
    HWND hwnd = FindWindowA("Valve001", NULL);
    if (hwnd && GetWindowTextA(hwnd, title, sizeof(title))) {
        return strstr(title, " - ") != NULL;
    }
    return false;
}

// ============================================
// TRY TO BECOME AGTR OWNER
// ============================================
static bool TryBecomeAGTROwner(const char* triggerName) {
    // Mutex oluştur veya aç
    g_hMutex = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    
    if (g_hMutex == NULL) {
        LogWrite(triggerName, "ERROR: Cannot create mutex");
        return false;
    }
    
    // Mutex'i almayı dene (0ms timeout - anında)
    DWORD result = WaitForSingleObject(g_hMutex, 0);
    
    if (result == WAIT_OBJECT_0 || result == WAIT_ABANDONED) {
        // Bu DLL owner oldu!
        g_bAGTROwner = true;
        LogWrite(triggerName, "AGTR Owner - This DLL will run the anti-cheat");
        return true;
    } else {
        // Başka bir DLL zaten çalışıyor
        LogWrite(triggerName, "AGTR already running from another DLL - skipping");
        CloseHandle(g_hMutex);
        g_hMutex = NULL;
        return false;
    }
}

// ============================================
// RELEASE OWNERSHIP
// ============================================
static void ReleaseAGTROwnership() {
    if (g_hMutex && g_bAGTROwner) {
        ReleaseMutex(g_hMutex);
        CloseHandle(g_hMutex);
        g_hMutex = NULL;
        g_bAGTROwner = false;
    }
}

#endif // AGTR_SHARED_H
