/*
 * AGTR Anti-Cheat - dinput8.dll Proxy
 * ====================================
 * Bu DLL tetiklendiğinde winmm.dll'i yükler.
 * winmm.dll tam tarama yapar.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

// COM tipleri - sadece pointer olarak kullanılıyor
#ifndef LPUNKNOWN
typedef void* LPUNKNOWN;
#endif

// Orijinal dinput8.dll fonksiyonları
typedef HRESULT (WINAPI *DirectInput8Create_t)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
typedef HRESULT (WINAPI *DllCanUnloadNow_t)(void);
typedef HRESULT (WINAPI *DllGetClassObject_t)(REFCLSID, REFIID, LPVOID*);

static HMODULE g_hOriginalDLL = NULL;
static HMODULE g_hWinmmDLL = NULL;  // AGTR winmm.dll
static DirectInput8Create_t g_pDirectInput8Create = NULL;
static DllCanUnloadNow_t g_pDllCanUnloadNow = NULL;
static DllGetClassObject_t g_pDllGetClassObject = NULL;

static bool g_bInitialized = false;
static char g_szLogPath[MAX_PATH] = {0};

void LogWrite(const char* fmt, ...) {
    if (g_szLogPath[0] == 0) {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        char* slash = strrchr(path, '\\');
        if (slash) *(slash + 1) = 0;
        sprintf(g_szLogPath, "%sagtr_client.log", path);
    }
    
    FILE* f = fopen(g_szLogPath, "a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%02d:%02d:%02d][dinput8] ", st.wHour, st.wMinute, st.wSecond);
        
        va_list args;
        va_start(args, fmt);
        vfprintf(f, fmt, args);
        va_end(args);
        
        fprintf(f, "\n");
        fclose(f);
    }
}

void LoadAGTRWinmm() {
    if (g_hWinmmDLL) return;
    
    // Aynı klasördeki winmm.dll'i yükle (AGTR)
    char dllPath[MAX_PATH];
    GetModuleFileNameA(NULL, dllPath, MAX_PATH);
    char* slash = strrchr(dllPath, '\\');
    if (slash) *(slash + 1) = 0;
    strcat(dllPath, "winmm.dll");
    
    // Dosya var mı kontrol et
    if (GetFileAttributesA(dllPath) != INVALID_FILE_ATTRIBUTES) {
        g_hWinmmDLL = LoadLibraryA(dllPath);
        if (g_hWinmmDLL) {
            LogWrite("Loaded AGTR winmm.dll - full scan enabled");
        } else {
            LogWrite("WARNING: Could not load winmm.dll: %d", GetLastError());
        }
    } else {
        LogWrite("WARNING: winmm.dll not found in game folder");
    }
}

bool LoadOriginalDLL() {
    if (g_hOriginalDLL) return true;
    
    char systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    strcat(systemPath, "\\dinput8.dll");
    
    g_hOriginalDLL = LoadLibraryA(systemPath);
    if (!g_hOriginalDLL) {
        LogWrite("ERROR: Cannot load original dinput8.dll");
        return false;
    }
    
    g_pDirectInput8Create = (DirectInput8Create_t)GetProcAddress(g_hOriginalDLL, "DirectInput8Create");
    g_pDllCanUnloadNow = (DllCanUnloadNow_t)GetProcAddress(g_hOriginalDLL, "DllCanUnloadNow");
    g_pDllGetClassObject = (DllGetClassObject_t)GetProcAddress(g_hOriginalDLL, "DllGetClassObject");
    
    return true;
}

extern "C" {

__declspec(dllexport) HRESULT WINAPI DirectInput8Create(HINSTANCE hinst, DWORD dwVersion, REFIID riidltf, LPVOID* ppvOut, LPUNKNOWN punkOuter) {
    if (!g_bInitialized) {
        g_bInitialized = true;
        LoadOriginalDLL();
        LoadAGTRWinmm();  // winmm.dll'i yükle, AGTR orada başlayacak
    }
    
    if (g_pDirectInput8Create) {
        return g_pDirectInput8Create(hinst, dwVersion, riidltf, ppvOut, punkOuter);
    }
    return E_FAIL;
}

__declspec(dllexport) HRESULT WINAPI DllCanUnloadNow(void) {
    if (g_pDllCanUnloadNow) return g_pDllCanUnloadNow();
    return S_FALSE;
}

__declspec(dllexport) HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (!LoadOriginalDLL()) return E_FAIL;
    if (g_pDllGetClassObject) return g_pDllGetClassObject(rclsid, riid, ppv);
    return E_FAIL;
}

} // extern "C"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            if (g_hOriginalDLL) FreeLibrary(g_hOriginalDLL);
            // winmm.dll'i serbest bırakma - AGTR hala çalışıyor olabilir
            break;
    }
    return TRUE;
}
