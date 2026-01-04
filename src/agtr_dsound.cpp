/*
 * AGTR Anti-Cheat - dsound.dll Proxy
 * ===================================
 * Bu DLL tetiklendiğinde winmm.dll'i yükler.
 * winmm.dll tam tarama yapar.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>  // LPUNKNOWN, LPCGUID için
#include <stdio.h>

// Orijinal dsound.dll fonksiyonları
typedef HRESULT (WINAPI *DirectSoundCreate_t)(LPCGUID, LPVOID*, LPUNKNOWN);
typedef HRESULT (WINAPI *DirectSoundCreate8_t)(LPCGUID, LPVOID*, LPUNKNOWN);
typedef HRESULT (WINAPI *DirectSoundEnumerateA_t)(LPVOID, LPVOID);
typedef HRESULT (WINAPI *DirectSoundEnumerateW_t)(LPVOID, LPVOID);
typedef HRESULT (WINAPI *DirectSoundCaptureCreate_t)(LPCGUID, LPVOID*, LPUNKNOWN);
typedef HRESULT (WINAPI *DirectSoundCaptureCreate8_t)(LPCGUID, LPVOID*, LPUNKNOWN);
typedef HRESULT (WINAPI *DirectSoundCaptureEnumerateA_t)(LPVOID, LPVOID);
typedef HRESULT (WINAPI *DirectSoundCaptureEnumerateW_t)(LPVOID, LPVOID);
typedef HRESULT (WINAPI *GetDeviceID_t)(LPCGUID, LPGUID);
typedef HRESULT (WINAPI *DirectSoundFullDuplexCreate_t)(LPCGUID, LPCGUID, LPVOID, LPVOID, HWND, DWORD, LPVOID*, LPVOID*, LPVOID*, LPUNKNOWN);
typedef HRESULT (WINAPI *DllCanUnloadNow_t)(void);
typedef HRESULT (WINAPI *DllGetClassObject_t)(REFCLSID, REFIID, LPVOID*);

static HMODULE g_hOriginalDLL = NULL;
static HMODULE g_hWinmmDLL = NULL;
static DirectSoundCreate_t g_pDirectSoundCreate = NULL;
static DirectSoundCreate8_t g_pDirectSoundCreate8 = NULL;
static DirectSoundEnumerateA_t g_pDirectSoundEnumerateA = NULL;
static DirectSoundEnumerateW_t g_pDirectSoundEnumerateW = NULL;
static DirectSoundCaptureCreate_t g_pDirectSoundCaptureCreate = NULL;
static DirectSoundCaptureCreate8_t g_pDirectSoundCaptureCreate8 = NULL;
static DirectSoundCaptureEnumerateA_t g_pDirectSoundCaptureEnumerateA = NULL;
static DirectSoundCaptureEnumerateW_t g_pDirectSoundCaptureEnumerateW = NULL;
static GetDeviceID_t g_pGetDeviceID = NULL;
static DirectSoundFullDuplexCreate_t g_pDirectSoundFullDuplexCreate = NULL;
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
        fprintf(f, "[%02d:%02d:%02d][dsound] ", st.wHour, st.wMinute, st.wSecond);
        
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
    
    char dllPath[MAX_PATH];
    GetModuleFileNameA(NULL, dllPath, MAX_PATH);
    char* slash = strrchr(dllPath, '\\');
    if (slash) *(slash + 1) = 0;
    strcat(dllPath, "winmm.dll");
    
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
    strcat(systemPath, "\\dsound.dll");
    
    g_hOriginalDLL = LoadLibraryA(systemPath);
    if (!g_hOriginalDLL) {
        LogWrite("ERROR: Cannot load original dsound.dll");
        return false;
    }
    
    g_pDirectSoundCreate = (DirectSoundCreate_t)GetProcAddress(g_hOriginalDLL, "DirectSoundCreate");
    g_pDirectSoundCreate8 = (DirectSoundCreate8_t)GetProcAddress(g_hOriginalDLL, "DirectSoundCreate8");
    g_pDirectSoundEnumerateA = (DirectSoundEnumerateA_t)GetProcAddress(g_hOriginalDLL, "DirectSoundEnumerateA");
    g_pDirectSoundEnumerateW = (DirectSoundEnumerateW_t)GetProcAddress(g_hOriginalDLL, "DirectSoundEnumerateW");
    g_pDirectSoundCaptureCreate = (DirectSoundCaptureCreate_t)GetProcAddress(g_hOriginalDLL, "DirectSoundCaptureCreate");
    g_pDirectSoundCaptureCreate8 = (DirectSoundCaptureCreate8_t)GetProcAddress(g_hOriginalDLL, "DirectSoundCaptureCreate8");
    g_pDirectSoundCaptureEnumerateA = (DirectSoundCaptureEnumerateA_t)GetProcAddress(g_hOriginalDLL, "DirectSoundCaptureEnumerateA");
    g_pDirectSoundCaptureEnumerateW = (DirectSoundCaptureEnumerateW_t)GetProcAddress(g_hOriginalDLL, "DirectSoundCaptureEnumerateW");
    g_pGetDeviceID = (GetDeviceID_t)GetProcAddress(g_hOriginalDLL, "GetDeviceID");
    g_pDirectSoundFullDuplexCreate = (DirectSoundFullDuplexCreate_t)GetProcAddress(g_hOriginalDLL, "DirectSoundFullDuplexCreate");
    g_pDllCanUnloadNow = (DllCanUnloadNow_t)GetProcAddress(g_hOriginalDLL, "DllCanUnloadNow");
    g_pDllGetClassObject = (DllGetClassObject_t)GetProcAddress(g_hOriginalDLL, "DllGetClassObject");
    
    return true;
}

extern "C" {

__declspec(dllexport) HRESULT WINAPI DirectSoundCreate(LPCGUID pcGuidDevice, LPVOID *ppDS, LPUNKNOWN pUnkOuter) {
    if (!g_bInitialized) {
        g_bInitialized = true;
        LoadOriginalDLL();
        LoadAGTRWinmm();
    }
    if (g_pDirectSoundCreate) return g_pDirectSoundCreate(pcGuidDevice, ppDS, pUnkOuter);
    return E_FAIL;
}

__declspec(dllexport) HRESULT WINAPI DirectSoundCreate8(LPCGUID pcGuidDevice, LPVOID *ppDS8, LPUNKNOWN pUnkOuter) {
    if (!g_bInitialized) {
        g_bInitialized = true;
        LoadOriginalDLL();
        LoadAGTRWinmm();
    }
    if (g_pDirectSoundCreate8) return g_pDirectSoundCreate8(pcGuidDevice, ppDS8, pUnkOuter);
    return E_FAIL;
}

__declspec(dllexport) HRESULT WINAPI DirectSoundEnumerateA(LPVOID pDSEnumCallback, LPVOID pContext) {
    if (!LoadOriginalDLL()) return E_FAIL;
    if (g_pDirectSoundEnumerateA) return g_pDirectSoundEnumerateA(pDSEnumCallback, pContext);
    return E_FAIL;
}

__declspec(dllexport) HRESULT WINAPI DirectSoundEnumerateW(LPVOID pDSEnumCallback, LPVOID pContext) {
    if (!LoadOriginalDLL()) return E_FAIL;
    if (g_pDirectSoundEnumerateW) return g_pDirectSoundEnumerateW(pDSEnumCallback, pContext);
    return E_FAIL;
}

__declspec(dllexport) HRESULT WINAPI DirectSoundCaptureCreate(LPCGUID pcGuidDevice, LPVOID *ppDSC, LPUNKNOWN pUnkOuter) {
    if (!LoadOriginalDLL()) return E_FAIL;
    if (g_pDirectSoundCaptureCreate) return g_pDirectSoundCaptureCreate(pcGuidDevice, ppDSC, pUnkOuter);
    return E_FAIL;
}

__declspec(dllexport) HRESULT WINAPI DirectSoundCaptureCreate8(LPCGUID pcGuidDevice, LPVOID *ppDSC8, LPUNKNOWN pUnkOuter) {
    if (!LoadOriginalDLL()) return E_FAIL;
    if (g_pDirectSoundCaptureCreate8) return g_pDirectSoundCaptureCreate8(pcGuidDevice, ppDSC8, pUnkOuter);
    return E_FAIL;
}

__declspec(dllexport) HRESULT WINAPI DirectSoundCaptureEnumerateA(LPVOID pDSEnumCallback, LPVOID pContext) {
    if (!LoadOriginalDLL()) return E_FAIL;
    if (g_pDirectSoundCaptureEnumerateA) return g_pDirectSoundCaptureEnumerateA(pDSEnumCallback, pContext);
    return E_FAIL;
}

__declspec(dllexport) HRESULT WINAPI DirectSoundCaptureEnumerateW(LPVOID pDSEnumCallback, LPVOID pContext) {
    if (!LoadOriginalDLL()) return E_FAIL;
    if (g_pDirectSoundCaptureEnumerateW) return g_pDirectSoundCaptureEnumerateW(pDSEnumCallback, pContext);
    return E_FAIL;
}

__declspec(dllexport) HRESULT WINAPI GetDeviceID(LPCGUID pGuidSrc, LPGUID pGuidDest) {
    if (!LoadOriginalDLL()) return E_FAIL;
    if (g_pGetDeviceID) return g_pGetDeviceID(pGuidSrc, pGuidDest);
    return E_FAIL;
}

__declspec(dllexport) HRESULT WINAPI DirectSoundFullDuplexCreate(LPCGUID pcGuidCaptureDevice, LPCGUID pcGuidRenderDevice,
    LPVOID pcDSCBufferDesc, LPVOID pcDSBufferDesc, HWND hWnd, DWORD dwLevel,
    LPVOID* ppDSFD, LPVOID *ppDSCBuffer8, LPVOID *ppDSBuffer8, LPUNKNOWN pUnkOuter) {
    if (!LoadOriginalDLL()) return E_FAIL;
    if (g_pDirectSoundFullDuplexCreate) 
        return g_pDirectSoundFullDuplexCreate(pcGuidCaptureDevice, pcGuidRenderDevice, pcDSCBufferDesc, 
            pcDSBufferDesc, hWnd, dwLevel, ppDSFD, ppDSCBuffer8, ppDSBuffer8, pUnkOuter);
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
            break;
    }
    return TRUE;
}
