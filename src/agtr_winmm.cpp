/*
 * AGTR Anti-Cheat v14.3 - Anti-Bypass Protection
 * ==================================================
 *
 * v14.3 Changes (BYPASS PROTECTION):
 * - Dynamic blacklist fetching from server (can't reverse engineer)
 * - Hybrid detection: dynamic + static fallback
 * - Server-side blacklist updates without DLL recompile
 * - Process/DLL/Window detection uses dynamic lists
 * - Foundation for hash-based detection (v15.0)
 *
 * v14.1.2 Changes:
 * - Fixed compilation error (extern "C" linkage conflict)
 * - Removed conflicting FORWARD_CALL functions
 *
 * v14.1 Changes:
 * - Expanded server port detection range (27000-27200)
 * - Improved server IP detection for all port configurations
 * - Fixed "unknown server" issue in admin panel
 *
 * v14.0 New Features:
 * - Window Enumeration (overlay detection)
 * - String Scanner (memory string search)
 * - DLL Load Monitor (injection detection)
 * - Anti-Blank Screenshot Detection
 * - Code Section Hash Verification
 * - Stack Trace Validation
 * - NtQueryInformation Hook Detection
 * - PEB Manipulation Check
 * - Async Scan Queue
 * - Smart Throttling (FPS-aware)
 * - Memory Pool
 * - Config Hot-Reload
 *
 * BUILD (x86 Developer Command Prompt):
 * cl /O2 /MT /LD /EHsc agtr_winmm.cpp /link /DEF:winmm.def /OUT:winmm.dll ^
 *    winmm.lib winhttp.lib ws2_32.lib iphlpapi.lib psapi.lib advapi32.lib ^
 *    bcrypt.lib crypt32.lib user32.lib gdi32.lib gdiplus.lib shell32.lib ole32.lib
 */

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

// Windows headers (order matters for GDI+)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objidl.h>
#include <gdiplus.h>
#include <mmsystem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ctype.h>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <queue>

#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

// ============================================
// VERSION & CONFIG
// ============================================
#define AGTR_VERSION "14.3"
#define AGTR_HASH_LENGTH 8  // ReChecker uyumlu 8 karakter MD5

// v14.0 Feature Flags
#define WINDOW_ENUM_ENABLED true
#define STRING_SCANNER_ENABLED true
#define DLL_MONITOR_ENABLED true
#define ANTI_BLANK_ENABLED true
#define CODE_HASH_ENABLED true
#define STACK_TRACE_ENABLED true
#define NTQUERY_HOOK_ENABLED true
#define PEB_CHECK_ENABLED true
#define ASYNC_SCAN_ENABLED true
#define SMART_THROTTLE_ENABLED true
#define MEMORY_POOL_ENABLED true
#define HOT_RELOAD_ENABLED true

// v14.3 Feature Flags (Anti-Bypass)
#define DYNAMIC_BLACKLIST_ENABLED true
#define HASH_DETECTION_ENABLED true
#define BEHAVIOR_MONITORING_ENABLED true
#define BLACKLIST_UPDATE_INTERVAL 3600000  // 1 hour

// v14.0 Config
#define SCAN_QUEUE_MAX 32
#define LOW_FPS_THRESHOLD 30
#define CONFIG_CHECK_INTERVAL 30000
#define POOL_BLOCK_SIZE 4096
#define POOL_MAX_BLOCKS 64

// Heartbeat intervals (milliseconds)
#define HEARTBEAT_IN_SERVER 30000      // Serverdeyken 30sn
#define HEARTBEAT_IN_MENU 120000       // Menüdeyken 120sn
#define HEARTBEAT_OFFLINE_RETRY 60000  // API offline ise 60sn

// Throttling
#define THROTTLE_MIN_INTERVAL 300000   // Aynı veriyi 5dk'da bir gönder
#define OFFLINE_CACHE_MAX 10           // Max cache'lenecek request

// API Config
#define API_PORT 5000
#define API_USE_HTTPS false
#define API_TIMEOUT 5000               // 5sn timeout

// v13.0 Feature Flags
#define SCREENSHOT_ENABLED true
#define WEBSOCKET_ENABLED true
#define ENCRYPTION_ENABLED true
#define AUTO_UPDATE_ENABLED true
#define SMA_COMM_ENABLED true
#define KERNEL_DETECTION_ENABLED true
#define INJECTION_DETECTION_ENABLED true

// Security Config
#define SIGNATURE_ENABLED false
#define ANTI_DEBUG_ENABLED true
#define DLL_HASH_ENABLED true

// SMA Communication
#define SMA_SHARED_MEM_NAME "AGTR_SHARED_v14"
#define SMA_SHARED_MEM_SIZE 4096
#define SMA_HEARTBEAT_INTERVAL 5000    // 5 saniyede bir SMA'ya durum bildir

// Screenshot Config
#define SCREENSHOT_QUALITY 50          // JPEG kalitesi (1-100)
#define SCREENSHOT_MAX_SIZE 150000     // Max 150KB

// Auto-Update Config
#define UPDATE_CHECK_INTERVAL 3600000  // 1 saatte bir güncelleme kontrolü

// Encrypted strings (XOR with rotating key)
static const BYTE ENC_KEY[] = {0xA7, 0x3F, 0x8C, 0x51, 0xD2, 0x6E, 0xB9, 0x04};
#define ENC_KEY_LEN 8

// "185.171.25.137" encrypted
static const BYTE ENC_API_HOST[] = {0x96, 0x07, 0xB9, 0x7F, 0xE3, 0x59, 0x88, 0x2A, 0x95, 0x0A, 0xA2, 0x60, 0xE1, 0x59};
#define ENC_API_HOST_LEN 14

// "/api/v1/scan" encrypted  
static const BYTE ENC_PATH_SCAN[] = {0x88, 0x5E, 0xFC, 0x38, 0xFD, 0x18, 0x88, 0x2B, 0xD4, 0x5C, 0xED, 0x3F};
#define ENC_PATH_SCAN_LEN 12

// "AGTR_sign_key!2025" - Signature key (encrypted)
static const BYTE ENC_SIG_KEY[] = {0xE6, 0x78, 0xD8, 0x03, 0x8D, 0x1D, 0xD0, 0x63, 0xC9, 0x60, 0xE7, 0x34, 0xAB, 0x4F, 0x8B, 0x34, 0x95, 0x0A};
#define ENC_SIG_KEY_LEN 18

// "/api/v1/client/register" encrypted
static const BYTE ENC_PATH_REGISTER[] = {0x88, 0x5E, 0xFC, 0x38, 0xFD, 0x18, 0x88, 0x2B, 0xC4, 0x53, 0xE5, 0x34, 0xBC, 0x1A, 0x96, 0x76, 0xC2, 0x58, 0xE5, 0x22, 0xA6, 0x0B, 0xCB};
#define ENC_PATH_REGISTER_LEN 23

// "/api/v1/client/heartbeat" encrypted
static const BYTE ENC_PATH_HEARTBEAT[] = {0x88, 0x5E, 0xFC, 0x38, 0xFD, 0x18, 0x88, 0x2B, 0xC4, 0x53, 0xE5, 0x34, 0xBC, 0x1A, 0x96, 0x6C, 0xC2, 0x5E, 0xFE, 0x25, 0xB0, 0x0B, 0xD8, 0x70};
#define ENC_PATH_HEARTBEAT_LEN 24

// "AGTR/13.0" encrypted (User-Agent)
static const BYTE ENC_USER_AGENT[] = {0xE6, 0x78, 0xD8, 0x03, 0xFD, 0x5F, 0x8A, 0x37, 0x97};
#define ENC_USER_AGENT_LEN 9

// "/api/v1/client/connect" encrypted
static const BYTE ENC_PATH_CONNECT[] = {0x88, 0x5E, 0xFC, 0x38, 0xFD, 0x18, 0x88, 0x2B, 0xC4, 0x53, 0xE5, 0x34, 0xBC, 0x1A, 0x96, 0x67, 0xC8, 0x51, 0xE2, 0x34, 0xB1, 0x1A};
#define ENC_PATH_CONNECT_LEN 22

// v13.0 - New encrypted paths
// "/api/v1/client/screenshot" 
static const BYTE ENC_PATH_SCREENSHOT[] = {0x88, 0x5E, 0xFC, 0x38, 0xFD, 0x18, 0x88, 0x2B, 0xC4, 0x53, 0xE5, 0x34, 0xBC, 0x1A, 0x96, 0x71, 0xC4, 0x43, 0xE6, 0x34, 0xBC, 0x1D, 0x99, 0x60, 0xC5};
#define ENC_PATH_SCREENSHOT_LEN 25

// "/api/v1/client/command"
static const BYTE ENC_PATH_COMMAND[] = {0x88, 0x5E, 0xFC, 0x38, 0xFD, 0x18, 0x88, 0x2B, 0xC4, 0x53, 0xE5, 0x34, 0xBC, 0x1A, 0x96, 0x67, 0xC8, 0x5A, 0xE5, 0x30, 0xBC, 0x0B};
#define ENC_PATH_COMMAND_LEN 22

// "/api/v1/client/update"
static const BYTE ENC_PATH_UPDATE[] = {0x88, 0x5E, 0xFC, 0x38, 0xFD, 0x18, 0x88, 0x2B, 0xC4, 0x53, 0xE5, 0x34, 0xBC, 0x1A, 0x96, 0x75, 0xD5, 0x5D, 0xEB, 0x25, 0xA4};
#define ENC_PATH_UPDATE_LEN 21

// ============================================
// FORWARD DECLARATIONS
// ============================================
void InitSecurity();
void Init();
void StartScanThread();
void Shutdown();
std::string HttpRequest(const wchar_t* path, const std::string& body, const std::string& method = "POST", bool canCache = false);
void Log(const char* fmt, ...);

// ============================================
// DECRYPT FUNCTIONS
// ============================================
static void DecryptString(const BYTE* enc, int len, char* out) {
    for (int i = 0; i < len; i++) {
        out[i] = enc[i] ^ ENC_KEY[i % ENC_KEY_LEN];
    }
    out[len] = 0;
}

static void DecryptStringW(const BYTE* enc, int len, wchar_t* out) {
    for (int i = 0; i < len; i++) {
        out[i] = (wchar_t)(enc[i] ^ ENC_KEY[i % ENC_KEY_LEN]);
    }
    out[len] = 0;
}

// Runtime decrypted values
static wchar_t g_szAPIHost[32] = {0};
static wchar_t g_szPathScan[64] = {0};
static wchar_t g_szPathRegister[64] = {0};
static wchar_t g_szPathHeartbeat[64] = {0};
static wchar_t g_szPathConnect[64] = {0};
static wchar_t g_szPathScreenshot[64] = {0};
static wchar_t g_szPathCommand[64] = {0};
static wchar_t g_szPathUpdate[64] = {0};
static wchar_t g_szUserAgent[32] = {0};
static bool g_bStringsDecrypted = false;

// Security globals
static char g_szSelfHash[65] = {0};
static char g_szSelfName[64] = {0};
static char g_szSignatureKey[64] = {0};

// ============================================
// v14.3 - DYNAMIC BLACKLIST GLOBALS
// ============================================
static std::set<std::string> g_DynamicProcBlacklist;
static std::set<std::string> g_DynamicDLLBlacklist;
static std::set<std::string> g_DynamicWindowBlacklist;
static std::set<std::string> g_DynamicStringBlacklist;
static std::map<std::string, std::string> g_HashBlacklist;  // hash -> name
static DWORD g_dwLastBlacklistUpdate = 0;
static bool g_bBlacklistInitialized = false;
static CRITICAL_SECTION g_csBlacklist;

// v14.3 - Behavior monitoring
struct BehaviorCounter {
    int suspiciousAPICalls;
    DWORD lastReset;

    BehaviorCounter() : suspiciousAPICalls(0), lastReset(GetTickCount()) {}

    void Increment() {
        suspiciousAPICalls++;
    }

    void Reset() {
        suspiciousAPICalls = 0;
        lastReset = GetTickCount();
    }

    int GetScore() {
        return suspiciousAPICalls * 5;
    }

    bool ShouldReset() {
        return (GetTickCount() - lastReset) > 300000;  // 5 minutes
    }
};

static BehaviorCounter g_BehaviorCounter;

static void EnsureStringsDecrypted() {
    if (g_bStringsDecrypted) return;
    DecryptStringW(ENC_API_HOST, ENC_API_HOST_LEN, g_szAPIHost);
    DecryptStringW(ENC_PATH_SCAN, ENC_PATH_SCAN_LEN, g_szPathScan);
    DecryptStringW(ENC_PATH_REGISTER, ENC_PATH_REGISTER_LEN, g_szPathRegister);
    DecryptStringW(ENC_PATH_HEARTBEAT, ENC_PATH_HEARTBEAT_LEN, g_szPathHeartbeat);
    DecryptStringW(ENC_PATH_CONNECT, ENC_PATH_CONNECT_LEN, g_szPathConnect);
    DecryptStringW(ENC_PATH_SCREENSHOT, ENC_PATH_SCREENSHOT_LEN, g_szPathScreenshot);
    DecryptStringW(ENC_PATH_COMMAND, ENC_PATH_COMMAND_LEN, g_szPathCommand);
    DecryptStringW(ENC_PATH_UPDATE, ENC_PATH_UPDATE_LEN, g_szPathUpdate);
    DecryptStringW(ENC_USER_AGENT, ENC_USER_AGENT_LEN, g_szUserAgent);
    DecryptString(ENC_SIG_KEY, ENC_SIG_KEY_LEN, g_szSignatureKey);
    g_bStringsDecrypted = true;
}

// ============================================
// v14.0 - MEMORY POOL
// ============================================
struct MemoryPool {
    BYTE* blocks[POOL_MAX_BLOCKS];
    bool used[POOL_MAX_BLOCKS];
    CRITICAL_SECTION cs;
    int totalBlocks;
    
    void Init() {
        InitializeCriticalSection(&cs);
        totalBlocks = 0;
        memset(blocks, 0, sizeof(blocks));
        memset(used, 0, sizeof(used));
        for (int i = 0; i < 16; i++) {
            blocks[i] = (BYTE*)VirtualAlloc(NULL, POOL_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (blocks[i]) totalBlocks++;
        }
    }
    
    void* Alloc(size_t size) {
        if (size > POOL_BLOCK_SIZE) return malloc(size);
        EnterCriticalSection(&cs);
        for (int i = 0; i < totalBlocks; i++) {
            if (!used[i] && blocks[i]) {
                used[i] = true;
                LeaveCriticalSection(&cs);
                return blocks[i];
            }
        }
        LeaveCriticalSection(&cs);
        return malloc(size);
    }
    
    void Free(void* ptr) {
        if (!ptr) return;
        EnterCriticalSection(&cs);
        for (int i = 0; i < totalBlocks; i++) {
            if (blocks[i] == ptr) {
                used[i] = false;
                memset(blocks[i], 0, POOL_BLOCK_SIZE);
                LeaveCriticalSection(&cs);
                return;
            }
        }
        LeaveCriticalSection(&cs);
        free(ptr);
    }
    
    void Cleanup() {
        EnterCriticalSection(&cs);
        for (int i = 0; i < totalBlocks; i++) {
            if (blocks[i]) { VirtualFree(blocks[i], 0, MEM_RELEASE); blocks[i] = NULL; }
        }
        LeaveCriticalSection(&cs);
        DeleteCriticalSection(&cs);
    }
};
static MemoryPool g_MemPool;
#define POOL_ALLOC(size) (MEMORY_POOL_ENABLED ? g_MemPool.Alloc(size) : malloc(size))
#define POOL_FREE(ptr) (MEMORY_POOL_ENABLED ? g_MemPool.Free(ptr) : free(ptr))

// ============================================
// v14.0 - SMART THROTTLING
// ============================================
static int g_iCurrentFPS = 60;
static int g_iFrameCount = 0;
static DWORD g_dwFrameStartTime = 0;
static bool g_bLowFPSMode = false;

void UpdateFPSCounter() {
    if (!SMART_THROTTLE_ENABLED) return;
    g_iFrameCount++;
    DWORD now = GetTickCount();
    if (now - g_dwFrameStartTime >= 1000) {
        g_iCurrentFPS = g_iFrameCount;
        g_iFrameCount = 0;
        g_dwFrameStartTime = now;
        g_bLowFPSMode = (g_iCurrentFPS < LOW_FPS_THRESHOLD);
    }
}

bool ShouldSkipHeavyScan() { return SMART_THROTTLE_ENABLED && g_iCurrentFPS < 15; }

// ============================================
// v14.0 - ASYNC SCAN QUEUE
// ============================================
enum ScanTaskType { SCAN_WINDOWS_V14=1, SCAN_STRINGS, SCAN_DLL_MON, SCAN_CODE_HASH, SCAN_STACK, SCAN_PEB_CHK };
struct ScanTask { ScanTaskType type; DWORD timestamp; };
static std::queue<ScanTask> g_ScanQueue;
static CRITICAL_SECTION g_csScanQueue;
static bool g_bAsyncInitialized = false;

void InitAsyncScan() {
    if (g_bAsyncInitialized) return;
    InitializeCriticalSection(&g_csScanQueue);
    g_bAsyncInitialized = true;
}

void QueueScan(ScanTaskType type) {
    if (!ASYNC_SCAN_ENABLED || !g_bAsyncInitialized) return;
    EnterCriticalSection(&g_csScanQueue);
    if (g_ScanQueue.size() < SCAN_QUEUE_MAX) {
        ScanTask t; t.type = type; t.timestamp = GetTickCount();
        g_ScanQueue.push(t);
    }
    LeaveCriticalSection(&g_csScanQueue);
}

// ============================================
// v14.0 - ENHANCED WINDOW ENUMERATION
// ============================================
static int g_iOverlayCount = 0;
static int g_iSuspiciousWindowCount = 0;

const char* g_WindowBlacklist[] = {
    "aimbot", "wallhack", "esp", "cheat", "hack", "triggerbot", "norecoil", "bhop",
    "speedhack", "cheat engine", "artmoney", "process hacker", "x64dbg", "ollydbg",
    "injector", "inject", "loader", "overlay", "imgui", "external", "radar", NULL
};

BOOL CALLBACK EnumWindowsCallback_v14(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;
    char title[256] = {0}, className[128] = {0};
    GetWindowTextA(hwnd, title, 255);
    GetClassNameA(hwnd, className, 127);
    if (!title[0] && !className[0]) return TRUE;
    
    DWORD exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
    bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
    bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
    bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
    
    // Overlay detection
    if (isTopmost && isLayered && isTransparent) {
        g_iOverlayCount++;
        Log("[WINDOW] Overlay: '%s' [%s]", title, className);
    }
    
    // Blacklist check
    char titleLower[256];
    strcpy(titleLower, title);
    for (char* p = titleLower; *p; p++) *p = tolower(*p);
    
    for (int i = 0; g_WindowBlacklist[i]; i++) {
        if (strstr(titleLower, g_WindowBlacklist[i])) {
            g_iSuspiciousWindowCount++;
            Log("[WINDOW] Suspicious: '%s' matched '%s'", title, g_WindowBlacklist[i]);
            break;
        }
    }
    return TRUE;
}

int ScanWindows_v14() {
    if (!WINDOW_ENUM_ENABLED) return 0;
    g_iOverlayCount = 0;
    g_iSuspiciousWindowCount = 0;
    EnumWindows(EnumWindowsCallback_v14, 0);
    return g_iSuspiciousWindowCount + g_iOverlayCount;
}

// ============================================
// v14.0 - STRING SCANNER
// ============================================
const char* g_SuspiciousStrings[] = {
    "aimbot", "aim_bot", "wallhack", "esp_draw", "esp_box", "triggerbot",
    "norecoil", "no_recoil", "bhop", "speedhack", "godmode", "cheat_enable",
    "imgui::begin", "d3d9_hook", "opengl_hook", "present_hook", NULL
};

int ScanMemoryStrings() {
    if (!STRING_SCANNER_ENABLED) return 0;
    int found = 0;
    HANDLE hProc = GetCurrentProcess();
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;
    
    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize <= 2*1024*1024 &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            BYTE* buf = (BYTE*)POOL_ALLOC(mbi.RegionSize);
            if (buf) {
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProc, mbi.BaseAddress, buf, mbi.RegionSize, &bytesRead)) {
                    for (int i = 0; g_SuspiciousStrings[i]; i++) {
                        const char* needle = g_SuspiciousStrings[i];
                        size_t nLen = strlen(needle);
                        for (size_t j = 0; j + nLen <= bytesRead; j++) {
                            bool match = true;
                            for (size_t k = 0; k < nLen; k++) {
                                if (tolower(buf[j+k]) != tolower(needle[k])) { match = false; break; }
                            }
                            if (match) {
                                Log("[STRING] Found '%s' at 0x%p", needle, (void*)((BYTE*)mbi.BaseAddress + j));
                                found++; j += nLen;
                            }
                        }
                    }
                }
                POOL_FREE(buf);
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    return found;
}

// ============================================
// v14.0 - DLL LOAD MONITOR
// ============================================
static std::vector<std::string> g_KnownDLLs;
static CRITICAL_SECTION g_csDLLMon;
static bool g_bDLLMonInit = false;

const char* g_SusDLLNames[] = {"hook", "inject", "cheat", "hack", "aimbot", "trainer", "minhook", NULL};

void InitDLLMonitor() {
    if (g_bDLLMonInit || !DLL_MONITOR_ENABLED) return;
    InitializeCriticalSection(&g_csDLLMon);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me; me.dwSize = sizeof(me);
        if (Module32First(hSnap, &me)) {
            do { g_KnownDLLs.push_back(me.szModule); } while (Module32Next(hSnap, &me));
        }
        CloseHandle(hSnap);
    }
    g_bDLLMonInit = true;
    Log("[DLLMON] Init with %d DLLs", (int)g_KnownDLLs.size());
}

int CheckNewDLLs() {
    if (!DLL_MONITOR_ENABLED || !g_bDLLMonInit) return 0;
    int suspicious = 0;
    EnterCriticalSection(&g_csDLLMon);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me; me.dwSize = sizeof(me);
        if (Module32First(hSnap, &me)) {
            do {
                bool known = false;
                for (auto& k : g_KnownDLLs) if (_stricmp(k.c_str(), me.szModule) == 0) { known = true; break; }
                if (!known) {
                    g_KnownDLLs.push_back(me.szModule);
                    char lower[256]; strcpy(lower, me.szModule);
                    for (char* p = lower; *p; p++) *p = tolower(*p);
                    for (int i = 0; g_SusDLLNames[i]; i++) {
                        if (strstr(lower, g_SusDLLNames[i])) {
                            Log("[DLLMON] !!! SUSPICIOUS: %s", me.szModule);
                            suspicious++;
                            break;
                        }
                    }
                }
            } while (Module32Next(hSnap, &me));
        }
        CloseHandle(hSnap);
    }
    LeaveCriticalSection(&g_csDLLMon);
    return suspicious;
}

// ============================================
// v14.0 - CODE SECTION HASH
// ============================================
static DWORD g_dwCodeSectionHash = 0;
static bool g_bCodeHashInit = false;

DWORD CalcSectionHash(BYTE* data, DWORD size) {
    DWORD hash = 0x811C9DC5;
    for (DWORD i = 0; i < size; i++) { hash ^= data[i]; hash *= 0x01000193; }
    return hash;
}

void InitCodeHash() {
    if (g_bCodeHashInit || !CODE_HASH_ENABLED) return;
    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return;
    PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)hMod;
    if (pDOS->e_magic != IMAGE_DOS_SIGNATURE) return;
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDOS->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNT);
    for (WORD i = 0; i < pNT->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSec[i].Name, ".text") == 0) {
            g_dwCodeSectionHash = CalcSectionHash((BYTE*)hMod + pSec[i].VirtualAddress, pSec[i].Misc.VirtualSize);
            Log("[CODEHASH] .text hash: 0x%08X", g_dwCodeSectionHash);
            break;
        }
    }
    g_bCodeHashInit = true;
}

int VerifyCodeSection() {
    if (!CODE_HASH_ENABLED || !g_bCodeHashInit) return 0;
    HMODULE hMod = GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDOS->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNT);
    for (WORD i = 0; i < pNT->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSec[i].Name, ".text") == 0) {
            DWORD cur = CalcSectionHash((BYTE*)hMod + pSec[i].VirtualAddress, pSec[i].Misc.VirtualSize);
            if (cur != g_dwCodeSectionHash) {
                Log("[CODEHASH] !!! MODIFIED: was 0x%08X now 0x%08X", g_dwCodeSectionHash, cur);
                return 1;
            }
            break;
        }
    }
    return 0;
}

// ============================================
// v14.0 - STACK TRACE VALIDATION
// ============================================
bool ValidateStackTrace() {
    if (!STACK_TRACE_ENABLED) return true;
    void* stack[32];
    WORD frames = CaptureStackBackTrace(0, 32, stack, NULL);
    HMODULE hMain = GetModuleHandleA(NULL);
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    
    for (WORD i = 0; i < frames; i++) {
        HMODULE hMod;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)stack[i], &hMod)) {
            if (hMod != hMain && hMod != hK32 && hMod != hNt) {
                char path[MAX_PATH]; GetModuleFileNameA(hMod, path, MAX_PATH);
                char* fn = strrchr(path, '\\'); if (fn) fn++; else fn = path;
                if (_stricmp(fn, "user32.dll") && _stricmp(fn, "gdi32.dll") && 
                    _stricmp(fn, "msvcrt.dll") && _stricmp(fn, "winmm.dll")) {
                    Log("[STACK] Unknown in callstack: %s", fn);
                    return false;
                }
            }
        }
    }
    return true;
}

// ============================================
// v14.0 - NtQuery HOOK DETECTION
// ============================================
bool CheckNtQueryHooks() {
    if (!NTQUERY_HOOK_ENABLED) return false;
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (!hNt) return false;
    const char* funcs[] = {"NtQueryInformationProcess", "NtQuerySystemInformation", "NtQueryVirtualMemory", NULL};
    for (int i = 0; funcs[i]; i++) {
        BYTE* p = (BYTE*)GetProcAddress(hNt, funcs[i]);
        if (p && (p[0] == 0xE9 || (p[0] == 0xFF && p[1] == 0x25) || (p[0] == 0x68 && p[5] == 0xC3))) {
            Log("[NTQUERY] Hook on %s", funcs[i]);
            return true;
        }
    }
    return false;
}

// ============================================
// v14.0 - PEB MANIPULATION CHECK
// ============================================
bool CheckPEBManipulation() {
    if (!PEB_CHECK_ENABLED) return false;
#ifdef _WIN64
    BYTE* pPeb = (BYTE*)__readgsqword(0x60);
    DWORD ntFlag = *(DWORD*)(pPeb + 0xBC);
#else
    BYTE* pPeb = (BYTE*)__readfsdword(0x30);
    DWORD ntFlag = *(DWORD*)(pPeb + 0x68);
#endif
    if (pPeb[2]) { Log("[PEB] BeingDebugged set!"); return true; }
    if (ntFlag & 0x70) { Log("[PEB] NtGlobalFlag: 0x%X", ntFlag); return true; }
    return false;
}

// ============================================
// v14.0 - ANTI-BLANK SCREENSHOT
// ============================================
static int g_iBlankSSCount = 0;

bool IsScreenshotBlank(const BYTE* data, int w, int h, int stride) {
    if (!ANTI_BLANK_ENABLED || !data) return false;
    int diff = 0;
    DWORD first = *(DWORD*)data & 0xFFFFFF;
    for (int i = 0; i < 50; i++) {
        int x = rand() % w, y = rand() % h;
        DWORD c = *(DWORD*)(data + y*stride + x*4) & 0xFFFFFF;
        if (c != first) diff++;
    }
    if (diff < 3) { Log("[ANTIBLANK] Screenshot blank!"); g_iBlankSSCount++; return true; }
    return false;
}

// ============================================
// v14.0 - CONFIG HOT-RELOAD
// ============================================
static DWORD g_dwConfigFileTime = 0;
static char g_szConfigPath[MAX_PATH] = {0};

struct RuntimeConfig {
    bool scan_enabled = true;
    int scan_interval = 120000;
    bool scan_windows = true;
    bool scan_strings = true;
    bool scan_dlls = true;
};
static RuntimeConfig g_RTConfig;

void LoadConfig(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return;
    char line[256];
    while (fgets(line, 255, f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char k[64], v[128];
        if (sscanf(line, "%63[^=]=%127s", k, v) == 2) {
            if (!strcmp(k, "scan_enabled")) g_RTConfig.scan_enabled = (v[0] == '1' || v[0] == 't');
            else if (!strcmp(k, "scan_interval")) g_RTConfig.scan_interval = atoi(v);
            else if (!strcmp(k, "scan_windows")) g_RTConfig.scan_windows = (v[0] == '1' || v[0] == 't');
            else if (!strcmp(k, "scan_strings")) g_RTConfig.scan_strings = (v[0] == '1' || v[0] == 't');
            else if (!strcmp(k, "scan_dlls")) g_RTConfig.scan_dlls = (v[0] == '1' || v[0] == 't');
        }
    }
    fclose(f);
    Log("[CONFIG] Loaded from %s", path);
}

void CheckConfigReload() {
    if (!HOT_RELOAD_ENABLED || !g_szConfigPath[0]) return;
    WIN32_FILE_ATTRIBUTE_DATA fi;
    if (GetFileAttributesExA(g_szConfigPath, GetFileExInfoStandard, &fi)) {
        if (fi.ftLastWriteTime.dwLowDateTime != g_dwConfigFileTime) {
            g_dwConfigFileTime = fi.ftLastWriteTime.dwLowDateTime;
            LoadConfig(g_szConfigPath);
        }
    }
}

void InitConfigReload(const char* gameDir) {
    snprintf(g_szConfigPath, MAX_PATH, "%s\\agtr_config.ini", gameDir);
    LoadConfig(g_szConfigPath);
    WIN32_FILE_ATTRIBUTE_DATA fi;
    if (GetFileAttributesExA(g_szConfigPath, GetFileExInfoStandard, &fi))
        g_dwConfigFileTime = fi.ftLastWriteTime.dwLowDateTime;
}

// ============================================
// v13.0 - SMA PLUGIN COMMUNICATION (Shared Memory)
// ============================================
#pragma pack(push, 1)
struct SMASharedData {
    // Header
    DWORD magic;              // 0x41475452 = "AGTR"
    DWORD version;            // 13
    DWORD timestamp;          // Son güncelleme zamanı
    
    // Player Info
    char hwid[64];            // Hardware ID
    char steamid[64];         // STEAM_X:Y:Z
    char steam_name[64];      // Steam kullanıcı adı
    char ip[32];              // Oyuncu IP
    
    // Status
    BYTE dll_loaded;          // 1 = DLL yüklü ve aktif
    BYTE scan_passed;         // 1 = Son scan temiz
    BYTE is_banned;           // 1 = Banlı
    BYTE is_whitelisted;      // 1 = Whitelist'te
    
    // Scan Results
    DWORD sus_count;          // Şüpheli sayısı
    DWORD last_scan_time;     // Son scan zamanı (Unix timestamp)
    char last_scan_result[256]; // Son scan sonucu özeti
    
    // DLL Info
    char dll_hash[16];        // DLL hash (8 karakter + null)
    char dll_version[16];     // DLL versiyon
    
    // Security Flags
    BYTE debugger_detected;
    BYTE vm_detected;
    BYTE hooks_detected;
    BYTE injection_detected;
    
    // Commands (API -> DLL)
    BYTE cmd_take_screenshot; // 1 = Screenshot al
    BYTE cmd_force_scan;      // 1 = Hemen scan yap
    BYTE cmd_disconnect;      // 1 = Oyuncuyu kov
    BYTE cmd_reserved;
    
    // Reserved for future use
    BYTE reserved[256];
};
#pragma pack(pop)

static HANDLE g_hSharedMem = NULL;
static SMASharedData* g_pSharedData = NULL;
static DWORD g_dwLastSMAUpdate = 0;

bool InitSMASharedMemory() {
    if (!SMA_COMM_ENABLED) return false;
    
    // Create or open shared memory
    g_hSharedMem = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        SMA_SHARED_MEM_SIZE,
        SMA_SHARED_MEM_NAME
    );
    
    if (!g_hSharedMem) {
        Log("SMA: Failed to create shared memory: %d", GetLastError());
        return false;
    }
    
    g_pSharedData = (SMASharedData*)MapViewOfFile(
        g_hSharedMem,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        sizeof(SMASharedData)
    );
    
    if (!g_pSharedData) {
        Log("SMA: Failed to map shared memory: %d", GetLastError());
        CloseHandle(g_hSharedMem);
        g_hSharedMem = NULL;
        return false;
    }
    
    // Initialize
    memset(g_pSharedData, 0, sizeof(SMASharedData));
    g_pSharedData->magic = 0x41475452; // "AGTR"
    g_pSharedData->version = 13;
    g_pSharedData->dll_loaded = 1;
    strcpy(g_pSharedData->dll_version, AGTR_VERSION);
    
    Log("SMA: Shared memory initialized");
    return true;
}

void UpdateSMASharedData() {
    if (!g_pSharedData) return;
    
    DWORD now = GetTickCount();
    if (now - g_dwLastSMAUpdate < SMA_HEARTBEAT_INTERVAL) return;
    g_dwLastSMAUpdate = now;
    
    // Update timestamp
    g_pSharedData->timestamp = (DWORD)time(NULL);
    
    // Status update is done in other functions
    // This just ensures periodic update
}

void CloseSMASharedMemory() {
    if (g_pSharedData) {
        g_pSharedData->dll_loaded = 0; // Mark as unloaded
        UnmapViewOfFile(g_pSharedData);
        g_pSharedData = NULL;
    }
    if (g_hSharedMem) {
        CloseHandle(g_hSharedMem);
        g_hSharedMem = NULL;
    }
}

// Check commands from SMA/API
bool CheckSMACommands() {
    if (!g_pSharedData) return false;
    
    bool hasCommand = false;
    
    if (g_pSharedData->cmd_take_screenshot) {
        Log("SMA: Screenshot command received");
        g_pSharedData->cmd_take_screenshot = 0;
        hasCommand = true;
        // Screenshot will be handled in scan thread
    }
    
    if (g_pSharedData->cmd_force_scan) {
        Log("SMA: Force scan command received");
        g_pSharedData->cmd_force_scan = 0;
        hasCommand = true;
    }
    
    if (g_pSharedData->cmd_disconnect) {
        Log("SMA: Disconnect command received");
        g_pSharedData->cmd_disconnect = 0;
        // Will be handled by showing message and exiting
        MessageBoxA(NULL, "AGTR Anti-Cheat: Kicked by admin", "AGTR", MB_OK | MB_ICONWARNING);
        ExitProcess(0);
    }
    
    return hasCommand;
}

// ============================================
// DYNAMIC SETTINGS
// ============================================
struct ClientSettings {
    bool scan_enabled = true;
    int scan_interval = 120000;
    bool scan_only_in_server = true;
    bool scan_processes = true;
    bool scan_modules = true;
    bool scan_windows = true;
    bool scan_files = true;
    bool scan_registry = true;
    bool kick_on_detect = true;
    char message_on_kick[256] = "AGTR Anti-Cheat: Banned";
    
    // v13.0 new settings
    bool screenshot_enabled = true;
    bool websocket_enabled = true;
    bool auto_update = true;
};
static ClientSettings g_Settings;

// ============================================
// GAME STATE
// ============================================
static bool g_bInServer = false;
static char g_szConnectedIP[64] = {0};
static int g_iConnectedPort = 0;
static DWORD g_dwLastHeartbeat = 0;
static DWORD g_dwLastScan = 0;
static bool g_bSettingsLoaded = false;

// Player info
static char g_szSteamID[64] = {0};
static char g_szSteamName[64] = {0};
static char g_szAuthToken[128] = {0};
static char g_szLastConnectedIP[64] = {0};
static int g_iLastConnectedPort = 0;
static DWORD g_dwConnectionStart = 0;
static bool g_bConnectionNotified = false;
static bool g_bSteamIDResolved = false;

// API state
static bool g_bAPIOnline = true;
static DWORD g_dwLastSuccessfulSend = 0;
static DWORD g_dwLastDataHash = 0;
static int g_iFailedRequests = 0;
static bool g_bFirstScanDone = false;

// Security detection results
static bool g_bDebuggerDetected = false;
static bool g_bVMDetected = false;
static bool g_bHooksDetected = false;
static bool g_bDriversDetected = false;
static bool g_bInjectionDetected = false;
static bool g_bIntegrityOK = true;

// v13.0 - Screenshot request
static bool g_bScreenshotRequested = false;
static DWORD g_dwLastScreenshot = 0;
#define SCREENSHOT_COOLDOWN 30000  // 30 saniye cooldown

// v13.0 - Update check
static DWORD g_dwLastUpdateCheck = 0;
static bool g_bUpdateAvailable = false;
static char g_szNewVersion[32] = {0};
static char g_szUpdateURL[256] = {0};

// Offline cache
struct CachedRequest {
    std::string data;
    DWORD timestamp;
    bool valid;
};
static CachedRequest g_OfflineCache[OFFLINE_CACHE_MAX];
static int g_iCacheCount = 0;

// Hash cache
struct HashCacheEntry {
    std::string hash;
    DWORD fileSize;
    FILETIME lastWrite;
    bool valid;
};
static std::map<std::string, HashCacheEntry> g_HashCache;

// ============================================
// GLOBALS
// ============================================
static HANDLE g_hThread = NULL;
static bool g_bRunning = true;
static bool g_bThreadStarted = false;
static CRITICAL_SECTION g_csLog;
static bool g_bSecurityInitialized = false;

static char g_szHWID[64] = {0};
static char g_szDLLHash[64] = {0};
static char g_szGameDir[MAX_PATH] = {0};
static char g_szValveDir[MAX_PATH] = {0};

static char g_szServerIP[64] = "unknown";
static int g_iServerPort = 0;

static bool g_bPassed = true;
static int g_iSusCount = 0;
static FILE* g_LogFile = NULL;

// GDI+ for screenshots
static ULONG_PTR g_gdiplusToken = 0;
static bool g_bGdiplusInitialized = false;

// ============================================
// SUSPICIOUS LISTS
// ============================================
const char* g_SusProc[] = { 
    "cheatengine", "artmoney", "ollydbg", "x64dbg", "x32dbg", 
    "processhacker", "wireshark", "fiddler", "ida.exe", "ida64.exe",
    "ghidra", "reclass", "themida", "ce.exe", "speedhack", 
    "gamehack", "trainer", "injector", "aimbot", "wallhack",
    "cheat", "hack", "esp", "triggerbot", "norecoil",
    NULL 
};

const char* g_WhitelistProc[] = {
    "svchost.exe", "csrss.exe", "smss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "explorer.exe", "dwm.exe", "taskhostw.exe",
    "searchindexer", "searchhost", "runtimebroker", "sihost.exe", "fontdrvhost",
    "ctfmon.exe", "conhost.exe", "dllhost.exe", "audiodg.exe", "spoolsv.exe",
    "msmpeng.exe", "mpcmdrun.exe", "mpdefendercoreservice", "securityhealthservice",
    "steam.exe", "steamservice.exe", "steamwebhelper",
    "discord.exe", "discordptb", "discordcanary",
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
    NULL
};

const char* g_SusWin[] = { 
    "cheat engine", "artmoney", "speed hack", "game hack", 
    "[aimbot]", "[wallhack]", "[esp]", "trainer", "injector",
    "dll inject", "process hack", "memory edit",
    NULL 
};

const char* g_SusReg[] = { 
    "SOFTWARE\\Cheat Engine", 
    "SOFTWARE\\ArtMoney",
    "SOFTWARE\\Process Hacker",
    NULL 
};

const char* g_SusFile[] = { "aimbot", "wallhack", "cheat", "hack", "esp", "speedhack", "norecoil", NULL };

const char* g_SusDLLs[] = {
    "opengl32.dll", "d3d9.dll",
    "hook.dll", "inject.dll", "cheat.dll", "hack.dll",
    "aimbot.dll", "wallhack.dll", "esp.dll", "speedhack.dll",
    NULL
};

// Suspicious drivers (kernel-level cheats)
const char* g_SusDrivers[] = {
    "kdmapper", "drvmap", "capcom", "gdrv", "cpuz",
    "AsIO", "WinRing0", "speedfan", "hwinfo", "aida64",
    "dbk64", "dbk32", "physmem", "iqvw64e", "msio64",
    NULL
};

// ============================================
// DATA STRUCTURES
// ============================================
struct ProcessInfo {
    std::string name;
    std::string path;
    DWORD pid;
    bool suspicious;
};
static std::vector<ProcessInfo> g_Processes;

struct ModuleInfo {
    std::string name;
    std::string path;
    std::string hash;
    DWORD size;
};
static std::vector<ModuleInfo> g_Modules;

struct WindowInfo {
    std::string title;
    std::string className;
    DWORD pid;
    bool suspicious;
};
static std::vector<WindowInfo> g_Windows;

struct FileHashInfo {
    std::string filename;
    std::string path;
    std::string shortHash;  // 8 karakter (ReChecker uyumlu)
    std::string fullHash;   // 32 karakter
    DWORD size;
    DWORD modTime;
};
static std::map<std::string, FileHashInfo> g_FileCache;


// ============================================
// v13.0 - AES-256 ENCRYPTION
// ============================================
static BYTE g_AESKey[32] = {0};  // 256-bit key
static BYTE g_AESIV[16] = {0};   // 128-bit IV
static bool g_bAESInitialized = false;

bool InitAESEncryption() {
    if (!ENCRYPTION_ENABLED) return false;
    if (g_bAESInitialized) return true;
    
    // Generate key from HWID + timestamp
    char keySource[256];
    snprintf(keySource, sizeof(keySource), "AGTR_%s_%s_v13", g_szHWID, g_szSelfHash);
    
    // SHA256 of keySource = AES key
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, (BYTE*)keySource, (DWORD)strlen(keySource), 0)) {
                DWORD hashLen = 32;
                CryptGetHashParam(hHash, HP_HASHVAL, g_AESKey, &hashLen, 0);
                
                // IV = first 16 bytes of MD5(key)
                HCRYPTHASH hMD5 = 0;
                if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hMD5)) {
                    CryptHashData(hMD5, g_AESKey, 32, 0);
                    DWORD ivLen = 16;
                    CryptGetHashParam(hMD5, HP_HASHVAL, g_AESIV, &ivLen, 0);
                    CryptDestroyHash(hMD5);
                }
                
                g_bAESInitialized = true;
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    
    return g_bAESInitialized;
}

// AES-256-CBC encrypt (returns base64 encoded)
std::string AESEncrypt(const std::string& plaintext) {
    if (!g_bAESInitialized || !ENCRYPTION_ENABLED) return plaintext;
    
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    std::string result;
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        return plaintext;
    }
    
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, g_AESKey, 32, 0) == 0) {
        // Calculate output size
        DWORD cbCipherText = 0;
        DWORD cbData = 0;
        BCryptEncrypt(hKey, (PUCHAR)plaintext.c_str(), (ULONG)plaintext.length(), NULL, g_AESIV, 16, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
        
        if (cbCipherText > 0) {
            BYTE* pbCipherText = (BYTE*)malloc(cbCipherText);
            BYTE iv[16];
            memcpy(iv, g_AESIV, 16);
            
            if (BCryptEncrypt(hKey, (PUCHAR)plaintext.c_str(), (ULONG)plaintext.length(), NULL, iv, 16, pbCipherText, cbCipherText, &cbData, BCRYPT_BLOCK_PADDING) == 0) {
                // Base64 encode
                DWORD b64Len = 0;
                CryptBinaryToStringA(pbCipherText, cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64Len);
                if (b64Len > 0) {
                    char* b64 = (char*)malloc(b64Len + 1);
                    if (CryptBinaryToStringA(pbCipherText, cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64, &b64Len)) {
                        result = b64;
                    }
                    free(b64);
                }
            }
            free(pbCipherText);
        }
        BCryptDestroyKey(hKey);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    return result.empty() ? plaintext : result;
}

// ============================================
// v13.0 - SCREENSHOT CAPTURE
// ============================================
bool InitGdiplus() {
    if (g_bGdiplusInitialized) return true;
    
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    if (Gdiplus::GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL) == Gdiplus::Ok) {
        g_bGdiplusInitialized = true;
        Log("GDI+ initialized");
        return true;
    }
    return false;
}

void ShutdownGdiplus() {
    if (g_bGdiplusInitialized) {
        Gdiplus::GdiplusShutdown(g_gdiplusToken);
        g_bGdiplusInitialized = false;
    }
}

// Get encoder CLSID for JPEG
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0, size = 0;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    
    Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)malloc(size);
    if (!pImageCodecInfo) return -1;
    
    Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
    
    for (UINT i = 0; i < num; i++) {
        if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[i].Clsid;
            free(pImageCodecInfo);
            return i;
        }
    }
    free(pImageCodecInfo);
    return -1;
}

// Capture screen and return base64 JPEG
std::string CaptureScreenshot() {
    if (!SCREENSHOT_ENABLED) return "";
    if (!InitGdiplus()) return "";
    
    DWORD now = GetTickCount();
    if (now - g_dwLastScreenshot < SCREENSHOT_COOLDOWN) {
        Log("Screenshot cooldown active");
        return "";
    }
    
    Log("Capturing screenshot...");
    
    std::string result;
    
    // Get screen dimensions
    int screenX = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int screenY = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int screenW = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int screenH = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    
    // Create DC and bitmap
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenW, screenH);
    SelectObject(hdcMem, hBitmap);
    
    // Copy screen
    BitBlt(hdcMem, 0, 0, screenW, screenH, hdcScreen, screenX, screenY, SRCCOPY);
    
    // Convert to GDI+ Bitmap
    Gdiplus::Bitmap* bitmap = Gdiplus::Bitmap::FromHBITMAP(hBitmap, NULL);
    
    if (bitmap) {
        // Save to memory stream as JPEG
        IStream* pStream = NULL;
        CreateStreamOnHGlobal(NULL, TRUE, &pStream);
        
        CLSID clsidJpeg;
        if (GetEncoderClsid(L"image/jpeg", &clsidJpeg) >= 0) {
            // Set quality
            Gdiplus::EncoderParameters encoderParams;
            encoderParams.Count = 1;
            encoderParams.Parameter[0].Guid = Gdiplus::EncoderQuality;
            encoderParams.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
            encoderParams.Parameter[0].NumberOfValues = 1;
            ULONG quality = SCREENSHOT_QUALITY;
            encoderParams.Parameter[0].Value = &quality;
            
            if (bitmap->Save(pStream, &clsidJpeg, &encoderParams) == Gdiplus::Ok) {
                // Get stream size
                STATSTG stats;
                pStream->Stat(&stats, STATFLAG_NONAME);
                ULONG streamSize = (ULONG)stats.cbSize.QuadPart;
                
                if (streamSize > 0 && streamSize <= SCREENSHOT_MAX_SIZE) {
                    // Read stream to buffer
                    HGLOBAL hMem = NULL;
                    GetHGlobalFromStream(pStream, &hMem);
                    BYTE* pData = (BYTE*)GlobalLock(hMem);
                    
                    if (pData) {
                        // Base64 encode
                        DWORD b64Len = 0;
                        CryptBinaryToStringA(pData, streamSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64Len);
                        if (b64Len > 0) {
                            char* b64 = (char*)malloc(b64Len + 1);
                            if (CryptBinaryToStringA(pData, streamSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64, &b64Len)) {
                                result = b64;
                                Log("Screenshot captured: %d bytes -> %d chars base64", streamSize, b64Len);
                            }
                            free(b64);
                        }
                        GlobalUnlock(hMem);
                    }
                } else {
                    Log("Screenshot too large: %d bytes (max %d)", streamSize, SCREENSHOT_MAX_SIZE);
                }
            }
        }
        pStream->Release();
        delete bitmap;
    }
    
    // Cleanup
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    
    g_dwLastScreenshot = now;
    return result;
}

// Send screenshot to API
void SendScreenshot() {
    std::string screenshot = CaptureScreenshot();
    if (screenshot.empty()) return;
    
    EnsureStringsDecrypted();
    
    char json[256];
    snprintf(json, sizeof(json),
        "{\"hwid\":\"%s\",\"steamid\":\"%s\",\"server_ip\":\"%s\",\"server_port\":%d,\"data\":\"",
        g_szHWID, g_szSteamID, g_szConnectedIP, g_iConnectedPort);
    
    std::string body = json;
    body += screenshot;
    body += "\"}";
    
    Log("Sending screenshot (%d bytes)...", (int)body.length());
    
    std::string resp = HttpRequest(g_szPathScreenshot, body, "POST", false);
    
    if (!resp.empty()) {
        Log("Screenshot sent successfully");
    } else {
        Log("Screenshot send failed");
    }
}

// ============================================
// v13.0 - KERNEL-LEVEL DETECTION (Enhanced)
// ============================================
struct DriverInfo {
    std::string name;
    std::string path;
    bool is_signed;
    bool is_suspicious;
};
static std::vector<DriverInfo> g_Drivers;

// NtQuerySystemInformation için tanımlar
typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

#define SystemModuleInformation 11

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

int ScanKernelDrivers() {
    if (!KERNEL_DETECTION_ENABLED) return 0;
    
    g_Drivers.clear();
    int suspicious = 0;
    
    // Method 1: NtQuerySystemInformation (kernel modules)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pNtQuerySystemInformation NtQuerySystemInformation = 
            (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        
        if (NtQuerySystemInformation) {
            ULONG bufferSize = 0;
            NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
            
            if (bufferSize > 0) {
                PRTL_PROCESS_MODULES pModules = (PRTL_PROCESS_MODULES)malloc(bufferSize);
                if (pModules) {
                    if (NtQuerySystemInformation(SystemModuleInformation, pModules, bufferSize, NULL) == 0) {
                        for (ULONG i = 0; i < pModules->NumberOfModules; i++) {
                            char* name = (char*)pModules->Modules[i].FullPathName + pModules->Modules[i].OffsetToFileName;
                            char nameLower[256];
                            strncpy(nameLower, name, 255);
                            for (char* p = nameLower; *p; p++) *p = tolower(*p);
                            
                            DriverInfo drv;
                            drv.name = name;
                            drv.path = (char*)pModules->Modules[i].FullPathName;
                            drv.is_signed = true;  // TODO: signature check
                            drv.is_suspicious = false;
                            
                            // Check against suspicious list
                            for (int j = 0; g_SusDrivers[j]; j++) {
                                if (strstr(nameLower, g_SusDrivers[j])) {
                                    drv.is_suspicious = true;
                                    suspicious++;
                                    Log("[KERNEL] Suspicious driver: %s", name);
                                    break;
                                }
                            }
                            
                            g_Drivers.push_back(drv);
                        }
                    }
                    free(pModules);
                }
            }
        }
    }
    
    // Method 2: Service Control Manager (running drivers)
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm) {
        DWORD bytesNeeded = 0, servicesReturned = 0;
        EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
            SERVICE_ACTIVE, NULL, 0, &bytesNeeded, &servicesReturned, NULL, NULL);
        
        if (bytesNeeded > 0) {
            BYTE* buffer = (BYTE*)malloc(bytesNeeded);
            if (buffer) {
                ENUM_SERVICE_STATUS_PROCESSA* services = (ENUM_SERVICE_STATUS_PROCESSA*)buffer;
                if (EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                    SERVICE_ACTIVE, buffer, bytesNeeded, &bytesNeeded, &servicesReturned, NULL, NULL)) {
                    
                    for (DWORD i = 0; i < servicesReturned; i++) {
                        char nameLower[256];
                        strncpy(nameLower, services[i].lpServiceName, 255);
                        for (char* p = nameLower; *p; p++) *p = tolower(*p);
                        
                        for (int j = 0; g_SusDrivers[j]; j++) {
                            if (strstr(nameLower, g_SusDrivers[j])) {
                                Log("[KERNEL] Suspicious service: %s (%s)", 
                                    services[i].lpServiceName, services[i].lpDisplayName);
                                suspicious++;
                                break;
                            }
                        }
                    }
                }
                free(buffer);
            }
        }
        CloseServiceHandle(scm);
    }
    
    g_bDriversDetected = (suspicious > 0);
    return suspicious;
}

// ============================================
// v13.0 - CODE INJECTION DETECTION
// ============================================

// Check for IAT hooks
int CheckIATHooks() {
    if (!INJECTION_DETECTION_ENABLED) return 0;
    
    int hooks = 0;
    HMODULE hModule = GetModuleHandleA(NULL);  // hl.exe
    if (!hModule) return 0;
    
    PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)hModule;
    if (pDOS->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOS->e_lfanew);
    if (pNT->Signature != IMAGE_NT_SIGNATURE) return 0;
    
    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule +
        pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    if (!pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) return 0;
    
    while (pImport->Name) {
        char* dllName = (char*)((BYTE*)hModule + pImport->Name);
        
        // Get original DLL
        HMODULE hDll = GetModuleHandleA(dllName);
        if (hDll) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImport->FirstThunk);
            PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImport->OriginalFirstThunk);
            
            while (pThunk->u1.Function && pOrigThunk->u1.AddressOfData) {
                if (!(pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + pOrigThunk->u1.AddressOfData);
                    FARPROC pReal = GetProcAddress(hDll, (char*)pName->Name);
                    
                    if (pReal && (FARPROC)pThunk->u1.Function != pReal) {
                        // IAT entry doesn't match real function - possible hook
                        MEMORY_BASIC_INFORMATION mbi;
                        if (VirtualQuery((void*)pThunk->u1.Function, &mbi, sizeof(mbi))) {
                            // Check if it points to a known module
                            char modName[MAX_PATH] = {0};
                            if (GetModuleFileNameA((HMODULE)mbi.AllocationBase, modName, MAX_PATH)) {
                                // If it's not the expected DLL, it might be a hook
                                if (strstr(modName, dllName) == NULL) {
                                    Log("[INJECT] IAT hook: %s!%s -> %s", dllName, (char*)pName->Name, modName);
                                    hooks++;
                                }
                            }
                        }
                    }
                }
                pThunk++;
                pOrigThunk++;
            }
        }
        pImport++;
    }
    
    return hooks;
}

// Check for inline hooks (JMP at function start)
int CheckInlineHooks() {
    if (!INJECTION_DETECTION_ENABLED) return 0;
    
    int hooks = 0;
    
    // Critical functions to check
    struct FuncCheck {
        const char* dll;
        const char* func;
    } funcsToCheck[] = {
        {"kernel32.dll", "LoadLibraryA"},
        {"kernel32.dll", "LoadLibraryW"},
        {"kernel32.dll", "GetProcAddress"},
        {"kernel32.dll", "VirtualAlloc"},
        {"kernel32.dll", "VirtualProtect"},
        {"kernel32.dll", "CreateFileA"},
        {"kernel32.dll", "ReadFile"},
        {"kernel32.dll", "WriteFile"},
        {"ntdll.dll", "NtReadVirtualMemory"},
        {"ntdll.dll", "NtWriteVirtualMemory"},
        {"ntdll.dll", "NtProtectVirtualMemory"},
        {"user32.dll", "GetAsyncKeyState"},
        {"user32.dll", "SetWindowsHookExA"},
        {NULL, NULL}
    };
    
    for (int i = 0; funcsToCheck[i].dll; i++) {
        HMODULE hMod = GetModuleHandleA(funcsToCheck[i].dll);
        if (!hMod) continue;
        
        FARPROC pFunc = GetProcAddress(hMod, funcsToCheck[i].func);
        if (!pFunc) continue;
        
        BYTE* ptr = (BYTE*)pFunc;
        
        // Check for common hook patterns
        // E9 xx xx xx xx = JMP rel32
        // EB xx = JMP rel8
        // FF 25 xx xx xx xx = JMP [mem]
        // 68 xx xx xx xx C3 = PUSH addr; RET
        
        if (ptr[0] == 0xE9 || ptr[0] == 0xEB) {
            Log("[INJECT] Inline hook (JMP): %s!%s", funcsToCheck[i].dll, funcsToCheck[i].func);
            hooks++;
        }
        else if (ptr[0] == 0xFF && ptr[1] == 0x25) {
            Log("[INJECT] Inline hook (JMP [mem]): %s!%s", funcsToCheck[i].dll, funcsToCheck[i].func);
            hooks++;
        }
        else if (ptr[0] == 0x68 && ptr[5] == 0xC3) {
            Log("[INJECT] Inline hook (PUSH/RET): %s!%s", funcsToCheck[i].dll, funcsToCheck[i].func);
            hooks++;
        }
    }
    
    g_bHooksDetected = (hooks > 0);
    return hooks;
}

// Check hl.exe .text section integrity
bool CheckTextSectionIntegrity() {
    if (!INJECTION_DETECTION_ENABLED) return true;
    
    static DWORD s_savedChecksum = 0;
    static bool s_firstCheck = true;
    
    HMODULE hModule = GetModuleHandleA(NULL);
    if (!hModule) return true;
    
    PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)hModule;
    if (pDOS->e_magic != IMAGE_DOS_SIGNATURE) return true;
    
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOS->e_lfanew);
    if (pNT->Signature != IMAGE_NT_SIGNATURE) return true;
    
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNT);
    
    for (WORD i = 0; i < pNT->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSection[i].Name, ".text") == 0) {
            BYTE* pCode = (BYTE*)hModule + pSection[i].VirtualAddress;
            DWORD codeSize = pSection[i].Misc.VirtualSize;
            
            // Calculate checksum
            DWORD checksum = 0;
            for (DWORD j = 0; j < codeSize; j += 64) {
                checksum ^= *(DWORD*)(pCode + j);
                checksum = (checksum << 7) | (checksum >> 25);
            }
            
            if (s_firstCheck) {
                s_savedChecksum = checksum;
                s_firstCheck = false;
                Log("[INJECT] .text section checksum saved: %08X", checksum);
                return true;
            }
            
            if (checksum != s_savedChecksum) {
                Log("[INJECT] .text section modified! Was %08X, now %08X", s_savedChecksum, checksum);
                g_bInjectionDetected = true;
                return false;
            }
            break;
        }
    }
    
    return true;
}

int ScanCodeInjection() {
    int total = 0;
    
    // IAT hooks
    total += CheckIATHooks();
    
    // Inline hooks
    total += CheckInlineHooks();
    
    // .text section integrity
    if (!CheckTextSectionIntegrity()) {
        total++;
    }
    
    g_bInjectionDetected = (total > 0);
    
    if (total > 0) {
        Log("[INJECT] Total injection indicators: %d", total);
        
        // Update SMA shared data
        if (g_pSharedData) {
            g_pSharedData->injection_detected = 1;
        }
    }
    
    return total;
}


// ============================================
// v13.0 - AUTO-UPDATE SYSTEM
// ============================================
struct UpdateInfo {
    char version[32];
    char url[256];
    char hash[65];
    bool required;
};

bool CheckForUpdates(UpdateInfo* info) {
    if (!AUTO_UPDATE_ENABLED) return false;
    
    DWORD now = GetTickCount();
    if (now - g_dwLastUpdateCheck < UPDATE_CHECK_INTERVAL) return false;
    g_dwLastUpdateCheck = now;
    
    EnsureStringsDecrypted();
    
    char json[256];
    snprintf(json, sizeof(json), "{\"hwid\":\"%s\",\"version\":\"%s\"}", g_szHWID, AGTR_VERSION);
    
    std::string resp = HttpRequest(g_szPathUpdate, json, "POST", false);
    
    if (resp.empty()) return false;
    
    // Parse response
    // {"update_available":true,"version":"13.1","url":"http://...","hash":"...","required":false}
    
    if (strstr(resp.c_str(), "\"update_available\":true")) {
        const char* verStart = strstr(resp.c_str(), "\"version\":\"");
        const char* urlStart = strstr(resp.c_str(), "\"url\":\"");
        const char* hashStart = strstr(resp.c_str(), "\"hash\":\"");
        
        if (verStart && urlStart) {
            verStart += 11;
            const char* verEnd = strchr(verStart, '"');
            if (verEnd && verEnd - verStart < 32) {
                strncpy(info->version, verStart, verEnd - verStart);
                info->version[verEnd - verStart] = 0;
            }
            
            urlStart += 7;
            const char* urlEnd = strchr(urlStart, '"');
            if (urlEnd && urlEnd - urlStart < 256) {
                strncpy(info->url, urlStart, urlEnd - urlStart);
                info->url[urlEnd - urlStart] = 0;
            }
            
            if (hashStart) {
                hashStart += 8;
                const char* hashEnd = strchr(hashStart, '"');
                if (hashEnd && hashEnd - hashStart < 65) {
                    strncpy(info->hash, hashStart, hashEnd - hashStart);
                    info->hash[hashEnd - hashStart] = 0;
                }
            }
            
            info->required = (strstr(resp.c_str(), "\"required\":true") != NULL);
            
            Log("[UPDATE] New version available: %s", info->version);
            g_bUpdateAvailable = true;
            strcpy(g_szNewVersion, info->version);
            strcpy(g_szUpdateURL, info->url);
            
            return true;
        }
    }
    
    return false;
}

bool DownloadUpdate(const char* url, const char* destPath) {
    Log("[UPDATE] Downloading from: %s", url);
    
    // Parse URL
    char host[256] = {0};
    char path[512] = {0};
    int port = 80;
    bool https = false;
    
    if (strncmp(url, "https://", 8) == 0) {
        https = true;
        port = 443;
        sscanf(url + 8, "%255[^/]%511s", host, path);
    } else if (strncmp(url, "http://", 7) == 0) {
        sscanf(url + 7, "%255[^/]%511s", host, path);
    } else {
        return false;
    }
    
    wchar_t wHost[256], wPath[512];
    mbstowcs(wHost, host, 256);
    mbstowcs(wPath, path, 512);
    
    HINTERNET hSession = WinHttpOpen(L"AGTR-Update", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
    
    HINTERNET hConnect = WinHttpConnect(hSession, wHost, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    bool success = false;
    
    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {
        
        // Create temp file
        HANDLE hFile = CreateFileA(destPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            char buffer[8192];
            DWORD bytesRead, bytesWritten;
            DWORD totalBytes = 0;
            
            while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);
                totalBytes += bytesRead;
            }
            
            CloseHandle(hFile);
            
            if (totalBytes > 0) {
                Log("[UPDATE] Downloaded %d bytes to %s", totalBytes, destPath);
                success = true;
            }
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return success;
}

void ApplyUpdate() {
    if (!g_bUpdateAvailable || g_szUpdateURL[0] == 0) return;
    
    char tempPath[MAX_PATH];
    char newDllPath[MAX_PATH];
    char bakPath[MAX_PATH];
    
    // Download to temp
    GetTempPathA(MAX_PATH, tempPath);
    strcat(tempPath, "agtr_update.dll");
    
    if (!DownloadUpdate(g_szUpdateURL, tempPath)) {
        Log("[UPDATE] Download failed");
        return;
    }
    
    // Current DLL path
    snprintf(newDllPath, sizeof(newDllPath), "%s\\winmm.dll", g_szGameDir);
    snprintf(bakPath, sizeof(bakPath), "%s\\winmm.dll.bak", g_szGameDir);
    
    // Write batch file to replace on restart
    char batPath[MAX_PATH];
    snprintf(batPath, sizeof(batPath), "%s\\agtr_update.bat", g_szGameDir);
    
    FILE* bat = fopen(batPath, "w");
    if (bat) {
        fprintf(bat, "@echo off\n");
        fprintf(bat, ":loop\n");
        fprintf(bat, "tasklist /FI \"IMAGENAME eq hl.exe\" 2>NUL | find /I \"hl.exe\" >NUL\n");
        fprintf(bat, "if %%ERRORLEVEL%%==0 (\n");
        fprintf(bat, "    timeout /t 2 /nobreak >NUL\n");
        fprintf(bat, "    goto loop\n");
        fprintf(bat, ")\n");
        fprintf(bat, "del \"%s\" 2>NUL\n", bakPath);
        fprintf(bat, "move \"%s\" \"%s\"\n", newDllPath, bakPath);
        fprintf(bat, "move \"%s\" \"%s\"\n", tempPath, newDllPath);
        fprintf(bat, "del \"%%~f0\"\n");
        fclose(bat);
        
        Log("[UPDATE] Update batch created. Will apply on next restart.");
        
        // Notify user
        MessageBoxA(NULL, 
            "AGTR Anti-Cheat update downloaded.\nPlease restart the game to apply the update.",
            "AGTR Update", MB_OK | MB_ICONINFORMATION);
    }
}

// ============================================
// LOGGING
// ============================================
void Log(const char* fmt, ...) {
    EnterCriticalSection(&g_csLog);
    
    if (!g_LogFile && g_szGameDir[0]) {
        char path[MAX_PATH];
        sprintf(path, "%s\\agtr_client.log", g_szGameDir);
        g_LogFile = fopen(path, "a");
    }
    
    if (g_LogFile) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_LogFile, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
        
        va_list args;
        va_start(args, fmt);
        vfprintf(g_LogFile, fmt, args);
        va_end(args);
        
        fprintf(g_LogFile, "\n");
        fflush(g_LogFile);
    }
    
    LeaveCriticalSection(&g_csLog);
}

void ToLower(char* s) { for (; *s; s++) *s = tolower(*s); }

// v14.3 - String helper
static std::string ToLowerStr(const char* str) {
    std::string result = str;
    for (size_t i = 0; i < result.length(); i++) {
        result[i] = (char)tolower((unsigned char)result[i]);
    }
    return result;
}

// ============================================
// MD5 HASH (ReChecker uyumlu 8 karakter)
// ============================================
class MD5 {
public:
    MD5() { Init(); }
    void Init() { count[0]=count[1]=0; state[0]=0x67452301; state[1]=0xefcdab89; state[2]=0x98badcfe; state[3]=0x10325476; }
    void Update(const unsigned char* input, unsigned int len) {
        unsigned int i, idx, partLen;
        idx = (count[0] >> 3) & 0x3F;
        if ((count[0] += (len << 3)) < (len << 3)) count[1]++;
        count[1] += (len >> 29);
        partLen = 64 - idx;
        if (len >= partLen) { memcpy(&buffer[idx], input, partLen); Transform(state, buffer); for (i = partLen; i + 63 < len; i += 64) Transform(state, &input[i]); idx = 0; }
        else i = 0;
        memcpy(&buffer[idx], &input[i], len-i);
    }
    void Final(unsigned char digest[16]) {
        unsigned char bits[8]; static unsigned char PADDING[64] = { 0x80 };
        Encode(bits, count, 8);
        unsigned int idx = (count[0] >> 3) & 0x3f, padLen = (idx < 56) ? (56 - idx) : (120 - idx);
        Update(PADDING, padLen); Update(bits, 8); Encode(digest, state, 16);
    }
    std::string GetHashString() { 
        unsigned char d[16]; Final(d); 
        char h[33]; 
        for(int i=0;i<16;i++) sprintf(h+i*2,"%02x",d[i]); 
        return std::string(h); 
    }
    // 8 karakter versiyon (ReChecker uyumlu)
    std::string GetShortHash() {
        std::string full = GetHashString();
        return full.substr(0, AGTR_HASH_LENGTH);
    }
private:
    unsigned int state[4], count[2]; unsigned char buffer[64];
    void Transform(unsigned int state[4], const unsigned char block[64]) {
        unsigned int a=state[0],b=state[1],c=state[2],d=state[3],x[16];
        Decode(x,block,64);
        #define S(x,n) (((x)<<(n))|((x)>>(32-(n))))
        #define F(x,y,z) (((x)&(y))|((~x)&(z)))
        #define G(x,y,z) (((x)&(z))|((y)&(~z)))
        #define H(x,y,z) ((x)^(y)^(z))
        #define I(x,y,z) ((y)^((x)|(~z)))
        #define FF(a,b,c,d,x,s,ac) {(a)+=F((b),(c),(d))+(x)+(ac);(a)=S((a),(s));(a)+=(b);}
        #define GG(a,b,c,d,x,s,ac) {(a)+=G((b),(c),(d))+(x)+(ac);(a)=S((a),(s));(a)+=(b);}
        #define HH(a,b,c,d,x,s,ac) {(a)+=H((b),(c),(d))+(x)+(ac);(a)=S((a),(s));(a)+=(b);}
        #define II(a,b,c,d,x,s,ac) {(a)+=I((b),(c),(d))+(x)+(ac);(a)=S((a),(s));(a)+=(b);}
        FF(a,b,c,d,x[0],7,0xd76aa478);FF(d,a,b,c,x[1],12,0xe8c7b756);FF(c,d,a,b,x[2],17,0x242070db);FF(b,c,d,a,x[3],22,0xc1bdceee);
        FF(a,b,c,d,x[4],7,0xf57c0faf);FF(d,a,b,c,x[5],12,0x4787c62a);FF(c,d,a,b,x[6],17,0xa8304613);FF(b,c,d,a,x[7],22,0xfd469501);
        FF(a,b,c,d,x[8],7,0x698098d8);FF(d,a,b,c,x[9],12,0x8b44f7af);FF(c,d,a,b,x[10],17,0xffff5bb1);FF(b,c,d,a,x[11],22,0x895cd7be);
        FF(a,b,c,d,x[12],7,0x6b901122);FF(d,a,b,c,x[13],12,0xfd987193);FF(c,d,a,b,x[14],17,0xa679438e);FF(b,c,d,a,x[15],22,0x49b40821);
        GG(a,b,c,d,x[1],5,0xf61e2562);GG(d,a,b,c,x[6],9,0xc040b340);GG(c,d,a,b,x[11],14,0x265e5a51);GG(b,c,d,a,x[0],20,0xe9b6c7aa);
        GG(a,b,c,d,x[5],5,0xd62f105d);GG(d,a,b,c,x[10],9,0x02441453);GG(c,d,a,b,x[15],14,0xd8a1e681);GG(b,c,d,a,x[4],20,0xe7d3fbc8);
        GG(a,b,c,d,x[9],5,0x21e1cde6);GG(d,a,b,c,x[14],9,0xc33707d6);GG(c,d,a,b,x[3],14,0xf4d50d87);GG(b,c,d,a,x[8],20,0x455a14ed);
        GG(a,b,c,d,x[13],5,0xa9e3e905);GG(d,a,b,c,x[2],9,0xfcefa3f8);GG(c,d,a,b,x[7],14,0x676f02d9);GG(b,c,d,a,x[12],20,0x8d2a4c8a);
        HH(a,b,c,d,x[5],4,0xfffa3942);HH(d,a,b,c,x[8],11,0x8771f681);HH(c,d,a,b,x[11],16,0x6d9d6122);HH(b,c,d,a,x[14],23,0xfde5380c);
        HH(a,b,c,d,x[1],4,0xa4beea44);HH(d,a,b,c,x[4],11,0x4bdecfa9);HH(c,d,a,b,x[7],16,0xf6bb4b60);HH(b,c,d,a,x[10],23,0xbebfbc70);
        HH(a,b,c,d,x[13],4,0x289b7ec6);HH(d,a,b,c,x[0],11,0xeaa127fa);HH(c,d,a,b,x[3],16,0xd4ef3085);HH(b,c,d,a,x[6],23,0x04881d05);
        HH(a,b,c,d,x[9],4,0xd9d4d039);HH(d,a,b,c,x[12],11,0xe6db99e5);HH(c,d,a,b,x[15],16,0x1fa27cf8);HH(b,c,d,a,x[2],23,0xc4ac5665);
        II(a,b,c,d,x[0],6,0xf4292244);II(d,a,b,c,x[7],10,0x432aff97);II(c,d,a,b,x[14],15,0xab9423a7);II(b,c,d,a,x[5],21,0xfc93a039);
        II(a,b,c,d,x[12],6,0x655b59c3);II(d,a,b,c,x[3],10,0x8f0ccc92);II(c,d,a,b,x[10],15,0xffeff47d);II(b,c,d,a,x[1],21,0x85845dd1);
        II(a,b,c,d,x[8],6,0x6fa87e4f);II(d,a,b,c,x[15],10,0xfe2ce6e0);II(c,d,a,b,x[6],15,0xa3014314);II(b,c,d,a,x[13],21,0x4e0811a1);
        II(a,b,c,d,x[4],6,0xf7537e82);II(d,a,b,c,x[11],10,0xbd3af235);II(c,d,a,b,x[2],15,0x2ad7d2bb);II(b,c,d,a,x[9],21,0xeb86d391);
        state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;
        #undef S
        #undef F
        #undef G
        #undef H
        #undef I
        #undef FF
        #undef GG
        #undef HH
        #undef II
    }
    void Encode(unsigned char* out, const unsigned int* in, unsigned int len) { for(unsigned int i=0,j=0;j<len;i++,j+=4){out[j]=in[i]&0xff;out[j+1]=(in[i]>>8)&0xff;out[j+2]=(in[i]>>16)&0xff;out[j+3]=(in[i]>>24)&0xff;} }
    void Decode(unsigned int* out, const unsigned char* in, unsigned int len) { for(unsigned int i=0,j=0;j<len;i++,j+=4) out[i]=in[j]|(in[j+1]<<8)|(in[j+2]<<16)|(in[j+3]<<24); }
};

// ============================================
// SECURITY FUNCTIONS
// ============================================

// SHA256 using Windows CryptoAPI
static bool SHA256Hash(const BYTE* data, DWORD dataLen, char* outHex) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];
    DWORD hashLen = 32;
    bool success = false;
    
    if (!outHex) return false;
    outHex[0] = 0;
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, data, dataLen, 0)) {
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                    for (DWORD i = 0; i < hashLen; i++) {
                        sprintf(outHex + (i * 2), "%02x", hash[i]);
                    }
                    outHex[64] = 0;
                    success = true;
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return success;
}

// Calculate DLL self hash
static void CalculateSelfHash() {
    char dllPath[MAX_PATH];
    HMODULE hSelf = NULL;
    
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)CalculateSelfHash, &hSelf);
    
    if (GetModuleFileNameA(hSelf, dllPath, MAX_PATH)) {
        char* lastSlash = strrchr(dllPath, '\\');
        if (lastSlash) {
            strcpy(g_szSelfName, lastSlash + 1);
        } else {
            strcpy(g_szSelfName, dllPath);
        }
        for (char* p = g_szSelfName; *p; p++) {
            *p = tolower(*p);
        }
        
        HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize > 0 && fileSize < 10 * 1024 * 1024) {
                BYTE* fileData = (BYTE*)malloc(fileSize);
                if (fileData) {
                    DWORD bytesRead;
                    if (ReadFile(hFile, fileData, fileSize, &bytesRead, NULL) && bytesRead == fileSize) {
                        SHA256Hash(fileData, fileSize, g_szSelfHash);
                    }
                    free(fileData);
                }
            }
            CloseHandle(hFile);
        }
    }
    
    if (g_szSelfHash[0] == 0) strcpy(g_szSelfHash, "unknown");
    if (g_szSelfName[0] == 0) strcpy(g_szSelfName, "winmm.dll");
}

// Anti-debug checks
static bool CheckDebugger() {
    if (!ANTI_DEBUG_ENABLED) return false;
    
    // Check 1: IsDebuggerPresent
    if (IsDebuggerPresent()) return true;
    
    // Check 2: CheckRemoteDebuggerPresent
    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) return true;
    
    // Check 3: PEB NtGlobalFlag
    DWORD ntGlobalFlag = 0;
    __try {
        #ifdef _WIN64
        ntGlobalFlag = *(DWORD*)((BYTE*)__readgsqword(0x60) + 0xBC);
        #else
        ntGlobalFlag = *(DWORD*)((BYTE*)__readfsdword(0x30) + 0x68);
        #endif
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    
    if (ntGlobalFlag & 0x70) return true;
    
    // Check 4: Hardware breakpoints
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
    }
    
    return false;
}

// VM Detection
static bool CheckVirtualMachine() {
    g_bVMDetected = false;
    
    // CPUID check
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) g_bVMDetected = true;
    
    // Registry check
    HKEY hKey;
    const char* vmKeys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        NULL
    };
    
    for (int i = 0; vmKeys[i]; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            g_bVMDetected = true;
            break;
        }
    }
    
    return g_bVMDetected;
}


// ============================================
// HWID GENERATION
// ============================================
void GenHWID() {
    int cpu[4]={0}; __cpuid(cpu,0);
    DWORD vol=0; GetVolumeInformationA("C:\\",NULL,0,&vol,NULL,NULL,NULL,0);
    char pc[MAX_COMPUTERNAME_LENGTH+1]={0}; DWORD sz=sizeof(pc); GetComputerNameA(pc,&sz);
    sprintf(g_szHWID, "%08X%08X%08X", cpu[0]^cpu[1], vol, (pc[0]<<24)|(pc[1]<<16)|(pc[2]<<8)|pc[3]);
    Log("HWID: %s", g_szHWID);
    
    // Update SMA shared data
    if (g_pSharedData) {
        strcpy(g_pSharedData->hwid, g_szHWID);
    }
}

// ============================================
// STEAMID DETECTION
// ============================================
bool GetSteamIDFromRegistry() {
    HKEY hKey;
    char steamPath[MAX_PATH] = {0};
    DWORD size = sizeof(steamPath);
    
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD userId = 0;
        size = sizeof(userId);
        if (RegQueryValueExA(hKey, "ActiveProcess\\ActiveUser", NULL, NULL, (LPBYTE)&userId, &size) == ERROR_SUCCESS && userId > 0) {
            DWORD y = userId & 1;
            DWORD z = userId >> 1;
            sprintf(g_szSteamID, "STEAM_0:%d:%d", y, z);
            Log("SteamID from Registry: %s", g_szSteamID);
            RegCloseKey(hKey);
            return true;
        }
        RegCloseKey(hKey);
    }
    
    // Method 2: loginusers.vdf
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        size = sizeof(steamPath);
        if (RegQueryValueExA(hKey, "SteamPath", NULL, NULL, (LPBYTE)steamPath, &size) == ERROR_SUCCESS) {
            char vdfPath[MAX_PATH];
            sprintf(vdfPath, "%s\\config\\loginusers.vdf", steamPath);
            
            FILE* f = fopen(vdfPath, "r");
            if (f) {
                char line[512];
                char lastSteamID64[32] = {0};
                
                while (fgets(line, sizeof(line), f)) {
                    char* p = strstr(line, "\"7656119");
                    if (p) {
                        p++;
                        char* end = strchr(p, '"');
                        if (end) {
                            *end = 0;
                            strcpy(lastSteamID64, p);
                        }
                    }
                }
                fclose(f);
                
                if (lastSteamID64[0]) {
                    unsigned long long sid64 = _strtoui64(lastSteamID64, NULL, 10);
                    DWORD accountId = (DWORD)(sid64 & 0xFFFFFFFF);
                    DWORD y = accountId & 1;
                    DWORD z = accountId >> 1;
                    sprintf(g_szSteamID, "STEAM_0:%d:%d", y, z);
                    Log("SteamID from VDF: %s", g_szSteamID);
                    RegCloseKey(hKey);
                    return true;
                }
            }
        }
        RegCloseKey(hKey);
    }
    
    return false;
}

bool GetSteamIDFromUserdata() {
    HKEY hKey;
    char steamPath[MAX_PATH] = {0};
    DWORD size = sizeof(steamPath);
    
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) != ERROR_SUCCESS) return false;
    if (RegQueryValueExA(hKey, "SteamPath", NULL, NULL, (LPBYTE)steamPath, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }
    RegCloseKey(hKey);
    
    char userdataPath[MAX_PATH];
    sprintf(userdataPath, "%s\\userdata\\*", steamPath);
    
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(userdataPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return false;
    
    DWORD latestAccountId = 0;
    FILETIME latestTime = {0};
    
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && fd.cFileName[0] != '.') {
            DWORD accountId = atoi(fd.cFileName);
            if (accountId > 0 && CompareFileTime(&fd.ftLastWriteTime, &latestTime) > 0) {
                latestTime = fd.ftLastWriteTime;
                latestAccountId = accountId;
            }
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    
    if (latestAccountId > 0) {
        DWORD y = latestAccountId & 1;
        DWORD z = latestAccountId >> 1;
        sprintf(g_szSteamID, "STEAM_0:%d:%d", y, z);
        Log("SteamID from userdata: %s", g_szSteamID);
        return true;
    }
    
    return false;
}

void GetSteamUsername() {
    HKEY hKey;
    DWORD size = sizeof(g_szSteamName);
    
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "LastGameNameUsed", NULL, NULL, (LPBYTE)g_szSteamName, &size) != ERROR_SUCCESS) {
            size = sizeof(g_szSteamName);
            RegQueryValueExA(hKey, "AutoLoginUser", NULL, NULL, (LPBYTE)g_szSteamName, &size);
        }
        RegCloseKey(hKey);
    }
}

void ResolveSteamID() {
    if (g_bSteamIDResolved) return;
    
    Log("Resolving SteamID...");
    
    if (!GetSteamIDFromRegistry()) {
        if (!GetSteamIDFromUserdata()) {
            strcpy(g_szSteamID, "STEAM_ID_UNKNOWN");
        }
    }
    
    GetSteamUsername();
    g_bSteamIDResolved = true;
    
    // Update SMA shared data
    if (g_pSharedData) {
        strcpy(g_pSharedData->steamid, g_szSteamID);
        strcpy(g_pSharedData->steam_name, g_szSteamName);
    }
}

// ============================================
// FILE HASH (ReChecker uyumlu 8 karakter MD5)
// ============================================
void GetFileHash(const char* filepath, char* shortHash, char* fullHash, DWORD* fileSize) {
    shortHash[0] = fullHash[0] = 0;
    *fileSize = 0;
    
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(filepath, GetFileExInfoStandard, &fad)) return;
    
    *fileSize = fad.nFileSizeLow;
    
    // Cache check
    std::string key = filepath;
    auto it = g_HashCache.find(key);
    if (it != g_HashCache.end() && it->second.valid) {
        if (it->second.fileSize == *fileSize &&
            it->second.lastWrite.dwLowDateTime == fad.ftLastWriteTime.dwLowDateTime &&
            it->second.lastWrite.dwHighDateTime == fad.ftLastWriteTime.dwHighDateTime) {
            strncpy(fullHash, it->second.hash.c_str(), 32); fullHash[32] = 0;
            strncpy(shortHash, it->second.hash.c_str(), AGTR_HASH_LENGTH); shortHash[AGTR_HASH_LENGTH] = 0;
            return;
        }
    }
    
    HANDLE h = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    
    MD5 md5; unsigned char buf[32768]; DWORD rd;
    while(ReadFile(h, buf, sizeof(buf), &rd, NULL) && rd > 0) md5.Update(buf, rd);
    CloseHandle(h);
    
    std::string hash = md5.GetHashString();
    strncpy(fullHash, hash.c_str(), 32); fullHash[32] = 0;
    strncpy(shortHash, hash.c_str(), AGTR_HASH_LENGTH); shortHash[AGTR_HASH_LENGTH] = 0;
    
    // Cache'e kaydet
    HashCacheEntry entry;
    entry.hash = hash;
    entry.fileSize = *fileSize;
    entry.lastWrite = fad.ftLastWriteTime;
    entry.valid = true;
    g_HashCache[key] = entry;
}

void ComputeDLLHash() {
    char path[MAX_PATH];
    sprintf(path, "%s\\winmm.dll", g_szGameDir);
    char shortH[16];
    DWORD size;
    GetFileHash(path, shortH, g_szDLLHash, &size);
    Log("DLL Hash: %s (short: %s)", g_szDLLHash, shortH);
    
    // Update SMA shared data
    if (g_pSharedData) {
        strncpy(g_pSharedData->dll_hash, shortH, 15);
    }
}

// ============================================
// SERVER DETECTION
// ============================================
bool DetectConnectedServer() {
    g_bInServer = false;
    g_szConnectedIP[0] = 0;
    g_iConnectedPort = 0;
    
    DWORD hlPid = GetCurrentProcessId();
    
    // TCP connections
    MIB_TCPTABLE_OWNER_PID* pTcpTable = NULL;
    DWORD dwSize = 0;
    
    if (GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
        if (pTcpTable && GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID& row = pTcpTable->table[i];
                if (row.dwOwningPid == hlPid && row.dwState == MIB_TCP_STATE_ESTAB) {
                    IN_ADDR remoteAddr;
                    remoteAddr.S_un.S_addr = row.dwRemoteAddr;
                    int remotePort = ntohs((u_short)row.dwRemotePort);
                    
                    // v14.1: Expanded port range for server detection (27000-27200)
                    if (remotePort >= 27000 && remotePort <= 27200) {
                        strcpy(g_szConnectedIP, inet_ntoa(remoteAddr));
                        g_iConnectedPort = remotePort;
                        g_bInServer = true;
                        break;
                    }
                }
            }
        }
        if (pTcpTable) free(pTcpTable);
    }
    
    // UDP check
    if (!g_bInServer) {
        MIB_UDPTABLE_OWNER_PID* pUdpTable = NULL;
        dwSize = 0;
        
        if (GetExtendedUdpTable(NULL, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
            pUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(dwSize);
            if (pUdpTable && GetExtendedUdpTable(pUdpTable, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
                    MIB_UDPROW_OWNER_PID& row = pUdpTable->table[i];
                    if (row.dwOwningPid == hlPid) {
                        int localPort = ntohs((u_short)row.dwLocalPort);
                        // v14.1: Expanded port range (27000-27200)
                        if (localPort >= 27000 && localPort <= 27200) {
                            g_bInServer = true;
                            break;
                        }
                    }
                }
            }
            if (pUdpTable) free(pUdpTable);
        }
    }
    
    // Server change detection
    if (g_bInServer) {
        if (strcmp(g_szConnectedIP, g_szLastConnectedIP) != 0 || g_iConnectedPort != g_iLastConnectedPort) {
            strcpy(g_szLastConnectedIP, g_szConnectedIP);
            g_iLastConnectedPort = g_iConnectedPort;
            g_dwConnectionStart = GetTickCount();
            g_bConnectionNotified = false;
            Log("Server changed: %s:%d", g_szConnectedIP, g_iConnectedPort);
            
            // Update SMA
            if (g_pSharedData) {
                snprintf(g_pSharedData->ip, sizeof(g_pSharedData->ip), "%s:%d", g_szConnectedIP, g_iConnectedPort);
            }
        }
    } else {
        if (g_szLastConnectedIP[0]) {
            Log("Disconnected from server");
            g_szLastConnectedIP[0] = 0;
            g_iLastConnectedPort = 0;
            g_bConnectionNotified = false;
            
            if (g_pSharedData) {
                g_pSharedData->ip[0] = 0;
            }
        }
    }
    
    return g_bInServer;
}

// ============================================
// HTTP REQUEST
// ============================================
std::string HttpRequest(const wchar_t* path, const std::string& body, const std::string& method, bool canCache) {
    std::string response;
    
    EnsureStringsDecrypted();
    
    HINTERNET hSession = WinHttpOpen(g_szUserAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        g_bAPIOnline = false;
        g_iFailedRequests++;
        return response;
    }
    
    // Timeout
    DWORD timeout = API_TIMEOUT;
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    
    HINTERNET hConnect = WinHttpConnect(hSession, g_szAPIHost, API_PORT, 0);
    if (!hConnect) { 
        WinHttpCloseHandle(hSession);
        g_bAPIOnline = false;
        g_iFailedRequests++;
        return response;
    }
    
    DWORD flags = API_USE_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    std::wstring wmethod(method.begin(), method.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, wmethod.c_str(), path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { 
        WinHttpCloseHandle(hConnect); 
        WinHttpCloseHandle(hSession);
        g_bAPIOnline = false;
        g_iFailedRequests++;
        return response;
    }
    
    std::wstring headers = L"Content-Type: application/json\r\n";
    
    // Encrypt body if enabled
    std::string sendBody = body;
    if (ENCRYPTION_ENABLED && g_bAESInitialized && !body.empty()) {
        std::string encrypted = AESEncrypt(body);
        if (!encrypted.empty() && encrypted != body) {
            sendBody = "{\"encrypted\":\"" + encrypted + "\"}";
            headers += L"X-AGTR-Encrypted: 1\r\n";
        }
    }
    
    BOOL result;
    if (sendBody.empty()) {
        result = WinHttpSendRequest(hRequest, headers.c_str(), -1, NULL, 0, 0, 0);
    } else {
        result = WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)sendBody.c_str(), (DWORD)sendBody.length(), (DWORD)sendBody.length(), 0);
    }
    
    if (result) {
        result = WinHttpReceiveResponse(hRequest, NULL);
        if (result) {
            char buffer[8192] = {0};
            DWORD bytesRead = 0;
            while (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
                response.append(buffer, bytesRead);
                memset(buffer, 0, sizeof(buffer));
                bytesRead = 0;
            }
            g_bAPIOnline = true;
            g_iFailedRequests = 0;
        }
    }
    
    if (!result || response.empty()) {
        g_iFailedRequests++;
        if (g_iFailedRequests >= 3) {
            g_bAPIOnline = false;
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return response;
}

// Quick connect notification
void NotifyServerConnect() {
    if (!g_bInServer || g_bConnectionNotified) return;
    if (!g_szConnectedIP[0]) return;
    
    if (!g_bSteamIDResolved) ResolveSteamID();
    
    EnsureStringsDecrypted();
    
    char json[1024];
    sprintf(json, 
        "{\"hwid\":\"%s\","
        "\"steamid\":\"%s\","
        "\"steam_name\":\"%s\","
        "\"server_ip\":\"%s\","
        "\"server_port\":%d,"
        "\"dll_hash\":\"%.*s\","
        "\"version\":\"%s\","
        "\"event\":\"connect\"}",
        g_szHWID, g_szSteamID, g_szSteamName,
        g_szConnectedIP, g_iConnectedPort,
        AGTR_HASH_LENGTH, g_szDLLHash,
        AGTR_VERSION);
    
    Log("Connect notification: %s:%d", g_szConnectedIP, g_iConnectedPort);
    
    std::string resp = HttpRequest(g_szPathConnect, json, "POST", false);
    
    if (!resp.empty()) {
        g_bConnectionNotified = true;
        
        // Check for screenshot request
        if (strstr(resp.c_str(), "\"screenshot\":true")) {
            g_bScreenshotRequested = true;
        }
        
        // Ban check
        if (strstr(resp.c_str(), "\"status\":\"banned\"")) {
            Log("!!! BANNED ON CONNECT !!!");
            if (g_pSharedData) g_pSharedData->is_banned = 1;
            MessageBoxA(NULL, g_Settings.message_on_kick, "AGTR Anti-Cheat", MB_OK | MB_ICONERROR);
            ExitProcess(0);
        }
    }
}

// Fetch settings
bool FetchSettings() {
    EnsureStringsDecrypted();
    
    if (!g_bSteamIDResolved) ResolveSteamID();
    
    char json[512];
    sprintf(json, 
        "{\"hwid\":\"%s\","
        "\"steamid\":\"%s\","
        "\"dll_hash\":\"%.*s\","
        "\"version\":\"%s\"}",
        g_szHWID, g_szSteamID,
        AGTR_HASH_LENGTH, g_szDLLHash,
        AGTR_VERSION);
    
    std::string resp = HttpRequest(g_szPathRegister, json);
    
    if (resp.empty()) {
        Log("Settings fetch failed");
        return false;
    }
    
    Log("Settings: %.100s...", resp.c_str());
    
    // Parse settings
    if (strstr(resp.c_str(), "\"scan_enabled\":false")) g_Settings.scan_enabled = false;
    if (strstr(resp.c_str(), "\"screenshot_enabled\":false")) g_Settings.screenshot_enabled = false;
    
    const char* intPos = strstr(resp.c_str(), "\"scan_interval\":");
    if (intPos) {
        int interval = atoi(intPos + 16);
        if (interval >= 30 && interval <= 600) {
            g_Settings.scan_interval = interval * 1000;
        }
    }
    
    // Check whitelist
    if (strstr(resp.c_str(), "\"whitelisted\":true")) {
        if (g_pSharedData) g_pSharedData->is_whitelisted = 1;
    }
    
    // Ban check
    if (strstr(resp.c_str(), "\"status\":\"banned\"")) {
        Log("!!! BANNED !!!");
        if (g_pSharedData) g_pSharedData->is_banned = 1;
        MessageBoxA(NULL, g_Settings.message_on_kick, "AGTR Anti-Cheat", MB_OK | MB_ICONERROR);
        ExitProcess(0);
        return false;
    }
    
    g_bSettingsLoaded = true;
    return true;
}

// ============================================
// v14.3 - DYNAMIC BLACKLIST SYSTEM
// ============================================

// Simple JSON helper: Extract array items
static bool ExtractJSONArray(const char* json, const char* key, std::set<std::string>& output) {
    char searchKey[128];
    sprintf(searchKey, "\"%s\":[", key);

    const char* arrayStart = strstr(json, searchKey);
    if (!arrayStart) return false;

    arrayStart += strlen(searchKey);
    const char* arrayEnd = strchr(arrayStart, ']');
    if (!arrayEnd) return false;

    // Parse items: {"name":"value","severity":"..."}
    const char* pos = arrayStart;
    while (pos < arrayEnd) {
        const char* nameStart = strstr(pos, "\"name\":\"");
        if (!nameStart || nameStart >= arrayEnd) break;

        nameStart += 8;  // Skip "name":"
        const char* nameEnd = strchr(nameStart, '"');
        if (!nameEnd || nameEnd >= arrayEnd) break;

        std::string name(nameStart, nameEnd - nameStart);
        if (!name.empty()) {
            // Convert to lowercase
            for (size_t i = 0; i < name.length(); i++) {
                name[i] = tolower(name[i]);
            }
            output.insert(name);
        }

        pos = nameEnd + 1;
    }

    return !output.empty();
}

// Fetch dynamic blacklists from server
bool FetchDynamicBlacklists() {
    if (!DYNAMIC_BLACKLIST_ENABLED) return false;

    EnsureStringsDecrypted();

    // Check if we should update
    DWORD now = GetTickCount();
    if (g_bBlacklistInitialized && (now - g_dwLastBlacklistUpdate) < BLACKLIST_UPDATE_INTERVAL) {
        return true;  // Cache still valid
    }

    Log("[v14.3] Fetching dynamic blacklists...");

    // Build URL: /api/v1/blacklist/all
    wchar_t url[256];
    wcscpy(url, g_szAPIHost);
    wcscat(url, L"/api/v1/blacklist/all");

    // HTTP GET request
    std::string resp = HttpRequest(url, "", "GET", false);

    if (resp.empty() || resp.find("\"version\"") == std::string::npos) {
        Log("[v14.3] Failed to fetch blacklists, using static fallback");
        return false;
    }

    EnterCriticalSection(&g_csBlacklist);

    // Clear old data
    g_DynamicProcBlacklist.clear();
    g_DynamicDLLBlacklist.clear();
    g_DynamicWindowBlacklist.clear();
    g_DynamicStringBlacklist.clear();

    // Parse JSON arrays
    ExtractJSONArray(resp.c_str(), "processes", g_DynamicProcBlacklist);
    ExtractJSONArray(resp.c_str(), "dlls", g_DynamicDLLBlacklist);
    ExtractJSONArray(resp.c_str(), "windows", g_DynamicWindowBlacklist);
    ExtractJSONArray(resp.c_str(), "strings", g_DynamicStringBlacklist);

    // Parse hashes (if any)
    // Format: "hashes":[{"hash":"ABC123","type":"md5"}]
    const char* hashArray = strstr(resp.c_str(), "\"hashes\":[");
    if (hashArray) {
        const char* hashEnd = strchr(hashArray, ']');
        if (hashEnd) {
            const char* pos = hashArray;
            while (pos < hashEnd) {
                const char* hashStart = strstr(pos, "\"hash\":\"");
                if (!hashStart || hashStart >= hashEnd) break;

                hashStart += 8;
                const char* hashEnd2 = strchr(hashStart, '"');
                if (!hashEnd2 || hashEnd2 >= hashEnd) break;

                std::string hash(hashStart, hashEnd2 - hashStart);
                if (hash.length() >= 8) {
                    // Convert to lowercase
                    for (size_t i = 0; i < hash.length(); i++) {
                        hash[i] = (char)tolower((unsigned char)hash[i]);
                    }
                    g_HashBlacklist[hash] = "known_cheat";
                }

                pos = hashEnd2 + 1;
            }
        }
    }

    g_bBlacklistInitialized = true;
    g_dwLastBlacklistUpdate = now;

    LeaveCriticalSection(&g_csBlacklist);

    Log("[v14.3] Dynamic blacklist loaded: %d procs, %d dlls, %d windows, %d hashes",
        (int)g_DynamicProcBlacklist.size(),
        (int)g_DynamicDLLBlacklist.size(),
        (int)g_DynamicWindowBlacklist.size(),
        (int)g_HashBlacklist.size());

    return true;
}

// v14.3: Check if process is blacklisted (dynamic + static fallback)
static bool IsProcessBlacklisted_v14_3(const char* processName) {
    std::string lowerName = ToLowerStr(processName);

    // Try dynamic blacklist first
    if (g_bBlacklistInitialized && DYNAMIC_BLACKLIST_ENABLED) {
        EnterCriticalSection(&g_csBlacklist);
        bool found = (g_DynamicProcBlacklist.find(lowerName) != g_DynamicProcBlacklist.end());
        LeaveCriticalSection(&g_csBlacklist);

        if (found) {
            Log("[v14.3] DYNAMIC DETECTION: %s", processName);
            return true;
        }
    }

    // Fallback to static blacklist
    for (int i = 0; g_SusProc[i]; i++) {
        if (strstr(lowerName.c_str(), g_SusProc[i])) {
            return true;
        }
    }

    return false;
}

// v14.3: Check if DLL is blacklisted (dynamic + static fallback)
static bool IsDLLBlacklisted_v14_3(const char* dllName) {
    std::string lowerName = ToLowerStr(dllName);

    // Try dynamic blacklist first
    if (g_bBlacklistInitialized && DYNAMIC_BLACKLIST_ENABLED) {
        EnterCriticalSection(&g_csBlacklist);
        bool found = (g_DynamicDLLBlacklist.find(lowerName) != g_DynamicDLLBlacklist.end());
        LeaveCriticalSection(&g_csBlacklist);

        if (found) {
            Log("[v14.3] DYNAMIC DLL DETECTION: %s", dllName);
            return true;
        }
    }

    // Fallback to static blacklist
    for (int i = 0; g_SusDLLs[i]; i++) {
        if (strstr(lowerName.c_str(), g_SusDLLs[i])) {
            return true;
        }
    }

    return false;
}

// v14.3: Check if window is blacklisted (dynamic + static fallback)
static bool IsWindowBlacklisted_v14_3(const char* windowTitle) {
    std::string lowerTitle = ToLowerStr(windowTitle);

    // Try dynamic blacklist first
    if (g_bBlacklistInitialized && DYNAMIC_BLACKLIST_ENABLED) {
        EnterCriticalSection(&g_csBlacklist);
        std::set<std::string>::const_iterator it;
        for (it = g_DynamicWindowBlacklist.begin(); it != g_DynamicWindowBlacklist.end(); ++it) {
            if (lowerTitle.find(*it) != std::string::npos) {
                LeaveCriticalSection(&g_csBlacklist);
                Log("[v14.3] DYNAMIC WINDOW DETECTION: %s", windowTitle);
                return true;
            }
        }
        LeaveCriticalSection(&g_csBlacklist);
    }

    // Fallback to static blacklist
    for (int i = 0; g_SusWin[i]; i++) {
        if (strstr(lowerTitle.c_str(), g_SusWin[i])) {
            return true;
        }
    }

    return false;
}


// ============================================
// SCAN FUNCTIONS
// ============================================
int ScanProcesses() {
    g_Processes.clear();
    int suspicious = 0;
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe = {sizeof(pe)};
    if (Process32First(hSnap, &pe)) {
        do {
            char lowerName[MAX_PATH];
            strcpy(lowerName, pe.szExeFile);
            ToLower(lowerName);
            
            ProcessInfo pi;
            pi.name = pe.szExeFile;
            pi.pid = pe.th32ProcessID;
            pi.suspicious = false;
            
            // Whitelist check
            bool whitelisted = false;
            for (int i = 0; g_WhitelistProc[i]; i++) {
                if (strstr(lowerName, g_WhitelistProc[i])) {
                    whitelisted = true;
                    break;
                }
            }
            
            if (!whitelisted) {
                // v14.3: Use dynamic + static blacklist
                if (IsProcessBlacklisted_v14_3(pe.szExeFile)) {
                    pi.suspicious = true;
                    suspicious++;
                    Log("[PROC] Suspicious: %s (PID %d)", pe.szExeFile, pe.th32ProcessID);
                }
            }
            
            g_Processes.push_back(pi);
        } while (Process32Next(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    return suspicious;
}

int ScanModules() {
    g_Modules.clear();
    int suspicious = 0;
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    
    MODULEENTRY32 me = {sizeof(me)};
    if (Module32First(hSnap, &me)) {
        do {
            char lowerName[MAX_PATH];
            strcpy(lowerName, me.szModule);
            ToLower(lowerName);
            
            ModuleInfo mi;
            mi.name = me.szModule;
            mi.path = me.szExePath;
            mi.size = me.modBaseSize;
            
            // Hash calculation (8 karakter)
            char shortHash[16], fullHash[64];
            DWORD size;
            GetFileHash(me.szExePath, shortHash, fullHash, &size);
            mi.hash = shortHash;  // 8 karakter
            
            // v14.3: Check for suspicious DLLs (dynamic + static)
            if (IsDLLBlacklisted_v14_3(me.szModule)) {
                suspicious++;
                Log("[MOD] Suspicious: %s", me.szModule);
            }
            
            g_Modules.push_back(mi);
        } while (Module32Next(hSnap, &me));
    }
    
    CloseHandle(hSnap);
    return suspicious;
}

int ScanWindows() {
    g_Windows.clear();
    int suspicious = 0;
    
    struct WinData { std::vector<WindowInfo>* windows; int* sus; };
    WinData wd = {&g_Windows, &suspicious};
    
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        WinData* pData = (WinData*)lParam;
        
        char title[256] = {0}, className[256] = {0};
        GetWindowTextA(hwnd, title, 255);
        GetClassNameA(hwnd, className, 255);
        
        if (title[0] == 0) return TRUE;
        
        char lowerTitle[256];
        strcpy(lowerTitle, title);
        ToLower(lowerTitle);
        
        WindowInfo wi;
        wi.title = title;
        wi.className = className;
        GetWindowThreadProcessId(hwnd, &wi.pid);
        wi.suspicious = false;
        
        // v14.3: Check window title (dynamic + static)
        if (IsWindowBlacklisted_v14_3(title)) {
            wi.suspicious = true;
            (*pData->sus)++;
            Log("[WIN] Suspicious: %s", title);
        }
        
        pData->windows->push_back(wi);
        return TRUE;
    }, (LPARAM)&wd);
    
    return suspicious;
}

int ScanRegistry() {
    int suspicious = 0;
    
    HKEY hKey;
    for (int i = 0; g_SusReg[i]; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, g_SusReg[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS ||
            RegOpenKeyExA(HKEY_CURRENT_USER, g_SusReg[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            suspicious++;
            Log("[REG] Suspicious: %s", g_SusReg[i]);
        }
    }
    
    return suspicious;
}

int CheckSusFiles() {
    int suspicious = 0;
    
    // Check game directory
    char searchPath[MAX_PATH];
    sprintf(searchPath, "%s\\*", g_szGameDir);
    
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            
            char lowerName[MAX_PATH];
            strcpy(lowerName, fd.cFileName);
            ToLower(lowerName);
            
            for (int i = 0; g_SusFile[i]; i++) {
                if (strstr(lowerName, g_SusFile[i])) {
                    suspicious++;
                    Log("[FILE] Suspicious: %s", fd.cFileName);
                    break;
                }
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    
    return suspicious;
}

// Memory pattern scan
void* memmem(const void* haystack, size_t haystacklen, const void* needle, size_t needlelen) {
    if (!needlelen) return (void*)haystack;
    if (haystacklen < needlelen) return NULL;
    const char* h = (const char*)haystack;
    const char* n = (const char*)needle;
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(h + i, n, needlelen) == 0) return (void*)(h + i);
    }
    return NULL;
}

int ScanMemoryPatterns() {
    int found = 0;
    HANDLE hProc = GetCurrentProcess();
    
    const char* patterns[] = {
        "aimbot_enable", "wallhack_on", "esp_draw",
        "bhop_auto", "norecoil", "triggerbot", "speedhack",
        NULL
    };
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;
    
    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            
            if (mbi.RegionSize <= 1024 * 1024) {
                BYTE* buffer = (BYTE*)malloc(mbi.RegionSize);
                if (buffer) {
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) {
                        for (int i = 0; patterns[i]; i++) {
                            if (memmem(buffer, bytesRead, patterns[i], strlen(patterns[i]))) {
                                Log("[MEM] Pattern found: %s", patterns[i]);
                                found++;
                            }
                        }
                    }
                    free(buffer);
                }
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    
    return found;
}

// ============================================
// BUILD JSON
// ============================================
std::string BuildJson() {
    char buf[32768];
    char* p = buf;
    
    p += sprintf(p, "{\"hwid\":\"%s\",", g_szHWID);
    p += sprintf(p, "\"steamid\":\"%s\",", g_szSteamID);
    p += sprintf(p, "\"steam_name\":\"%s\",", g_szSteamName);
    p += sprintf(p, "\"server_ip\":\"%s\",", g_bInServer ? g_szConnectedIP : "");
    p += sprintf(p, "\"server_port\":%d,", g_bInServer ? g_iConnectedPort : 0);
    p += sprintf(p, "\"dll_hash\":\"%.*s\",", AGTR_HASH_LENGTH, g_szDLLHash);
    p += sprintf(p, "\"dll_name\":\"%s\",", g_szSelfName);
    p += sprintf(p, "\"version\":\"%s\",", AGTR_VERSION);
    p += sprintf(p, "\"passed\":%s,", g_bPassed ? "true" : "false");
    p += sprintf(p, "\"sus_count\":%d,", g_iSusCount);
    
    // Security flags
    p += sprintf(p, "\"debugger\":%s,", g_bDebuggerDetected ? "true" : "false");
    p += sprintf(p, "\"vm\":%s,", g_bVMDetected ? "true" : "false");
    p += sprintf(p, "\"hooks\":%s,", g_bHooksDetected ? "true" : "false");
    p += sprintf(p, "\"injection\":%s,", g_bInjectionDetected ? "true" : "false");
    p += sprintf(p, "\"drivers\":%s,", g_bDriversDetected ? "true" : "false");
    
    // Processes (suspicious only)
    p += sprintf(p, "\"processes\":[");
    bool first = true;
    for (auto& proc : g_Processes) {
        if (proc.suspicious) {
            if (!first) *p++ = ',';
            p += sprintf(p, "{\"name\":\"%s\",\"pid\":%d}", proc.name.c_str(), proc.pid);
            first = false;
        }
    }
    p += sprintf(p, "],");
    
    // Modules (with 8-char hash)
    p += sprintf(p, "\"modules\":[");
    first = true;
    int modCount = 0;
    for (auto& mod : g_Modules) {
        if (modCount++ > 50) break;  // Limit
        if (!first) *p++ = ',';
        p += sprintf(p, "{\"name\":\"%s\",\"hash\":\"%s\",\"size\":%d}",
            mod.name.c_str(), mod.hash.c_str(), mod.size);
        first = false;
    }
    p += sprintf(p, "]}");
    
    return std::string(buf);
}

void SendToAPI(const std::string& json, const std::string& sig) {
    EnsureStringsDecrypted();
    
    g_dwLastDataHash = 0;
    for (size_t i = 0; i < json.length(); i += 64) {
        g_dwLastDataHash ^= (DWORD)json[i] << ((i % 4) * 8);
    }
    
    std::string resp = HttpRequest(g_szPathScan, json, "POST", true);
    
    if (!resp.empty()) {
        g_dwLastSuccessfulSend = GetTickCount();
        
        // Check for commands in response
        if (strstr(resp.c_str(), "\"screenshot\":true") || strstr(resp.c_str(), "\"action\":\"screenshot\"")) {
            g_bScreenshotRequested = true;
            Log("Screenshot requested by server");
        }
        
        if (strstr(resp.c_str(), "\"action\":\"kick\"") || strstr(resp.c_str(), "\"status\":\"banned\"")) {
            Log("!!! KICKED/BANNED !!!");
            if (g_pSharedData) g_pSharedData->is_banned = 1;
            MessageBoxA(NULL, g_Settings.message_on_kick, "AGTR Anti-Cheat", MB_OK | MB_ICONERROR);
            ExitProcess(0);
        }
    }
}

// ============================================
// MAIN SCAN
// ============================================
void DoScan() {
    Log("=== Starting Scan v14.0 ===");
    
    // v14.0 - Smart throttling
    if (ShouldSkipHeavyScan()) {
        Log("[SCAN] Skipping heavy scans - low FPS");
        return;
    }
    
    g_iSusCount = 0;
    
    // Standard scans
    if (g_Settings.scan_processes) g_iSusCount += ScanProcesses();
    if (g_Settings.scan_modules) g_iSusCount += ScanModules();
    if (g_Settings.scan_windows) g_iSusCount += ScanWindows();
    if (g_Settings.scan_registry) g_iSusCount += ScanRegistry();
    if (g_Settings.scan_files) g_iSusCount += CheckSusFiles();
    
    // v14.0 - Enhanced window scan with overlay detection
    if (WINDOW_ENUM_ENABLED && g_RTConfig.scan_windows) {
        g_iSusCount += ScanWindows_v14();
    }
    
    // v14.0 - String scanner
    if (STRING_SCANNER_ENABLED && g_RTConfig.scan_strings) {
        g_iSusCount += ScanMemoryStrings();
    }
    
    // v14.0 - DLL load monitor
    if (DLL_MONITOR_ENABLED && g_RTConfig.scan_dlls) {
        g_iSusCount += CheckNewDLLs();
    }
    
    // v14.0 - Code section hash verification
    if (CODE_HASH_ENABLED) {
        g_iSusCount += VerifyCodeSection();
    }
    
    // v14.0 - Stack trace validation
    if (STACK_TRACE_ENABLED && !ValidateStackTrace()) {
        Log("[STACK] Invalid stack trace!");
        g_iSusCount++;
    }
    
    // v14.0 - NtQuery hook detection
    if (NTQUERY_HOOK_ENABLED && CheckNtQueryHooks()) {
        g_iSusCount++;
    }
    
    // v14.0 - PEB manipulation check
    if (PEB_CHECK_ENABLED && CheckPEBManipulation()) {
        g_iSusCount++;
    }
    
    // Security checks
    g_bDebuggerDetected = CheckDebugger();
    if (g_bDebuggerDetected) {
        Log("!!! DEBUGGER DETECTED !!!");
        g_iSusCount++;
    }
    
    CheckVirtualMachine();
    
    // v13.0 - Enhanced detection
    if (KERNEL_DETECTION_ENABLED) {
        g_iSusCount += ScanKernelDrivers();
    }
    
    if (INJECTION_DETECTION_ENABLED) {
        g_iSusCount += ScanCodeInjection();
    }
    
    // Memory scan (only first time)
    if (!g_bFirstScanDone) {
        int memPatterns = ScanMemoryPatterns();
        if (memPatterns > 0) {
            Log("!!! %d MEMORY PATTERNS FOUND !!!", memPatterns);
            g_iSusCount += memPatterns;
        }
        g_bFirstScanDone = true;
    }
    
    g_bPassed = (g_iSusCount == 0) && !g_bDebuggerDetected && !g_bHooksDetected && !g_bInjectionDetected;
    
    // Update SMA shared data
    if (g_pSharedData) {
        g_pSharedData->scan_passed = g_bPassed ? 1 : 0;
        g_pSharedData->sus_count = g_iSusCount;
        g_pSharedData->last_scan_time = (DWORD)time(NULL);
        g_pSharedData->debugger_detected = g_bDebuggerDetected ? 1 : 0;
        g_pSharedData->vm_detected = g_bVMDetected ? 1 : 0;
        g_pSharedData->hooks_detected = g_bHooksDetected ? 1 : 0;
        g_pSharedData->injection_detected = g_bInjectionDetected ? 1 : 0;
        snprintf(g_pSharedData->last_scan_result, sizeof(g_pSharedData->last_scan_result),
            "%s|sus:%d|proc:%d|mod:%d", g_bPassed ? "CLEAN" : "SUS", g_iSusCount,
            (int)g_Processes.size(), (int)g_Modules.size());
    }
    
    std::string json = BuildJson();
    
    Log("Scan: %s | Sus:%d | Proc:%d | Mod:%d | FPS:%d", 
        g_bPassed ? "CLEAN" : "SUS", g_iSusCount, 
        (int)g_Processes.size(), (int)g_Modules.size(), g_iCurrentFPS);
    
    SendToAPI(json, "");
}

// ============================================
// SCAN THREAD
// ============================================
DWORD WINAPI ScanThread(LPVOID) {
    // Low priority - don't affect game
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    
    Sleep(3000);  // Wait for game to initialize
    
    // v14.0 - Initialize new systems
    if (MEMORY_POOL_ENABLED) g_MemPool.Init();
    if (ASYNC_SCAN_ENABLED) InitAsyncScan();
    if (DLL_MONITOR_ENABLED) InitDLLMonitor();
    if (CODE_HASH_ENABLED) InitCodeHash();
    if (HOT_RELOAD_ENABLED) InitConfigReload(g_szGameDir);

    // Initialize security (heavy operations)
    InitSecurity();

    // Initialize SMA communication
    InitSMASharedMemory();

    // Initialize AES encryption
    InitAESEncryption();

    // v14.3 - Initialize dynamic blacklist system
    if (DYNAMIC_BLACKLIST_ENABLED) {
        InitializeCriticalSection(&g_csBlacklist);
        Log("[v14.3] Initializing dynamic blacklist system...");
    }
    
    // Generate IDs
    GenHWID();
    ComputeDLLHash();
    
    // Fetch settings
    FetchSettings();

    // v14.3 - Fetch dynamic blacklists from server
    if (DYNAMIC_BLACKLIST_ENABLED) {
        if (!FetchDynamicBlacklists()) {
            Log("[v14.3] Using static fallback blacklists");
        }
    }

    // Initial scan
    DoScan();
    
    // Check for updates
    UpdateInfo updateInfo = {0};
    if (CheckForUpdates(&updateInfo)) {
        // Don't block, just notify
    }
    
    DWORD lastScan = GetTickCount();
    DWORD lastHeartbeat = GetTickCount();
    DWORD lastSMAUpdate = GetTickCount();
    DWORD lastCommandCheck = GetTickCount();
    DWORD lastConfigCheck = GetTickCount();
    DWORD lastDLLCheck = GetTickCount();
    
    while (g_bRunning) {
        Sleep(1000);  // 1 second tick
        
        DWORD now = GetTickCount();
        
        // v14.0 - Config hot-reload
        if (HOT_RELOAD_ENABLED && now - lastConfigCheck >= CONFIG_CHECK_INTERVAL) {
            CheckConfigReload();
            lastConfigCheck = now;
        }
        
        // v14.0 - DLL monitor (frequent check)
        if (DLL_MONITOR_ENABLED && now - lastDLLCheck >= 5000) {
            CheckNewDLLs();
            lastDLLCheck = now;
        }
        
        // Detect server
        DetectConnectedServer();
        
        // Quick connect notification
        if (g_bInServer && !g_bConnectionNotified) {
            NotifyServerConnect();
        }
        
        // SMA shared memory update
        if (now - lastSMAUpdate >= SMA_HEARTBEAT_INTERVAL) {
            UpdateSMASharedData();
            lastSMAUpdate = now;
        }
        
        // Check commands (from SMA or API response)
        if (now - lastCommandCheck >= 1000) {
            CheckSMACommands();
            lastCommandCheck = now;
        }
        
        // Screenshot if requested
        if (g_bScreenshotRequested && g_Settings.screenshot_enabled) {
            g_bScreenshotRequested = false;
            SendScreenshot();
        }
        
        // Scan
        DWORD scanInterval = g_Settings.scan_interval;
        if (g_Settings.scan_only_in_server && !g_bInServer) {
            scanInterval *= 2;  // Slower when not in server
        }
        
        if (g_Settings.scan_enabled && (now - lastScan >= scanInterval)) {
            DoScan();
            lastScan = now;
        }
        
        // Update check
        if (now - g_dwLastUpdateCheck >= UPDATE_CHECK_INTERVAL) {
            UpdateInfo ui = {0};
            if (CheckForUpdates(&ui) && ui.required) {
                ApplyUpdate();
            }
        }
    }
    
    return 0;
}


// ============================================
// INIT/SHUTDOWN
// ============================================
void InitSecurity() {
    if (g_bSecurityInitialized) return;
    g_bSecurityInitialized = true;
    
    CalculateSelfHash();
    Log("Security: DLL=%s Hash=%s", g_szSelfName, g_szSelfHash);
}

void Init() {
    InitializeCriticalSection(&g_csLog);
    
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) *slash = 0;
    
    strcpy(g_szGameDir, path);
    sprintf(g_szValveDir, "%s\\valve", path);
    
    EnsureStringsDecrypted();
    
    Log("Init: %s (v%s)", g_szGameDir, AGTR_VERSION);
}

void StartScanThread() {
    if (g_bThreadStarted) return;
    g_bThreadStarted = true;
    g_bRunning = true;
    g_hThread = CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
}

void Shutdown() {
    g_bRunning = false;
    
    if (g_hThread) { 
        WaitForSingleObject(g_hThread, 2000); 
        CloseHandle(g_hThread); 
    }
    
    // v14.0 - Cleanup
    if (MEMORY_POOL_ENABLED) g_MemPool.Cleanup();
    if (ASYNC_SCAN_ENABLED && g_bAsyncInitialized) DeleteCriticalSection(&g_csScanQueue);
    if (DLL_MONITOR_ENABLED && g_bDLLMonInit) DeleteCriticalSection(&g_csDLLMon);

    // v14.3 - Cleanup
    if (DYNAMIC_BLACKLIST_ENABLED && g_bBlacklistInitialized) DeleteCriticalSection(&g_csBlacklist);

    CloseSMASharedMemory();
    ShutdownGdiplus();
    
    if (g_LogFile) { 
        fclose(g_LogFile); 
        g_LogFile = NULL; 
    }
    
    DeleteCriticalSection(&g_csLog);
}

// ============================================
// ORIGINAL WINMM FUNCTION POINTERS (ALL)
// ============================================
static HMODULE g_hOrigWinmm = NULL;

// Macro for easy proxy
#define PROXY_FUNC(name) static FARPROC o_##name = NULL;

PROXY_FUNC(timeGetTime)
PROXY_FUNC(timeBeginPeriod)
PROXY_FUNC(timeEndPeriod)
PROXY_FUNC(timeGetDevCaps)
PROXY_FUNC(timeGetSystemTime)
PROXY_FUNC(timeSetEvent)
PROXY_FUNC(timeKillEvent)
PROXY_FUNC(waveOutOpen)
PROXY_FUNC(waveOutClose)
PROXY_FUNC(waveOutWrite)
PROXY_FUNC(waveOutPrepareHeader)
PROXY_FUNC(waveOutUnprepareHeader)
PROXY_FUNC(waveOutReset)
PROXY_FUNC(waveOutPause)
PROXY_FUNC(waveOutRestart)
PROXY_FUNC(waveOutGetPosition)
PROXY_FUNC(waveOutGetDevCapsA)
PROXY_FUNC(waveOutGetDevCapsW)
PROXY_FUNC(waveOutGetNumDevs)
PROXY_FUNC(waveOutGetVolume)
PROXY_FUNC(waveOutSetVolume)
PROXY_FUNC(waveOutGetErrorTextA)
PROXY_FUNC(waveOutGetErrorTextW)
PROXY_FUNC(waveOutGetID)
PROXY_FUNC(waveOutMessage)
PROXY_FUNC(waveOutBreakLoop)
PROXY_FUNC(waveInOpen)
PROXY_FUNC(waveInClose)
PROXY_FUNC(waveInGetNumDevs)
PROXY_FUNC(waveInGetDevCapsA)
PROXY_FUNC(waveInGetDevCapsW)
PROXY_FUNC(waveInStart)
PROXY_FUNC(waveInStop)
PROXY_FUNC(waveInReset)
PROXY_FUNC(waveInPrepareHeader)
PROXY_FUNC(waveInUnprepareHeader)
PROXY_FUNC(waveInAddBuffer)
PROXY_FUNC(waveInGetPosition)
PROXY_FUNC(waveInGetID)
PROXY_FUNC(waveInGetErrorTextA)
PROXY_FUNC(waveInGetErrorTextW)
PROXY_FUNC(waveInMessage)
PROXY_FUNC(PlaySoundA)
PROXY_FUNC(PlaySoundW)
PROXY_FUNC(sndPlaySoundA)
PROXY_FUNC(sndPlaySoundW)
PROXY_FUNC(joyGetNumDevs)
PROXY_FUNC(joyGetDevCapsA)
PROXY_FUNC(joyGetDevCapsW)
PROXY_FUNC(joyGetPos)
PROXY_FUNC(joyGetPosEx)
PROXY_FUNC(joyGetThreshold)
PROXY_FUNC(joySetThreshold)
PROXY_FUNC(joySetCapture)
PROXY_FUNC(joyReleaseCapture)
PROXY_FUNC(midiOutGetNumDevs)
PROXY_FUNC(midiOutGetDevCapsA)
PROXY_FUNC(midiOutGetDevCapsW)
PROXY_FUNC(midiOutOpen)
PROXY_FUNC(midiOutClose)
PROXY_FUNC(midiOutShortMsg)
PROXY_FUNC(midiOutLongMsg)
PROXY_FUNC(midiOutReset)
PROXY_FUNC(midiOutPrepareHeader)
PROXY_FUNC(midiOutUnprepareHeader)
PROXY_FUNC(auxGetNumDevs)
PROXY_FUNC(auxGetDevCapsA)
PROXY_FUNC(auxGetDevCapsW)
PROXY_FUNC(auxGetVolume)
PROXY_FUNC(auxSetVolume)
PROXY_FUNC(auxOutMessage)
PROXY_FUNC(mixerGetNumDevs)
PROXY_FUNC(mixerOpen)
PROXY_FUNC(mixerClose)
PROXY_FUNC(mixerGetDevCapsA)
PROXY_FUNC(mixerGetDevCapsW)
PROXY_FUNC(mixerGetLineInfoA)
PROXY_FUNC(mixerGetLineInfoW)
PROXY_FUNC(mixerGetLineControlsA)
PROXY_FUNC(mixerGetLineControlsW)
PROXY_FUNC(mixerGetControlDetailsA)
PROXY_FUNC(mixerGetControlDetailsW)
PROXY_FUNC(mixerSetControlDetails)
PROXY_FUNC(mixerGetID)
PROXY_FUNC(mixerMessage)
PROXY_FUNC(mciSendCommandA)
PROXY_FUNC(mciSendCommandW)
PROXY_FUNC(mciSendStringA)
PROXY_FUNC(mciSendStringW)
PROXY_FUNC(mciGetErrorStringA)
PROXY_FUNC(mciGetErrorStringW)
PROXY_FUNC(mciGetDeviceIDA)
PROXY_FUNC(mciGetDeviceIDW)
PROXY_FUNC(mciGetDeviceIDFromElementIDA)
PROXY_FUNC(mciGetDeviceIDFromElementIDW)
PROXY_FUNC(mciSetYieldProc)
PROXY_FUNC(mciGetYieldProc)
PROXY_FUNC(mciGetCreatorTask)
PROXY_FUNC(mciExecute)
PROXY_FUNC(mmioOpenA)
PROXY_FUNC(mmioOpenW)
PROXY_FUNC(mmioClose)
PROXY_FUNC(mmioRead)
PROXY_FUNC(mmioWrite)
PROXY_FUNC(mmioSeek)
PROXY_FUNC(mmioGetInfo)
PROXY_FUNC(mmioSetInfo)
PROXY_FUNC(mmioSetBuffer)
PROXY_FUNC(mmioFlush)
PROXY_FUNC(mmioAdvance)
PROXY_FUNC(mmioInstallIOProcA)
PROXY_FUNC(mmioInstallIOProcW)
PROXY_FUNC(mmioStringToFOURCCA)
PROXY_FUNC(mmioStringToFOURCCW)
PROXY_FUNC(mmioDescend)
PROXY_FUNC(mmioAscend)
PROXY_FUNC(mmioCreateChunk)
PROXY_FUNC(mmioRenameA)
PROXY_FUNC(mmioSendMessage)

#define LOAD_FUNC(name) o_##name = GetProcAddress(g_hOrigWinmm, #name)

bool LoadOriginal() {
    if (g_hOrigWinmm) return true;
    
    char sysPath[MAX_PATH];
    GetSystemDirectoryA(sysPath, MAX_PATH);
    strcat(sysPath, "\\winmm.dll");
    
    g_hOrigWinmm = LoadLibraryA(sysPath);
    if (!g_hOrigWinmm) {
        Log("FATAL: Cannot load original winmm.dll");
        return false;
    }
    
    // Load all functions
    LOAD_FUNC(timeGetTime);
    LOAD_FUNC(timeBeginPeriod);
    LOAD_FUNC(timeEndPeriod);
    LOAD_FUNC(timeGetDevCaps);
    LOAD_FUNC(timeGetSystemTime);
    LOAD_FUNC(timeSetEvent);
    LOAD_FUNC(timeKillEvent);
    LOAD_FUNC(waveOutOpen);
    LOAD_FUNC(waveOutClose);
    LOAD_FUNC(waveOutWrite);
    LOAD_FUNC(waveOutPrepareHeader);
    LOAD_FUNC(waveOutUnprepareHeader);
    LOAD_FUNC(waveOutReset);
    LOAD_FUNC(waveOutPause);
    LOAD_FUNC(waveOutRestart);
    LOAD_FUNC(waveOutGetPosition);
    LOAD_FUNC(waveOutGetDevCapsA);
    LOAD_FUNC(waveOutGetDevCapsW);
    LOAD_FUNC(waveOutGetNumDevs);
    LOAD_FUNC(waveOutGetVolume);
    LOAD_FUNC(waveOutSetVolume);
    LOAD_FUNC(waveOutGetErrorTextA);
    LOAD_FUNC(waveOutGetErrorTextW);
    LOAD_FUNC(waveOutGetID);
    LOAD_FUNC(waveOutMessage);
    LOAD_FUNC(waveOutBreakLoop);
    LOAD_FUNC(waveInOpen);
    LOAD_FUNC(waveInClose);
    LOAD_FUNC(waveInGetNumDevs);
    LOAD_FUNC(waveInGetDevCapsA);
    LOAD_FUNC(waveInGetDevCapsW);
    LOAD_FUNC(waveInStart);
    LOAD_FUNC(waveInStop);
    LOAD_FUNC(waveInReset);
    LOAD_FUNC(waveInPrepareHeader);
    LOAD_FUNC(waveInUnprepareHeader);
    LOAD_FUNC(waveInAddBuffer);
    LOAD_FUNC(waveInGetPosition);
    LOAD_FUNC(waveInGetID);
    LOAD_FUNC(waveInGetErrorTextA);
    LOAD_FUNC(waveInGetErrorTextW);
    LOAD_FUNC(waveInMessage);
    LOAD_FUNC(PlaySoundA);
    LOAD_FUNC(PlaySoundW);
    LOAD_FUNC(sndPlaySoundA);
    LOAD_FUNC(sndPlaySoundW);
    LOAD_FUNC(joyGetNumDevs);
    LOAD_FUNC(joyGetDevCapsA);
    LOAD_FUNC(joyGetDevCapsW);
    LOAD_FUNC(joyGetPos);
    LOAD_FUNC(joyGetPosEx);
    LOAD_FUNC(joyGetThreshold);
    LOAD_FUNC(joySetThreshold);
    LOAD_FUNC(joySetCapture);
    LOAD_FUNC(joyReleaseCapture);
    LOAD_FUNC(midiOutGetNumDevs);
    LOAD_FUNC(midiOutGetDevCapsA);
    LOAD_FUNC(midiOutGetDevCapsW);
    LOAD_FUNC(midiOutOpen);
    LOAD_FUNC(midiOutClose);
    LOAD_FUNC(midiOutShortMsg);
    LOAD_FUNC(midiOutLongMsg);
    LOAD_FUNC(midiOutReset);
    LOAD_FUNC(midiOutPrepareHeader);
    LOAD_FUNC(midiOutUnprepareHeader);
    LOAD_FUNC(auxGetNumDevs);
    LOAD_FUNC(auxGetDevCapsA);
    LOAD_FUNC(auxGetDevCapsW);
    LOAD_FUNC(auxGetVolume);
    LOAD_FUNC(auxSetVolume);
    LOAD_FUNC(auxOutMessage);
    LOAD_FUNC(mixerGetNumDevs);
    LOAD_FUNC(mixerOpen);
    LOAD_FUNC(mixerClose);
    LOAD_FUNC(mixerGetDevCapsA);
    LOAD_FUNC(mixerGetDevCapsW);
    LOAD_FUNC(mixerGetLineInfoA);
    LOAD_FUNC(mixerGetLineInfoW);
    LOAD_FUNC(mixerGetLineControlsA);
    LOAD_FUNC(mixerGetLineControlsW);
    LOAD_FUNC(mixerGetControlDetailsA);
    LOAD_FUNC(mixerGetControlDetailsW);
    LOAD_FUNC(mixerSetControlDetails);
    LOAD_FUNC(mixerGetID);
    LOAD_FUNC(mixerMessage);
    LOAD_FUNC(mciSendCommandA);
    LOAD_FUNC(mciSendCommandW);
    LOAD_FUNC(mciSendStringA);
    LOAD_FUNC(mciSendStringW);
    LOAD_FUNC(mciGetErrorStringA);
    LOAD_FUNC(mciGetErrorStringW);
    LOAD_FUNC(mciGetDeviceIDA);
    LOAD_FUNC(mciGetDeviceIDW);
    LOAD_FUNC(mciGetDeviceIDFromElementIDA);
    LOAD_FUNC(mciGetDeviceIDFromElementIDW);
    LOAD_FUNC(mciSetYieldProc);
    LOAD_FUNC(mciGetYieldProc);
    LOAD_FUNC(mciGetCreatorTask);
    LOAD_FUNC(mciExecute);
    LOAD_FUNC(mmioOpenA);
    LOAD_FUNC(mmioOpenW);
    LOAD_FUNC(mmioClose);
    LOAD_FUNC(mmioRead);
    LOAD_FUNC(mmioWrite);
    LOAD_FUNC(mmioSeek);
    LOAD_FUNC(mmioGetInfo);
    LOAD_FUNC(mmioSetInfo);
    LOAD_FUNC(mmioSetBuffer);
    LOAD_FUNC(mmioFlush);
    LOAD_FUNC(mmioAdvance);
    LOAD_FUNC(mmioInstallIOProcA);
    LOAD_FUNC(mmioInstallIOProcW);
    LOAD_FUNC(mmioStringToFOURCCA);
    LOAD_FUNC(mmioStringToFOURCCW);
    LOAD_FUNC(mmioDescend);
    LOAD_FUNC(mmioAscend);
    LOAD_FUNC(mmioCreateChunk);
    LOAD_FUNC(mmioRenameA);
    LOAD_FUNC(mmioSendMessage);
    
    return true;
}

// ============================================
// EXPORTED FUNCTIONS (PROXY)
// ============================================
extern "C" {

// Macro for simple proxy exports
#define PROXY_EXPORT(name, ret, fail) \
    __declspec(dllexport) ret WINAPI name() { \
        if (!LoadOriginal() || !o_##name) return fail; \
        typedef ret (WINAPI *fn)(); \
        return ((fn)o_##name)(); \
    }

// Helper typedefs
typedef DWORD (WINAPI *fn_timeGetTime)(void);
typedef MMRESULT (WINAPI *fn_UINT)(UINT);
typedef MMRESULT (WINAPI *fn_TIMECAPS)(LPTIMECAPS, UINT);
typedef MMRESULT (WINAPI *fn_MMTIME)(LPMMTIME, UINT);
typedef MMRESULT (WINAPI *fn_TIMESET)(UINT, UINT, LPTIMECALLBACK, DWORD_PTR, UINT);
typedef MMRESULT (WINAPI *fn_WAVEOUT6)(LPHWAVEOUT, UINT, LPCWAVEFORMATEX, DWORD_PTR, DWORD_PTR, DWORD);
typedef MMRESULT (WINAPI *fn_HWO)(HWAVEOUT);
typedef MMRESULT (WINAPI *fn_HWO_HDR)(HWAVEOUT, LPWAVEHDR, UINT);
typedef UINT (WINAPI *fn_VOID_UINT)(void);
typedef BOOL (WINAPI *fn_PLAYSOUND_A)(LPCSTR, HMODULE, DWORD);
typedef BOOL (WINAPI *fn_PLAYSOUND_W)(LPCWSTR, HMODULE, DWORD);

__declspec(dllexport) DWORD WINAPI timeGetTime(void) {
    if (!LoadOriginal() || !o_timeGetTime) return 0;
    UpdateFPSCounter();
    return ((fn_timeGetTime)o_timeGetTime)();
}

__declspec(dllexport) MMRESULT WINAPI timeBeginPeriod(UINT u) {
    if (!LoadOriginal() || !o_timeBeginPeriod) return TIMERR_NOCANDO;
    return ((fn_UINT)o_timeBeginPeriod)(u);
}

__declspec(dllexport) MMRESULT WINAPI timeEndPeriod(UINT u) {
    if (!LoadOriginal() || !o_timeEndPeriod) return TIMERR_NOCANDO;
    return ((fn_UINT)o_timeEndPeriod)(u);
}

__declspec(dllexport) MMRESULT WINAPI timeGetDevCaps(LPTIMECAPS p, UINT u) {
    if (!LoadOriginal() || !o_timeGetDevCaps) return TIMERR_NOCANDO;
    return ((fn_TIMECAPS)o_timeGetDevCaps)(p, u);
}

__declspec(dllexport) MMRESULT WINAPI timeGetSystemTime(LPMMTIME p, UINT u) {
    if (!LoadOriginal() || !o_timeGetSystemTime) return TIMERR_NOCANDO;
    return ((fn_MMTIME)o_timeGetSystemTime)(p, u);
}

__declspec(dllexport) MMRESULT WINAPI timeSetEvent(UINT a, UINT b, LPTIMECALLBACK c, DWORD_PTR d, UINT e) {
    if (!LoadOriginal() || !o_timeSetEvent) return 0;
    return ((fn_TIMESET)o_timeSetEvent)(a, b, c, d, e);
}

__declspec(dllexport) MMRESULT WINAPI timeKillEvent(UINT u) {
    if (!LoadOriginal() || !o_timeKillEvent) return TIMERR_NOCANDO;
    return ((fn_UINT)o_timeKillEvent)(u);
}

// Generic forwarder macro for remaining functions
#define FWD(name) \
    __declspec(dllexport) void* WINAPI name() { \
        LoadOriginal(); \
        return o_##name ? ((void*(WINAPI*)())o_##name)() : 0; \
    }

// WaveOut functions
__declspec(dllexport) MMRESULT WINAPI waveOutOpen(LPHWAVEOUT a, UINT b, LPCWAVEFORMATEX c, DWORD_PTR d, DWORD_PTR e, DWORD f) {
    if (!LoadOriginal() || !o_waveOutOpen) return MMSYSERR_ERROR;
    return ((fn_WAVEOUT6)o_waveOutOpen)(a, b, c, d, e, f);
}

__declspec(dllexport) MMRESULT WINAPI waveOutClose(HWAVEOUT h) {
    if (!LoadOriginal() || !o_waveOutClose) return MMSYSERR_ERROR;
    return ((fn_HWO)o_waveOutClose)(h);
}

__declspec(dllexport) MMRESULT WINAPI waveOutWrite(HWAVEOUT h, LPWAVEHDR p, UINT u) {
    if (!LoadOriginal() || !o_waveOutWrite) return MMSYSERR_ERROR;
    return ((fn_HWO_HDR)o_waveOutWrite)(h, p, u);
}

__declspec(dllexport) MMRESULT WINAPI waveOutPrepareHeader(HWAVEOUT h, LPWAVEHDR p, UINT u) {
    if (!LoadOriginal() || !o_waveOutPrepareHeader) return MMSYSERR_ERROR;
    return ((fn_HWO_HDR)o_waveOutPrepareHeader)(h, p, u);
}

__declspec(dllexport) MMRESULT WINAPI waveOutUnprepareHeader(HWAVEOUT h, LPWAVEHDR p, UINT u) {
    if (!LoadOriginal() || !o_waveOutUnprepareHeader) return MMSYSERR_ERROR;
    return ((fn_HWO_HDR)o_waveOutUnprepareHeader)(h, p, u);
}

__declspec(dllexport) MMRESULT WINAPI waveOutReset(HWAVEOUT h) {
    if (!LoadOriginal() || !o_waveOutReset) return MMSYSERR_ERROR;
    return ((fn_HWO)o_waveOutReset)(h);
}

__declspec(dllexport) MMRESULT WINAPI waveOutPause(HWAVEOUT h) {
    if (!LoadOriginal() || !o_waveOutPause) return MMSYSERR_ERROR;
    return ((fn_HWO)o_waveOutPause)(h);
}

__declspec(dllexport) MMRESULT WINAPI waveOutRestart(HWAVEOUT h) {
    if (!LoadOriginal() || !o_waveOutRestart) return MMSYSERR_ERROR;
    return ((fn_HWO)o_waveOutRestart)(h);
}

__declspec(dllexport) UINT WINAPI waveOutGetNumDevs(void) {
    if (!LoadOriginal() || !o_waveOutGetNumDevs) return 0;
    return ((fn_VOID_UINT)o_waveOutGetNumDevs)();
}

__declspec(dllexport) BOOL WINAPI PlaySoundA(LPCSTR p, HMODULE h, DWORD d) {
    if (!LoadOriginal() || !o_PlaySoundA) return FALSE;
    return ((fn_PLAYSOUND_A)o_PlaySoundA)(p, h, d);
}

__declspec(dllexport) BOOL WINAPI PlaySoundW(LPCWSTR p, HMODULE h, DWORD d) {
    if (!LoadOriginal() || !o_PlaySoundW) return FALSE;
    return ((fn_PLAYSOUND_W)o_PlaySoundW)(p, h, d);
}

} // extern "C"


// ============================================
// DLL MAIN
// ============================================
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        LoadOriginal();
        Init();
        StartScanThread();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Shutdown();
    }
    return TRUE;
}
