/*
 * AGTR Anti-Cheat v13.0 - Shared Header
 * =====================================
 * Common definitions for all DLL proxies
 */

#ifndef AGTR_SHARED_H
#define AGTR_SHARED_H

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ctype.h>
#include <string>
#include <vector>
#include <map>
#include <gdiplus.h>

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

// ============================================
// VERSION & CONFIG
// ============================================
#define AGTR_VERSION "13.0"
#define AGTR_HASH_LENGTH 8

// Heartbeat intervals (milliseconds)
#define HEARTBEAT_IN_SERVER 30000
#define HEARTBEAT_IN_MENU 120000
#define HEARTBEAT_OFFLINE_RETRY 60000

// Throttling
#define THROTTLE_MIN_INTERVAL 300000
#define OFFLINE_CACHE_MAX 10

// API Config
#define API_PORT 5000
#define API_USE_HTTPS false
#define API_TIMEOUT 5000

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
#define SMA_SHARED_MEM_NAME "AGTR_SHARED_v13"
#define SMA_SHARED_MEM_SIZE 4096
#define SMA_HEARTBEAT_INTERVAL 5000

// Screenshot Config
#define SCREENSHOT_QUALITY 50
#define SCREENSHOT_MAX_SIZE 150000
#define SCREENSHOT_COOLDOWN 30000

// Auto-Update Config
#define UPDATE_CHECK_INTERVAL 3600000

// ============================================
// ENCRYPTION (XOR with rotating key)
// ============================================
static const BYTE ENC_KEY[] = {0xA7, 0x3F, 0x8C, 0x51, 0xD2, 0x6E, 0xB9, 0x04};
#define ENC_KEY_LEN 8

// "185.171.25.137" encrypted
static const BYTE ENC_API_HOST[] = {0x96, 0x07, 0xB9, 0x7F, 0xE3, 0x59, 0x88, 0x2A, 0x95, 0x0A, 0xA2, 0x60, 0xE1, 0x59};
#define ENC_API_HOST_LEN 14

// "/api/v1/scan" encrypted  
static const BYTE ENC_PATH_SCAN[] = {0x88, 0x5E, 0xFC, 0x38, 0xFD, 0x18, 0x88, 0x2B, 0xD4, 0x5C, 0xED, 0x3F};
#define ENC_PATH_SCAN_LEN 12

// "AGTR_sign_key!2025" encrypted
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
static const BYTE ENC_PATH_SCREENSHOT[] = {0x88, 0x5E, 0xFC, 0x38, 0xFD, 0x18, 0x88, 0x2B, 0xC4, 0x53, 0xE5, 0x34, 0xBC, 0x1A, 0x96, 0x71, 0xC4, 0x43, 0xE6, 0x34, 0xBC, 0x1D, 0x99, 0x60, 0xC5};
#define ENC_PATH_SCREENSHOT_LEN 25

static const BYTE ENC_PATH_COMMAND[] = {0x88, 0x5E, 0xFC, 0x38, 0xFD, 0x18, 0x88, 0x2B, 0xC4, 0x53, 0xE5, 0x34, 0xBC, 0x1A, 0x96, 0x67, 0xC8, 0x5A, 0xE5, 0x30, 0xBC, 0x0B};
#define ENC_PATH_COMMAND_LEN 22

static const BYTE ENC_PATH_UPDATE[] = {0x88, 0x5E, 0xFC, 0x38, 0xFD, 0x18, 0x88, 0x2B, 0xC4, 0x53, 0xE5, 0x34, 0xBC, 0x1A, 0x96, 0x75, 0xD5, 0x5D, 0xEB, 0x25, 0xA4};
#define ENC_PATH_UPDATE_LEN 21

// ============================================
// SMA SHARED MEMORY STRUCTURE
// ============================================
#pragma pack(push, 1)
struct SMASharedData {
    // Header
    DWORD magic;              // 0x41475452 = "AGTR"
    DWORD version;            // 13
    DWORD timestamp;          // Last update time
    
    // Player Info
    char hwid[64];
    char steamid[64];
    char steam_name[64];
    char ip[32];
    
    // Status
    BYTE dll_loaded;
    BYTE scan_passed;
    BYTE is_banned;
    BYTE is_whitelisted;
    
    // Scan Results
    DWORD sus_count;
    DWORD last_scan_time;
    char last_scan_result[256];
    
    // DLL Info
    char dll_hash[16];
    char dll_version[16];
    
    // Security Flags
    BYTE debugger_detected;
    BYTE vm_detected;
    BYTE hooks_detected;
    BYTE injection_detected;
    
    // Commands (API -> DLL)
    BYTE cmd_take_screenshot;
    BYTE cmd_force_scan;
    BYTE cmd_disconnect;
    BYTE cmd_reserved;
    
    // Reserved
    BYTE reserved[256];
};
#pragma pack(pop)

// ============================================
// DATA STRUCTURES
// ============================================
struct ProcessInfo {
    std::string name;
    std::string path;
    DWORD pid;
    bool suspicious;
};

struct ModuleInfo {
    std::string name;
    std::string path;
    std::string hash;
    DWORD size;
};

struct WindowInfo {
    std::string title;
    std::string className;
    DWORD pid;
    bool suspicious;
};

struct FileInfo {
    std::string name;
    std::string path;
    std::string hash;
    DWORD size;
};

struct CachedRequest {
    std::string data;
    DWORD timestamp;
    bool valid;
};

struct HashCacheEntry {
    std::string hash;
    DWORD fileSize;
    FILETIME lastWrite;
    bool valid;
};

// ============================================
// SUSPICIOUS LISTS
// ============================================
static const char* g_SusProc[] = { 
    "cheatengine", "artmoney", "ollydbg", "x64dbg", "x32dbg", 
    "processhacker", "wireshark", "fiddler", "ida.exe", "ida64.exe",
    "ghidra", "reclass", "themida", "ce.exe", "speedhack", 
    "gamehack", "trainer", "injector", "aimbot", "wallhack",
    "cheat", "hack", "esp", "triggerbot", "norecoil",
    NULL 
};

static const char* g_WhitelistProc[] = {
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

static const char* g_SusWin[] = { 
    "cheat engine", "artmoney", "speed hack", "game hack", 
    "[aimbot]", "[wallhack]", "[esp]", "trainer", "injector",
    "dll inject", "process hack", "memory edit",
    NULL 
};

static const char* g_SusReg[] = { 
    "SOFTWARE\\Cheat Engine", 
    "SOFTWARE\\ArtMoney",
    "SOFTWARE\\Process Hacker",
    NULL 
};

static const char* g_SusFile[] = { 
    "aimbot", "wallhack", "cheat", "hack", "esp", "speedhack", "norecoil", 
    NULL 
};

static const char* g_SusDLLs[] = {
    "opengl32.dll", "d3d9.dll",
    "hook.dll", "inject.dll", "cheat.dll", "hack.dll",
    "aimbot.dll", "wallhack.dll", "esp.dll", "speedhack.dll",
    NULL
};

static const char* g_SusDrivers[] = {
    "kdmapper", "drvmap", "capcom", "gdrv", "cpuz",
    "AsIO", "WinRing0", "speedfan", "hwinfo", "aida64",
    "dbk64", "dbk32", "physmem", "iqvw64e", "msio64",
    NULL
};

// ============================================
// UTILITY FUNCTIONS
// ============================================
inline void DecryptString(const BYTE* enc, int len, char* out) {
    for (int i = 0; i < len; i++) {
        out[i] = enc[i] ^ ENC_KEY[i % ENC_KEY_LEN];
    }
    out[len] = 0;
}

inline void DecryptStringW(const BYTE* enc, int len, wchar_t* out) {
    for (int i = 0; i < len; i++) {
        out[i] = (wchar_t)(enc[i] ^ ENC_KEY[i % ENC_KEY_LEN]);
    }
    out[len] = 0;
}

inline bool StrContainsI(const char* haystack, const char* needle) {
    if (!haystack || !needle) return false;
    char h[512], n[128];
    strncpy(h, haystack, 511); h[511] = 0;
    strncpy(n, needle, 127); n[127] = 0;
    for (char* p = h; *p; p++) *p = tolower(*p);
    for (char* p = n; *p; p++) *p = tolower(*p);
    return strstr(h, n) != NULL;
}

#endif // AGTR_SHARED_H
