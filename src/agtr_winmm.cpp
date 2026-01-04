/*
 * AGTR Anti-Cheat v12.4 - Security Hardened Edition
 * ============================================
 * 
 * v12.4 Security Features:
 * - HMAC-SHA256 Request Signing
 * - DLL Self-Hash Verification
 * - Anti-Debug Protection
 * - HTTPS Support (optional)
 * - Timestamp-based Replay Protection
 * 
 * BUILD (x86 Developer Command Prompt):
 * cl /O2 /MT /LD agtr_winmm.cpp /link /DEF:winmm.def /OUT:winmm.dll
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <mmsystem.h>
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
#include <ctype.h>
#include <string>
#include <vector>
#include <map>

#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

// ============================================
// VERSION & CONFIG
// ============================================
#define AGTR_VERSION "12.4"  // Security Hardened Edition
#define AGTR_HASH_LENGTH 8

// Adaptive Heartbeat intervals
#define HEARTBEAT_IN_SERVER 30000      // Serverdeyken 30sn
#define HEARTBEAT_IN_MENU 120000       // Menüdeyken 120sn
#define HEARTBEAT_OFFLINE_RETRY 60000  // API offline ise 60sn

// Throttling
#define THROTTLE_MIN_INTERVAL 300000   // Aynı veriyi 5dk'da bir gönder
#define OFFLINE_CACHE_MAX 10           // Max cache'lenecek request

// API Config - Encrypted at compile time, decrypted at runtime
#define API_PORT 5000
#define API_USE_HTTPS false
#define API_TIMEOUT 5000               // 5sn timeout

// Security Config (v12.4)
#define SIGNATURE_ENABLED false  // Kapalı - sadece DLL hash kontrolü
#define ANTI_DEBUG_ENABLED true
#define DLL_HASH_ENABLED true

// Encrypted strings (XOR with rotating key)
// Key: 0xA7, 0x3F, 0x8C, 0x51, 0xD2, 0x6E, 0xB9, 0x04
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

// "AGTR/12.1" encrypted (User-Agent)
static const BYTE ENC_USER_AGENT[] = {0xE6, 0x78, 0xD8, 0x03, 0xFD, 0x5F, 0x8B, 0x2A, 0x96};
#define ENC_USER_AGENT_LEN 9

// "/api/v1/client/connect" encrypted (v12.2 - Hızlı bağlantı bildirimi)
static const BYTE ENC_PATH_CONNECT[] = {0x88, 0x5E, 0xFC, 0x38, 0xFD, 0x18, 0x88, 0x2B, 0xC4, 0x53, 0xE5, 0x34, 0xBC, 0x1A, 0x96, 0x67, 0xC8, 0x51, 0xE2, 0x34, 0xB1, 0x1A};
#define ENC_PATH_CONNECT_LEN 22

// Decrypt function - decrypts in place to avoid string literals in memory
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

// Runtime decrypted values (filled on first use)
static wchar_t g_szAPIHost[32] = {0};
static wchar_t g_szPathScan[64] = {0};
static wchar_t g_szPathRegister[64] = {0};
static wchar_t g_szPathHeartbeat[64] = {0};
static wchar_t g_szPathConnect[64] = {0};  // v12.2
static wchar_t g_szUserAgent[32] = {0};
static bool g_bStringsDecrypted = false;

static void EnsureStringsDecrypted() {
    if (g_bStringsDecrypted) return;
    DecryptStringW(ENC_API_HOST, ENC_API_HOST_LEN, g_szAPIHost);
    DecryptStringW(ENC_PATH_SCAN, ENC_PATH_SCAN_LEN, g_szPathScan);
    DecryptStringW(ENC_PATH_REGISTER, ENC_PATH_REGISTER_LEN, g_szPathRegister);
    DecryptStringW(ENC_PATH_HEARTBEAT, ENC_PATH_HEARTBEAT_LEN, g_szPathHeartbeat);
    DecryptStringW(ENC_PATH_CONNECT, ENC_PATH_CONNECT_LEN, g_szPathConnect);  // v12.2
    DecryptStringW(ENC_USER_AGENT, ENC_USER_AGENT_LEN, g_szUserAgent);
    DecryptString(ENC_SIG_KEY, ENC_SIG_KEY_LEN, g_szSignatureKey);  // v12.4
    g_bStringsDecrypted = true;
}

// ============================================
// v12.4 SECURITY FUNCTIONS
// ============================================

// SHA256 using Windows CryptoAPI
static bool SHA256Hash(const BYTE* data, DWORD dataLen, char* outHex) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];
    DWORD hashLen = 32;
    bool success = false;
    
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

// HMAC-SHA256 for request signing
static bool HMAC_SHA256(const char* key, const char* data, char* outHex) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    BYTE hash[32];
    DWORD hashLen = 32;
    bool success = false;
    
    // HMAC key structure
    struct {
        BLOBHEADER hdr;
        DWORD keySize;
        BYTE key[64];
    } keyBlob;
    
    DWORD keyLen = (DWORD)strlen(key);
    if (keyLen > 64) keyLen = 64;
    
    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_RC2;
    keyBlob.keySize = keyLen;
    memcpy(keyBlob.key, key, keyLen);
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        HMAC_INFO hmacInfo = {0};
        hmacInfo.HashAlgid = CALG_SHA_256;
        
        if (CryptCreateHash(hProv, CALG_HMAC, 0, 0, &hHash)) {
            // Import key for HMAC
            if (CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob.hdr) + sizeof(DWORD) + keyLen, 0, CRYPT_IPSEC_HMAC_KEY, &hKey)) {
                CryptDestroyHash(hHash);
                if (CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash)) {
                    if (CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0)) {
                        if (CryptHashData(hHash, (BYTE*)data, (DWORD)strlen(data), 0)) {
                            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                                for (DWORD i = 0; i < hashLen; i++) {
                                    sprintf(outHex + (i * 2), "%02x", hash[i]);
                                }
                                outHex[64] = 0;
                                success = true;
                            }
                        }
                    }
                }
                CryptDestroyKey(hKey);
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    
    // Fallback: Simple hash if HMAC fails
    if (!success) {
        // Basit XOR + SHA256 fallback
        char combined[4096];
        snprintf(combined, sizeof(combined), "%s:%s", key, data);
        success = SHA256Hash((BYTE*)combined, (DWORD)strlen(combined), outHex);
    }
    
    return success;
}

// Calculate DLL self hash and get filename
static void CalculateSelfHash() {
    char dllPath[MAX_PATH];
    HMODULE hSelf = NULL;
    
    // Get our own module handle
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)CalculateSelfHash, &hSelf);
    
    if (GetModuleFileNameA(hSelf, dllPath, MAX_PATH)) {
        // Extract filename from path
        char* lastSlash = strrchr(dllPath, '\\');
        if (lastSlash) {
            strcpy(g_szSelfName, lastSlash + 1);
        } else {
            strcpy(g_szSelfName, dllPath);
        }
        // Convert to lowercase
        for (char* p = g_szSelfName; *p; p++) {
            *p = tolower(*p);
        }
        
        HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize > 0 && fileSize < 10 * 1024 * 1024) {  // Max 10MB
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
    
    if (g_szSelfHash[0] == 0) {
        strcpy(g_szSelfHash, "unknown");
    }
    if (g_szSelfName[0] == 0) {
        strcpy(g_szSelfName, "winmm.dll");  // Default
    }
}

// Anti-debug checks
static bool CheckDebugger() {
    if (!ANTI_DEBUG_ENABLED) return false;
    
    // Check 1: IsDebuggerPresent
    if (IsDebuggerPresent()) {
        return true;
    }
    
    // Check 2: CheckRemoteDebuggerPresent
    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
        return true;
    }
    
    // Check 3: PEB NtGlobalFlag
    DWORD ntGlobalFlag = 0;
    __try {
        #ifdef _WIN64
        ntGlobalFlag = *(DWORD*)((BYTE*)__readgsqword(0x60) + 0xBC);
        #else
        ntGlobalFlag = *(DWORD*)((BYTE*)__readfsdword(0x30) + 0x68);
        #endif
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    
    if (ntGlobalFlag & 0x70) {  // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
        return true;
    }
    
    // Check 4: Timing check (debugger slows execution)
    DWORD start = GetTickCount();
    for (volatile int i = 0; i < 100000; i++) {}
    DWORD elapsed = GetTickCount() - start;
    if (elapsed > 500) {  // Normal < 50ms, debugger > 500ms (tolerant for slow PCs)
        return true;
    }
    
    // Check 5: Hardware breakpoints
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            return true;
        }
    }
    
    return false;
}

// Generate timestamp for replay protection
static DWORD64 GetTimestamp() {
    return (DWORD64)time(NULL);
}

// Sign a request
static void SignRequest(const char* jsonData, DWORD64 timestamp, char* outSignature) {
    if (!SIGNATURE_ENABLED) {
        outSignature[0] = 0;
        return;
    }
    
    EnsureStringsDecrypted();
    
    char dataToSign[8192];
    snprintf(dataToSign, sizeof(dataToSign), "%llu:%s", timestamp, jsonData);
    
    HMAC_SHA256(g_szSignatureKey, dataToSign, outSignature);
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

// v12.2 - Yeni özellikler
static char g_szSteamID[64] = {0};           // Oyuncunun SteamID'si
static char g_szSteamName[64] = {0};         // Steam kullanıcı adı
static char g_szAuthToken[128] = {0};        // Sunucu tarafından verilen token
static char g_szLastConnectedIP[64] = {0};   // Önceki bağlantı (değişim tespiti için)
static int g_iLastConnectedPort = 0;
static DWORD g_dwConnectionStart = 0;        // Sunucuya bağlanma zamanı
static bool g_bConnectionNotified = false;   // Hızlı bildirim gönderildi mi?
static bool g_bSteamIDResolved = false;      // SteamID çözüldü mü?

// Optimization states
static bool g_bAPIOnline = true;           // API erişilebilir mi?
static DWORD g_dwLastSuccessfulSend = 0;   // Son başarılı gönderim
static DWORD g_dwLastDataHash = 0;         // Throttling için veri hash'i
static int g_iFailedRequests = 0;          // Ardışık başarısız request sayısı
static bool g_bFirstScanDone = false;      // İlk scan yapıldı mı?

// Offline cache
struct CachedRequest {
    std::string data;
    DWORD timestamp;
    bool valid;
};
static CachedRequest g_OfflineCache[OFFLINE_CACHE_MAX];
static int g_iCacheCount = 0;

// Hash cache - dosya değişmediyse tekrar hash'leme
struct HashCacheEntry {
    std::string hash;
    DWORD fileSize;
    FILETIME lastWrite;
    bool valid;
};
static std::map<std::string, HashCacheEntry> g_HashCache;

// ============================================
// OBFUSCATED KEY
// ============================================
#define OBF_XOR 0x5A
static const unsigned char OBF_KEY[] = {0x1B,0x3D,0x2E,0x28,0x6F,0x6A,0x6F,0x75,0x29,0x3F,0x39,0x28,0x3F,0x2E};
#define OBF_KEY_LEN 14
static void Deobf(const unsigned char* s, int len, char* d) { for(int i=0;i<len;i++) d[i]=s[i]^OBF_XOR; d[len]=0; }

// ============================================
// GLOBALS
// ============================================
static HMODULE g_hOriginal = NULL;
static HANDLE g_hThread = NULL;
static bool g_bRunning = true;
static bool g_bThreadStarted = false;
static CRITICAL_SECTION g_csLog;

static char g_szHWID[64] = {0};
static char g_szDLLHash[64] = {0};
static char g_szGameDir[MAX_PATH] = {0};
static char g_szValveDir[MAX_PATH] = {0};

// v12.4 Security
static char g_szSelfHash[65] = {0};       // DLL'in kendi SHA256 hash'i
static char g_szSelfName[64] = {0};       // DLL'in kendi dosya adı (winmm.dll, dinput8.dll, dsound.dll)
static char g_szSignatureKey[64] = {0};   // Decrypted signature key
static char g_szServerIP[64] = "unknown";
static int g_iServerPort = 0;

static bool g_bPassed = true;
static int g_iSusCount = 0;
static int g_iRegistrySus = 0;
static FILE* g_LogFile = NULL;

// Security detection results
static bool g_bDebuggerDetected = false;
static bool g_bVMDetected = false;
static bool g_bHooksDetected = false;
static bool g_bDriversDetected = false;
static bool g_bIntegrityOK = true;
static char g_szOwnHash[64] = {0};  // DLL'in kendi hash'i (eski, deprecated)

// ============================================
// PERFORMANCE OPTIMIZATION SYSTEM (v12.1)
// ============================================

// Forward declarations
std::string HttpRequest(const wchar_t* path, const std::string& body, const std::string& method = "POST", bool canCache = false);

// #7 Delta Process Scan - Önceki process listesi
static std::map<DWORD, std::string> g_LastProcesses;
static std::map<std::string, DWORD> g_LastModules;
static bool g_bDeltaScanEnabled = true;

// #3 Menu-Only Deep Scan
static bool g_bDeepScanPending = false;
static DWORD g_dwLastDeepScan = 0;
#define DEEP_SCAN_INTERVAL 300000  // 5 dakikada bir deep scan

// #26 FPS Monitor
static float g_fCurrentFPS = 999.0f;
static DWORD g_dwLastFrameTime = 0;
static int g_iFrameCount = 0;
static DWORD g_dwFPSCheckTime = 0;
#define MIN_FPS_FOR_SCAN 40.0f     // Bu FPS'in altındayken scan yapma
#define FPS_CHECK_INTERVAL 1000    // Her saniye FPS kontrol

// #19 Smart Throttling
enum ScanIntensity {
    SCAN_INTENSITY_NONE = 0,    // Scan yapma
    SCAN_INTENSITY_LIGHT = 1,   // Sadece signature check
    SCAN_INTENSITY_NORMAL = 2,  // Normal scan
    SCAN_INTENSITY_DEEP = 3     // Tam scan (tüm dosyalar, registry vs)
};
static ScanIntensity g_CurrentIntensity = SCAN_INTENSITY_NORMAL;

// #13 Micro-Batch Operations
static int g_iBatchIndex = 0;
static int g_iProcessBatchPos = 0;
static int g_iModuleBatchPos = 0;
#define BATCH_SIZE_PROCESS 5       // Her tick'te max 5 process tara
#define BATCH_SIZE_MODULE 3        // Her tick'te max 3 modül tara

// #15 Deferred Reporting
struct DeferredResult {
    std::string type;
    std::string name;
    bool suspicious;
    DWORD timestamp;
};
static std::vector<DeferredResult> g_DeferredResults;
static DWORD g_dwLastReportTime = 0;
#define DEFERRED_REPORT_INTERVAL 30000  // 30 saniyede bir rapor gönder

// #28 Game State Awareness
enum GameState {
    STATE_MENU = 0,
    STATE_LOADING = 1,
    STATE_PLAYING = 2,
    STATE_DEAD = 3,
    STATE_SPECTATING = 4
};
static GameState g_CurrentGameState = STATE_MENU;
static bool g_bPlayerAlive = true;
static DWORD g_dwLastDamageTime = 0;
static DWORD g_dwLastShotTime = 0;

// #22 Signature-First Check - Hızlı imza listesi
struct QuickSignature {
    const char* pattern;
    const char* name;
    int severity;  // 1=low, 2=medium, 3=high, 4=critical
};
static QuickSignature g_QuickSigs[] = {
    {"cheatengine", "Cheat Engine", 4},
    {"ce.exe", "Cheat Engine", 4},
    {"artmoney", "ArtMoney", 4},
    {"speedhack", "SpeedHack", 4},
    {"aimbot", "Aimbot", 4},
    {"wallhack", "Wallhack", 4},
    {"x64dbg", "Debugger", 3},
    {"ollydbg", "Debugger", 3},
    {"ida.exe", "Disassembler", 3},
    {"injector", "DLL Injector", 3},
    {NULL, NULL, 0}
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
    std::string shortHash;
    std::string fullHash;
    DWORD size;
    DWORD modTime;
};
static std::map<std::string, FileHashInfo> g_FileCache;

// ============================================
// SUSPICIOUS LISTS
// ============================================
const char* g_SusProc[] = { 
    "cheatengine", "artmoney", "ollydbg", "x64dbg", "x32dbg", 
    "processhacker", "wireshark", "fiddler", "ida.exe", "ida64.exe",
    "ghidra", "reclass", "themida", "ce.exe", "speedhack", 
    "gamehack", "trainer", "injector", "aimbot", "wallhack",
    NULL 
};

const char* g_WhitelistProc[] = {
    "svchost.exe", "csrss.exe", "smss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "explorer.exe", "dwm.exe", "taskhostw.exe",
    "searchindexer", "searchhost", "runtimebroker", "sihost.exe", "fontdrvhost",
    "ctfmon.exe", "conhost.exe", "dllhost.exe", "audiodg.exe", "spoolsv.exe",
    "msmpeng.exe", "mpcmdrun.exe", "mpdefendercoreservice", "securityhealthservice",
    "smartscreen.exe", "sgrmbroker.exe",
    "steam.exe", "steamservice.exe", "steamwebhelper", "epicgameslauncher",
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
    NULL
};

// Macro/automation tools
const char* g_MacroProc[] = {
    "autohotkey", "ahk", "autoit", "au3", "macro",
    "tinytask", "pulover", "jitbit", "razer synapse",
    "logitech", "lghub", "corsair", "icue",
    NULL
};

// ============================================
// ORIGINAL WINMM FUNCTIONS
// ============================================
typedef DWORD (WINAPI *pfnTimeGetTime)(void);
typedef MMRESULT (WINAPI *pfnTimeBeginPeriod)(UINT);
typedef MMRESULT (WINAPI *pfnTimeEndPeriod)(UINT);
typedef MMRESULT (WINAPI *pfnTimeGetDevCaps)(LPTIMECAPS, UINT);
typedef MMRESULT (WINAPI *pfnTimeGetSystemTime)(LPMMTIME, UINT);
typedef MMRESULT (WINAPI *pfnTimeSetEvent)(UINT, UINT, LPTIMECALLBACK, DWORD_PTR, UINT);
typedef MMRESULT (WINAPI *pfnTimeKillEvent)(UINT);
typedef MMRESULT (WINAPI *pfnWaveOutOpen)(LPHWAVEOUT, UINT, LPCWAVEFORMATEX, DWORD_PTR, DWORD_PTR, DWORD);
typedef MMRESULT (WINAPI *pfnWaveOutClose)(HWAVEOUT);
typedef MMRESULT (WINAPI *pfnWaveOutWrite)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutPrepareHeader)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutUnprepareHeader)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutReset)(HWAVEOUT);
typedef MMRESULT (WINAPI *pfnWaveOutPause)(HWAVEOUT);
typedef MMRESULT (WINAPI *pfnWaveOutRestart)(HWAVEOUT);
typedef MMRESULT (WINAPI *pfnWaveOutGetPosition)(HWAVEOUT, LPMMTIME, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutGetDevCapsA)(UINT, LPWAVEOUTCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutGetDevCapsW)(UINT, LPWAVEOUTCAPSW, UINT);
typedef UINT (WINAPI *pfnWaveOutGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnWaveOutGetVolume)(HWAVEOUT, LPDWORD);
typedef MMRESULT (WINAPI *pfnWaveOutSetVolume)(HWAVEOUT, DWORD);
typedef MMRESULT (WINAPI *pfnWaveOutGetErrorTextA)(MMRESULT, LPSTR, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutGetErrorTextW)(MMRESULT, LPWSTR, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutGetID)(HWAVEOUT, LPUINT);
typedef MMRESULT (WINAPI *pfnWaveOutMessage)(HWAVEOUT, UINT, DWORD_PTR, DWORD_PTR);
typedef MMRESULT (WINAPI *pfnWaveOutBreakLoop)(HWAVEOUT);
typedef MMRESULT (WINAPI *pfnWaveInOpen)(LPHWAVEIN, UINT, LPCWAVEFORMATEX, DWORD_PTR, DWORD_PTR, DWORD);
typedef MMRESULT (WINAPI *pfnWaveInClose)(HWAVEIN);
typedef UINT (WINAPI *pfnWaveInGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnWaveInGetDevCapsA)(UINT, LPWAVEINCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnWaveInGetDevCapsW)(UINT, LPWAVEINCAPSW, UINT);
typedef MMRESULT (WINAPI *pfnWaveInStart)(HWAVEIN);
typedef MMRESULT (WINAPI *pfnWaveInStop)(HWAVEIN);
typedef MMRESULT (WINAPI *pfnWaveInReset)(HWAVEIN);
typedef MMRESULT (WINAPI *pfnWaveInPrepareHeader)(HWAVEIN, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *pfnWaveInUnprepareHeader)(HWAVEIN, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *pfnWaveInAddBuffer)(HWAVEIN, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *pfnWaveInGetPosition)(HWAVEIN, LPMMTIME, UINT);
typedef MMRESULT (WINAPI *pfnWaveInGetID)(HWAVEIN, LPUINT);
typedef MMRESULT (WINAPI *pfnWaveInGetErrorTextA)(MMRESULT, LPSTR, UINT);
typedef MMRESULT (WINAPI *pfnWaveInGetErrorTextW)(MMRESULT, LPWSTR, UINT);
typedef MMRESULT (WINAPI *pfnWaveInMessage)(HWAVEIN, UINT, DWORD_PTR, DWORD_PTR);
typedef BOOL (WINAPI *pfnPlaySoundA)(LPCSTR, HMODULE, DWORD);
typedef BOOL (WINAPI *pfnPlaySoundW)(LPCWSTR, HMODULE, DWORD);
typedef BOOL (WINAPI *pfnSndPlaySoundA)(LPCSTR, UINT);
typedef BOOL (WINAPI *pfnSndPlaySoundW)(LPCWSTR, UINT);
typedef UINT (WINAPI *pfnMidiOutGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnMidiOutGetDevCapsA)(UINT, LPMIDIOUTCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnMidiOutGetDevCapsW)(UINT, LPMIDIOUTCAPSW, UINT);
typedef MMRESULT (WINAPI *pfnMidiOutOpen)(LPHMIDIOUT, UINT, DWORD_PTR, DWORD_PTR, DWORD);
typedef MMRESULT (WINAPI *pfnMidiOutClose)(HMIDIOUT);
typedef MMRESULT (WINAPI *pfnMidiOutShortMsg)(HMIDIOUT, DWORD);
typedef MMRESULT (WINAPI *pfnMidiOutLongMsg)(HMIDIOUT, LPMIDIHDR, UINT);
typedef MMRESULT (WINAPI *pfnMidiOutReset)(HMIDIOUT);
typedef MMRESULT (WINAPI *pfnMidiOutPrepareHeader)(HMIDIOUT, LPMIDIHDR, UINT);
typedef MMRESULT (WINAPI *pfnMidiOutUnprepareHeader)(HMIDIOUT, LPMIDIHDR, UINT);
typedef UINT (WINAPI *pfnJoyGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnJoyGetDevCapsA)(UINT, LPJOYCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnJoyGetDevCapsW)(UINT, LPJOYCAPSW, UINT);
typedef MMRESULT (WINAPI *pfnJoyGetPos)(UINT, LPJOYINFO);
typedef MMRESULT (WINAPI *pfnJoyGetPosEx)(UINT, LPJOYINFOEX);
typedef MMRESULT (WINAPI *pfnJoyGetThreshold)(UINT, LPUINT);
typedef MMRESULT (WINAPI *pfnJoySetThreshold)(UINT, UINT);
typedef MMRESULT (WINAPI *pfnJoySetCapture)(HWND, UINT, UINT, BOOL);
typedef MMRESULT (WINAPI *pfnJoyReleaseCapture)(UINT);
typedef UINT (WINAPI *pfnAuxGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnAuxGetDevCapsA)(UINT, LPAUXCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnAuxGetDevCapsW)(UINT, LPAUXCAPSW, UINT);
typedef MMRESULT (WINAPI *pfnAuxGetVolume)(UINT, LPDWORD);
typedef MMRESULT (WINAPI *pfnAuxSetVolume)(UINT, DWORD);
typedef MMRESULT (WINAPI *pfnAuxOutMessage)(UINT, UINT, DWORD_PTR, DWORD_PTR);
typedef UINT (WINAPI *pfnMixerGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnMixerOpen)(LPHMIXER, UINT, DWORD_PTR, DWORD_PTR, DWORD);
typedef MMRESULT (WINAPI *pfnMixerClose)(HMIXER);
typedef MMRESULT (WINAPI *pfnMixerGetDevCapsA)(UINT, LPMIXERCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnMixerGetDevCapsW)(UINT, LPMIXERCAPSW, UINT);
typedef MMRESULT (WINAPI *pfnMixerGetLineInfoA)(HMIXEROBJ, LPMIXERLINEA, DWORD);
typedef MMRESULT (WINAPI *pfnMixerGetLineInfoW)(HMIXEROBJ, LPMIXERLINEW, DWORD);
typedef MMRESULT (WINAPI *pfnMixerGetLineControlsA)(HMIXEROBJ, LPMIXERLINECONTROLSA, DWORD);
typedef MMRESULT (WINAPI *pfnMixerGetLineControlsW)(HMIXEROBJ, LPMIXERLINECONTROLSW, DWORD);
typedef MMRESULT (WINAPI *pfnMixerGetControlDetailsA)(HMIXEROBJ, LPMIXERCONTROLDETAILS, DWORD);
typedef MMRESULT (WINAPI *pfnMixerGetControlDetailsW)(HMIXEROBJ, LPMIXERCONTROLDETAILS, DWORD);
typedef MMRESULT (WINAPI *pfnMixerSetControlDetails)(HMIXEROBJ, LPMIXERCONTROLDETAILS, DWORD);
typedef MMRESULT (WINAPI *pfnMixerGetID)(HMIXEROBJ, PUINT, DWORD);
typedef DWORD (WINAPI *pfnMixerMessage)(HMIXER, UINT, DWORD_PTR, DWORD_PTR);
typedef MCIERROR (WINAPI *pfnMciSendCommandA)(MCIDEVICEID, UINT, DWORD_PTR, DWORD_PTR);
typedef MCIERROR (WINAPI *pfnMciSendCommandW)(MCIDEVICEID, UINT, DWORD_PTR, DWORD_PTR);
typedef MCIERROR (WINAPI *pfnMciSendStringA)(LPCSTR, LPSTR, UINT, HWND);
typedef MCIERROR (WINAPI *pfnMciSendStringW)(LPCWSTR, LPWSTR, UINT, HWND);
typedef BOOL (WINAPI *pfnMciGetErrorStringA)(MCIERROR, LPSTR, UINT);
typedef BOOL (WINAPI *pfnMciGetErrorStringW)(MCIERROR, LPWSTR, UINT);
typedef MCIDEVICEID (WINAPI *pfnMciGetDeviceIDA)(LPCSTR);
typedef MCIDEVICEID (WINAPI *pfnMciGetDeviceIDW)(LPCWSTR);
typedef MCIDEVICEID (WINAPI *pfnMciGetDeviceIDFromElementIDA)(DWORD, LPCSTR);
typedef MCIDEVICEID (WINAPI *pfnMciGetDeviceIDFromElementIDW)(DWORD, LPCWSTR);
typedef BOOL (WINAPI *pfnMciSetYieldProc)(MCIDEVICEID, YIELDPROC, DWORD);
typedef YIELDPROC (WINAPI *pfnMciGetYieldProc)(MCIDEVICEID, LPDWORD);
typedef HTASK (WINAPI *pfnMciGetCreatorTask)(MCIDEVICEID);
typedef BOOL (WINAPI *pfnMciExecute)(LPCSTR);
typedef HMMIO (WINAPI *pfnMmioOpenA)(LPSTR, LPMMIOINFO, DWORD);
typedef HMMIO (WINAPI *pfnMmioOpenW)(LPWSTR, LPMMIOINFO, DWORD);
typedef MMRESULT (WINAPI *pfnMmioClose)(HMMIO, UINT);
typedef LONG (WINAPI *pfnMmioRead)(HMMIO, HPSTR, LONG);
typedef LONG (WINAPI *pfnMmioWrite)(HMMIO, const char*, LONG);
typedef LONG (WINAPI *pfnMmioSeek)(HMMIO, LONG, int);
typedef MMRESULT (WINAPI *pfnMmioGetInfo)(HMMIO, LPMMIOINFO, UINT);
typedef MMRESULT (WINAPI *pfnMmioSetInfo)(HMMIO, LPCMMIOINFO, UINT);
typedef MMRESULT (WINAPI *pfnMmioSetBuffer)(HMMIO, LPSTR, LONG, UINT);
typedef MMRESULT (WINAPI *pfnMmioFlush)(HMMIO, UINT);
typedef MMRESULT (WINAPI *pfnMmioAdvance)(HMMIO, LPMMIOINFO, UINT);
typedef LPMMIOPROC (WINAPI *pfnMmioInstallIOProcA)(FOURCC, LPMMIOPROC, DWORD);
typedef LPMMIOPROC (WINAPI *pfnMmioInstallIOProcW)(FOURCC, LPMMIOPROC, DWORD);
typedef FOURCC (WINAPI *pfnMmioStringToFOURCCA)(LPCSTR, UINT);
typedef FOURCC (WINAPI *pfnMmioStringToFOURCCW)(LPCWSTR, UINT);
typedef MMRESULT (WINAPI *pfnMmioDescend)(HMMIO, LPMMCKINFO, const MMCKINFO*, UINT);
typedef MMRESULT (WINAPI *pfnMmioAscend)(HMMIO, LPMMCKINFO, UINT);
typedef MMRESULT (WINAPI *pfnMmioCreateChunk)(HMMIO, LPMMCKINFO, UINT);
typedef MMRESULT (WINAPI *pfnMmioRename)(LPCSTR, LPCSTR, LPCMMIOINFO, DWORD);
typedef LRESULT (WINAPI *pfnMmioSendMessage)(HMMIO, UINT, LPARAM, LPARAM);

// Function pointers
static pfnTimeGetTime o_TimeGetTime = NULL;
static pfnTimeBeginPeriod o_TimeBeginPeriod = NULL;
static pfnTimeEndPeriod o_TimeEndPeriod = NULL;
static pfnTimeGetDevCaps o_TimeGetDevCaps = NULL;
static pfnTimeGetSystemTime o_TimeGetSystemTime = NULL;
static pfnTimeSetEvent o_TimeSetEvent = NULL;
static pfnTimeKillEvent o_TimeKillEvent = NULL;
static pfnWaveOutOpen o_WaveOutOpen = NULL;
static pfnWaveOutClose o_WaveOutClose = NULL;
static pfnWaveOutWrite o_WaveOutWrite = NULL;
static pfnWaveOutPrepareHeader o_WaveOutPrepareHeader = NULL;
static pfnWaveOutUnprepareHeader o_WaveOutUnprepareHeader = NULL;
static pfnWaveOutReset o_WaveOutReset = NULL;
static pfnWaveOutPause o_WaveOutPause = NULL;
static pfnWaveOutRestart o_WaveOutRestart = NULL;
static pfnWaveOutGetPosition o_WaveOutGetPosition = NULL;
static pfnWaveOutGetDevCapsA o_WaveOutGetDevCapsA = NULL;
static pfnWaveOutGetDevCapsW o_WaveOutGetDevCapsW = NULL;
static pfnWaveOutGetNumDevs o_WaveOutGetNumDevs = NULL;
static pfnWaveOutGetVolume o_WaveOutGetVolume = NULL;
static pfnWaveOutSetVolume o_WaveOutSetVolume = NULL;
static pfnWaveOutGetErrorTextA o_WaveOutGetErrorTextA = NULL;
static pfnWaveOutGetErrorTextW o_WaveOutGetErrorTextW = NULL;
static pfnWaveOutGetID o_WaveOutGetID = NULL;
static pfnWaveOutMessage o_WaveOutMessage = NULL;
static pfnWaveOutBreakLoop o_WaveOutBreakLoop = NULL;
static pfnWaveInOpen o_WaveInOpen = NULL;
static pfnWaveInClose o_WaveInClose = NULL;
static pfnWaveInGetNumDevs o_WaveInGetNumDevs = NULL;
static pfnWaveInGetDevCapsA o_WaveInGetDevCapsA = NULL;
static pfnWaveInGetDevCapsW o_WaveInGetDevCapsW = NULL;
static pfnWaveInStart o_WaveInStart = NULL;
static pfnWaveInStop o_WaveInStop = NULL;
static pfnWaveInReset o_WaveInReset = NULL;
static pfnWaveInPrepareHeader o_WaveInPrepareHeader = NULL;
static pfnWaveInUnprepareHeader o_WaveInUnprepareHeader = NULL;
static pfnWaveInAddBuffer o_WaveInAddBuffer = NULL;
static pfnWaveInGetPosition o_WaveInGetPosition = NULL;
static pfnWaveInGetID o_WaveInGetID = NULL;
static pfnWaveInGetErrorTextA o_WaveInGetErrorTextA = NULL;
static pfnWaveInGetErrorTextW o_WaveInGetErrorTextW = NULL;
static pfnWaveInMessage o_WaveInMessage = NULL;
static pfnPlaySoundA o_PlaySoundA = NULL;
static pfnPlaySoundW o_PlaySoundW = NULL;
static pfnSndPlaySoundA o_SndPlaySoundA = NULL;
static pfnSndPlaySoundW o_SndPlaySoundW = NULL;
static pfnMidiOutGetNumDevs o_MidiOutGetNumDevs = NULL;
static pfnMidiOutGetDevCapsA o_MidiOutGetDevCapsA = NULL;
static pfnMidiOutGetDevCapsW o_MidiOutGetDevCapsW = NULL;
static pfnMidiOutOpen o_MidiOutOpen = NULL;
static pfnMidiOutClose o_MidiOutClose = NULL;
static pfnMidiOutShortMsg o_MidiOutShortMsg = NULL;
static pfnMidiOutLongMsg o_MidiOutLongMsg = NULL;
static pfnMidiOutReset o_MidiOutReset = NULL;
static pfnMidiOutPrepareHeader o_MidiOutPrepareHeader = NULL;
static pfnMidiOutUnprepareHeader o_MidiOutUnprepareHeader = NULL;
static pfnJoyGetNumDevs o_JoyGetNumDevs = NULL;
static pfnJoyGetDevCapsA o_JoyGetDevCapsA = NULL;
static pfnJoyGetDevCapsW o_JoyGetDevCapsW = NULL;
static pfnJoyGetPos o_JoyGetPos = NULL;
static pfnJoyGetPosEx o_JoyGetPosEx = NULL;
static pfnJoyGetThreshold o_JoyGetThreshold = NULL;
static pfnJoySetThreshold o_JoySetThreshold = NULL;
static pfnJoySetCapture o_JoySetCapture = NULL;
static pfnJoyReleaseCapture o_JoyReleaseCapture = NULL;
static pfnAuxGetNumDevs o_AuxGetNumDevs = NULL;
static pfnAuxGetDevCapsA o_AuxGetDevCapsA = NULL;
static pfnAuxGetDevCapsW o_AuxGetDevCapsW = NULL;
static pfnAuxGetVolume o_AuxGetVolume = NULL;
static pfnAuxSetVolume o_AuxSetVolume = NULL;
static pfnAuxOutMessage o_AuxOutMessage = NULL;
static pfnMixerGetNumDevs o_MixerGetNumDevs = NULL;
static pfnMixerOpen o_MixerOpen = NULL;
static pfnMixerClose o_MixerClose = NULL;
static pfnMixerGetDevCapsA o_MixerGetDevCapsA = NULL;
static pfnMixerGetDevCapsW o_MixerGetDevCapsW = NULL;
static pfnMixerGetLineInfoA o_MixerGetLineInfoA = NULL;
static pfnMixerGetLineInfoW o_MixerGetLineInfoW = NULL;
static pfnMixerGetLineControlsA o_MixerGetLineControlsA = NULL;
static pfnMixerGetLineControlsW o_MixerGetLineControlsW = NULL;
static pfnMixerGetControlDetailsA o_MixerGetControlDetailsA = NULL;
static pfnMixerGetControlDetailsW o_MixerGetControlDetailsW = NULL;
static pfnMixerSetControlDetails o_MixerSetControlDetails = NULL;
static pfnMixerGetID o_MixerGetID = NULL;
static pfnMixerMessage o_MixerMessage = NULL;
static pfnMciSendCommandA o_MciSendCommandA = NULL;
static pfnMciSendCommandW o_MciSendCommandW = NULL;
static pfnMciSendStringA o_MciSendStringA = NULL;
static pfnMciSendStringW o_MciSendStringW = NULL;
static pfnMciGetErrorStringA o_MciGetErrorStringA = NULL;
static pfnMciGetErrorStringW o_MciGetErrorStringW = NULL;
static pfnMciGetDeviceIDA o_MciGetDeviceIDA = NULL;
static pfnMciGetDeviceIDW o_MciGetDeviceIDW = NULL;
static pfnMciGetDeviceIDFromElementIDA o_MciGetDeviceIDFromElementIDA = NULL;
static pfnMciGetDeviceIDFromElementIDW o_MciGetDeviceIDFromElementIDW = NULL;
static pfnMciSetYieldProc o_MciSetYieldProc = NULL;
static pfnMciGetYieldProc o_MciGetYieldProc = NULL;
static pfnMciGetCreatorTask o_MciGetCreatorTask = NULL;
static pfnMciExecute o_MciExecute = NULL;
static pfnMmioOpenA o_MmioOpenA = NULL;
static pfnMmioOpenW o_MmioOpenW = NULL;
static pfnMmioClose o_MmioClose = NULL;
static pfnMmioRead o_MmioRead = NULL;
static pfnMmioWrite o_MmioWrite = NULL;
static pfnMmioSeek o_MmioSeek = NULL;
static pfnMmioGetInfo o_MmioGetInfo = NULL;
static pfnMmioSetInfo o_MmioSetInfo = NULL;
static pfnMmioSetBuffer o_MmioSetBuffer = NULL;
static pfnMmioFlush o_MmioFlush = NULL;
static pfnMmioAdvance o_MmioAdvance = NULL;
static pfnMmioInstallIOProcA o_MmioInstallIOProcA = NULL;
static pfnMmioInstallIOProcW o_MmioInstallIOProcW = NULL;
static pfnMmioStringToFOURCCA o_MmioStringToFOURCCA = NULL;
static pfnMmioStringToFOURCCW o_MmioStringToFOURCCW = NULL;
static pfnMmioDescend o_MmioDescend = NULL;
static pfnMmioAscend o_MmioAscend = NULL;
static pfnMmioCreateChunk o_MmioCreateChunk = NULL;
static pfnMmioRename o_MmioRename = NULL;
static pfnMmioSendMessage o_MmioSendMessage = NULL;

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

// ============================================
// SECURITY CHECKS
// ============================================

// #16 - DLL Integrity Check
bool CheckDLLIntegrity() {
    char dllPath[MAX_PATH];
    HMODULE hMod = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&CheckDLLIntegrity, &hMod);
    GetModuleFileNameA(hMod, dllPath, MAX_PATH);
    
    // Hash hesapla
    HANDLE h = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    
    DWORD size = GetFileSize(h, NULL);
    BYTE* buf = (BYTE*)malloc(size);
    if (!buf) { CloseHandle(h); return false; }
    
    DWORD read;
    ReadFile(h, buf, size, &read, NULL);
    CloseHandle(h);
    
    // Simple checksum
    DWORD checksum = 0;
    for (DWORD i = 0; i < read; i++) checksum += buf[i];
    free(buf);
    
    sprintf(g_szOwnHash, "%08X%08X", checksum, size);
    
    // İlk çalıştırmada hash'i kaydet, sonrakilerde karşılaştır
    static char savedHash[64] = {0};
    if (!savedHash[0]) {
        strcpy(savedHash, g_szOwnHash);
        return true;
    }
    
    g_bIntegrityOK = (strcmp(savedHash, g_szOwnHash) == 0);
    if (!g_bIntegrityOK) Log("!!! DLL INTEGRITY FAILED !!!");
    return g_bIntegrityOK;
}

// #17 - Anti-Debug Detection
bool CheckDebugger() {
    g_bDebuggerDetected = false;
    
    // Method 1: IsDebuggerPresent
    if (IsDebuggerPresent()) {
        g_bDebuggerDetected = true;
        return true;
    }
    
    // Method 2: CheckRemoteDebuggerPresent
    BOOL remoteDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
    if (remoteDebugger) {
        g_bDebuggerDetected = true;
        return true;
    }
    
    // Method 3: NtGlobalFlag check (PEB)
    #ifdef _WIN32
    __try {
        DWORD* pPEB = NULL;
        #ifdef _WIN64
        pPEB = (DWORD*)__readgsqword(0x60);
        #else
        __asm {
            mov eax, fs:[0x30]
            mov pPEB, eax
        }
        #endif
        if (pPEB) {
            DWORD ntGlobalFlag = *(DWORD*)((BYTE*)pPEB + 0x68);
            if (ntGlobalFlag & 0x70) { // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
                g_bDebuggerDetected = true;
                return true;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    #endif
    
    // Method 4: Timing check
    DWORD t1 = GetTickCount();
    Sleep(1);
    DWORD t2 = GetTickCount();
    if ((t2 - t1) > 100) { // Debug stepping
        g_bDebuggerDetected = true;
        return true;
    }
    
    return false;
}

// #19 - API Hook Detection
bool CheckAPIHooks() {
    g_bHooksDetected = false;
    
    // Check critical functions for hooks (JMP/CALL at start)
    FARPROC funcs[] = {
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress"),
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc"),
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory"),
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"),
        NULL
    };
    
    for (int i = 0; funcs[i]; i++) {
        BYTE* ptr = (BYTE*)funcs[i];
        if (!ptr) continue;
        
        // Check for JMP (E9, EB, FF 25) or CALL hooks
        if (ptr[0] == 0xE9 || ptr[0] == 0xEB || 
            (ptr[0] == 0xFF && ptr[1] == 0x25) ||
            ptr[0] == 0x68) { // PUSH + RET hook
            g_bHooksDetected = true;
            Log("API Hook detected at %p", ptr);
            return true;
        }
    }
    
    return false;
}

// Helper: memmem implementation (must be before ScanMemoryPatterns)
void* memmem(const void* haystack, size_t haystacklen, const void* needle, size_t needlelen) {
    if (!needlelen) return (void*)haystack;
    if (haystacklen < needlelen) return NULL;
    
    const char* h = (const char*)haystack;
    const char* n = (const char*)needle;
    
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(h + i, n, needlelen) == 0) {
            return (void*)(h + i);
        }
    }
    return NULL;
}

// #20 - Memory Pattern Scan (hl.exe içinde bilinen cheat pattern'leri)
int ScanMemoryPatterns() {
    int found = 0;
    HANDLE hProc = GetCurrentProcess();
    
    // Bilinen cheat signature'ları
    const char* patterns[] = {
        "aimbot_enable",
        "wallhack_on",
        "esp_draw",
        "bhop_auto",
        "norecoil",
        "triggerbot",
        NULL
    };
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;
    
    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            
            // Sadece küçük bölgeleri tara (performans için)
            if (mbi.RegionSize <= 1024 * 1024) { // Max 1MB
                BYTE* buffer = (BYTE*)malloc(mbi.RegionSize);
                if (buffer) {
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) {
                        for (int i = 0; patterns[i]; i++) {
                            if (memmem(buffer, bytesRead, patterns[i], strlen(patterns[i]))) {
                                Log("Memory pattern found: %s", patterns[i]);
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

// #23 - Driver Detection
bool CheckSuspiciousDrivers() {
    g_bDriversDetected = false;
    
    // Service Control Manager'dan driver'ları listele
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return false;
    
    DWORD bytesNeeded = 0, servicesReturned = 0;
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
        SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, NULL, NULL);
    
    if (bytesNeeded > 0) {
        BYTE* buffer = (BYTE*)malloc(bytesNeeded);
        if (buffer) {
            ENUM_SERVICE_STATUS_PROCESSA* services = (ENUM_SERVICE_STATUS_PROCESSA*)buffer;
            if (EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                SERVICE_STATE_ALL, buffer, bytesNeeded, &bytesNeeded, &servicesReturned, NULL, NULL)) {
                
                for (DWORD i = 0; i < servicesReturned; i++) {
                    char nameLower[256];
                    strncpy(nameLower, services[i].lpServiceName, 255);
                    ToLower(nameLower);
                    
                    for (int j = 0; g_SusDrivers[j]; j++) {
                        if (strstr(nameLower, g_SusDrivers[j])) {
                            Log("Suspicious driver: %s", services[i].lpServiceName);
                            g_bDriversDetected = true;
                        }
                    }
                }
            }
            free(buffer);
        }
    }
    
    CloseServiceHandle(scm);
    return g_bDriversDetected;
}

// #24 - VM Detection
bool CheckVirtualMachine() {
    g_bVMDetected = false;
    
    // Method 1: CPUID check
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) { // Hypervisor bit
        g_bVMDetected = true;
    }
    
    // Method 2: Registry check
    HKEY hKey;
    const char* vmKeys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        "SYSTEM\\CurrentControlSet\\Services\\vmci",
        NULL
    };
    
    for (int i = 0; vmKeys[i]; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            g_bVMDetected = true;
            break;
        }
    }
    
    // Method 3: MAC address check (VM prefixes)
    // VMware: 00:0C:29, 00:50:56
    // VirtualBox: 08:00:27
    // Hyper-V: 00:15:5D
    
    if (g_bVMDetected) Log("VM detected");
    return g_bVMDetected;
}

// ============================================
// OPTIMIZATION HELPERS
// ============================================

// #1 - Simple hash for throttling (veri değişti mi kontrolü)
DWORD QuickDataHash(const std::string& data) {
    DWORD hash = 0;
    for (size_t i = 0; i < data.length(); i += 64) {
        hash ^= (DWORD)data[i] << ((i % 4) * 8);
    }
    return hash;
}

// #7 - Throttle check (aynı veriyi tekrar gönderme)
bool ShouldThrottle(const std::string& data) {
    DWORD hash = QuickDataHash(data);
    DWORD now = GetTickCount();
    
    if (hash == g_dwLastDataHash && (now - g_dwLastSuccessfulSend) < THROTTLE_MIN_INTERVAL) {
        Log("Throttled - data unchanged");
        return true;
    }
    return false;
}

// #6 - Offline cache'e ekle
void AddToOfflineCache(const std::string& data) {
    if (g_iCacheCount >= OFFLINE_CACHE_MAX) {
        // En eskiyi sil
        for (int i = 0; i < OFFLINE_CACHE_MAX - 1; i++) {
            g_OfflineCache[i] = g_OfflineCache[i + 1];
        }
        g_iCacheCount = OFFLINE_CACHE_MAX - 1;
    }
    
    g_OfflineCache[g_iCacheCount].data = data;
    g_OfflineCache[g_iCacheCount].timestamp = GetTickCount();
    g_OfflineCache[g_iCacheCount].valid = true;
    g_iCacheCount++;
    
    Log("Added to offline cache (%d items)", g_iCacheCount);
}

// #6 - Offline cache'i gönder
void FlushOfflineCache();  // Forward declaration

// #2 - Adaptive heartbeat interval
DWORD GetHeartbeatInterval() {
    if (!g_bAPIOnline) return HEARTBEAT_OFFLINE_RETRY;
    return g_bInServer ? HEARTBEAT_IN_SERVER : HEARTBEAT_IN_MENU;
}
bool LoadOriginal() {
    if (g_hOriginal) return true;
    
    char sysPath[MAX_PATH];
    GetSystemDirectoryA(sysPath, MAX_PATH);
    strcat(sysPath, "\\winmm.dll");
    
    g_hOriginal = LoadLibraryA(sysPath);
    if (!g_hOriginal) {
        Log("FATAL: Cannot load original winmm.dll");
        return false;
    }
    
    // Load all functions
    o_TimeGetTime = (pfnTimeGetTime)GetProcAddress(g_hOriginal, "timeGetTime");
    o_TimeBeginPeriod = (pfnTimeBeginPeriod)GetProcAddress(g_hOriginal, "timeBeginPeriod");
    o_TimeEndPeriod = (pfnTimeEndPeriod)GetProcAddress(g_hOriginal, "timeEndPeriod");
    o_TimeGetDevCaps = (pfnTimeGetDevCaps)GetProcAddress(g_hOriginal, "timeGetDevCaps");
    o_TimeGetSystemTime = (pfnTimeGetSystemTime)GetProcAddress(g_hOriginal, "timeGetSystemTime");
    o_TimeSetEvent = (pfnTimeSetEvent)GetProcAddress(g_hOriginal, "timeSetEvent");
    o_TimeKillEvent = (pfnTimeKillEvent)GetProcAddress(g_hOriginal, "timeKillEvent");
    o_WaveOutOpen = (pfnWaveOutOpen)GetProcAddress(g_hOriginal, "waveOutOpen");
    o_WaveOutClose = (pfnWaveOutClose)GetProcAddress(g_hOriginal, "waveOutClose");
    o_WaveOutWrite = (pfnWaveOutWrite)GetProcAddress(g_hOriginal, "waveOutWrite");
    o_WaveOutPrepareHeader = (pfnWaveOutPrepareHeader)GetProcAddress(g_hOriginal, "waveOutPrepareHeader");
    o_WaveOutUnprepareHeader = (pfnWaveOutUnprepareHeader)GetProcAddress(g_hOriginal, "waveOutUnprepareHeader");
    o_WaveOutReset = (pfnWaveOutReset)GetProcAddress(g_hOriginal, "waveOutReset");
    o_WaveOutPause = (pfnWaveOutPause)GetProcAddress(g_hOriginal, "waveOutPause");
    o_WaveOutRestart = (pfnWaveOutRestart)GetProcAddress(g_hOriginal, "waveOutRestart");
    o_WaveOutGetPosition = (pfnWaveOutGetPosition)GetProcAddress(g_hOriginal, "waveOutGetPosition");
    o_WaveOutGetDevCapsA = (pfnWaveOutGetDevCapsA)GetProcAddress(g_hOriginal, "waveOutGetDevCapsA");
    o_WaveOutGetDevCapsW = (pfnWaveOutGetDevCapsW)GetProcAddress(g_hOriginal, "waveOutGetDevCapsW");
    o_WaveOutGetNumDevs = (pfnWaveOutGetNumDevs)GetProcAddress(g_hOriginal, "waveOutGetNumDevs");
    o_WaveOutGetVolume = (pfnWaveOutGetVolume)GetProcAddress(g_hOriginal, "waveOutGetVolume");
    o_WaveOutSetVolume = (pfnWaveOutSetVolume)GetProcAddress(g_hOriginal, "waveOutSetVolume");
    o_WaveOutGetErrorTextA = (pfnWaveOutGetErrorTextA)GetProcAddress(g_hOriginal, "waveOutGetErrorTextA");
    o_WaveOutGetErrorTextW = (pfnWaveOutGetErrorTextW)GetProcAddress(g_hOriginal, "waveOutGetErrorTextW");
    o_WaveOutGetID = (pfnWaveOutGetID)GetProcAddress(g_hOriginal, "waveOutGetID");
    o_WaveOutMessage = (pfnWaveOutMessage)GetProcAddress(g_hOriginal, "waveOutMessage");
    o_WaveOutBreakLoop = (pfnWaveOutBreakLoop)GetProcAddress(g_hOriginal, "waveOutBreakLoop");
    o_WaveInOpen = (pfnWaveInOpen)GetProcAddress(g_hOriginal, "waveInOpen");
    o_WaveInClose = (pfnWaveInClose)GetProcAddress(g_hOriginal, "waveInClose");
    o_WaveInGetNumDevs = (pfnWaveInGetNumDevs)GetProcAddress(g_hOriginal, "waveInGetNumDevs");
    o_WaveInGetDevCapsA = (pfnWaveInGetDevCapsA)GetProcAddress(g_hOriginal, "waveInGetDevCapsA");
    o_WaveInGetDevCapsW = (pfnWaveInGetDevCapsW)GetProcAddress(g_hOriginal, "waveInGetDevCapsW");
    o_WaveInStart = (pfnWaveInStart)GetProcAddress(g_hOriginal, "waveInStart");
    o_WaveInStop = (pfnWaveInStop)GetProcAddress(g_hOriginal, "waveInStop");
    o_WaveInReset = (pfnWaveInReset)GetProcAddress(g_hOriginal, "waveInReset");
    o_WaveInPrepareHeader = (pfnWaveInPrepareHeader)GetProcAddress(g_hOriginal, "waveInPrepareHeader");
    o_WaveInUnprepareHeader = (pfnWaveInUnprepareHeader)GetProcAddress(g_hOriginal, "waveInUnprepareHeader");
    o_WaveInAddBuffer = (pfnWaveInAddBuffer)GetProcAddress(g_hOriginal, "waveInAddBuffer");
    o_WaveInGetPosition = (pfnWaveInGetPosition)GetProcAddress(g_hOriginal, "waveInGetPosition");
    o_WaveInGetID = (pfnWaveInGetID)GetProcAddress(g_hOriginal, "waveInGetID");
    o_WaveInGetErrorTextA = (pfnWaveInGetErrorTextA)GetProcAddress(g_hOriginal, "waveInGetErrorTextA");
    o_WaveInGetErrorTextW = (pfnWaveInGetErrorTextW)GetProcAddress(g_hOriginal, "waveInGetErrorTextW");
    o_WaveInMessage = (pfnWaveInMessage)GetProcAddress(g_hOriginal, "waveInMessage");
    o_PlaySoundA = (pfnPlaySoundA)GetProcAddress(g_hOriginal, "PlaySoundA");
    o_PlaySoundW = (pfnPlaySoundW)GetProcAddress(g_hOriginal, "PlaySoundW");
    o_SndPlaySoundA = (pfnSndPlaySoundA)GetProcAddress(g_hOriginal, "sndPlaySoundA");
    o_SndPlaySoundW = (pfnSndPlaySoundW)GetProcAddress(g_hOriginal, "sndPlaySoundW");
    o_JoyGetNumDevs = (pfnJoyGetNumDevs)GetProcAddress(g_hOriginal, "joyGetNumDevs");
    o_JoyGetDevCapsA = (pfnJoyGetDevCapsA)GetProcAddress(g_hOriginal, "joyGetDevCapsA");
    o_JoyGetDevCapsW = (pfnJoyGetDevCapsW)GetProcAddress(g_hOriginal, "joyGetDevCapsW");
    o_JoyGetPos = (pfnJoyGetPos)GetProcAddress(g_hOriginal, "joyGetPos");
    o_JoyGetPosEx = (pfnJoyGetPosEx)GetProcAddress(g_hOriginal, "joyGetPosEx");
    o_JoyGetThreshold = (pfnJoyGetThreshold)GetProcAddress(g_hOriginal, "joyGetThreshold");
    o_JoySetThreshold = (pfnJoySetThreshold)GetProcAddress(g_hOriginal, "joySetThreshold");
    o_JoySetCapture = (pfnJoySetCapture)GetProcAddress(g_hOriginal, "joySetCapture");
    o_JoyReleaseCapture = (pfnJoyReleaseCapture)GetProcAddress(g_hOriginal, "joyReleaseCapture");
    o_MidiOutGetNumDevs = (pfnMidiOutGetNumDevs)GetProcAddress(g_hOriginal, "midiOutGetNumDevs");
    o_MidiOutGetDevCapsA = (pfnMidiOutGetDevCapsA)GetProcAddress(g_hOriginal, "midiOutGetDevCapsA");
    o_MidiOutGetDevCapsW = (pfnMidiOutGetDevCapsW)GetProcAddress(g_hOriginal, "midiOutGetDevCapsW");
    o_MidiOutOpen = (pfnMidiOutOpen)GetProcAddress(g_hOriginal, "midiOutOpen");
    o_MidiOutClose = (pfnMidiOutClose)GetProcAddress(g_hOriginal, "midiOutClose");
    o_MidiOutShortMsg = (pfnMidiOutShortMsg)GetProcAddress(g_hOriginal, "midiOutShortMsg");
    o_MidiOutLongMsg = (pfnMidiOutLongMsg)GetProcAddress(g_hOriginal, "midiOutLongMsg");
    o_MidiOutReset = (pfnMidiOutReset)GetProcAddress(g_hOriginal, "midiOutReset");
    o_MidiOutPrepareHeader = (pfnMidiOutPrepareHeader)GetProcAddress(g_hOriginal, "midiOutPrepareHeader");
    o_MidiOutUnprepareHeader = (pfnMidiOutUnprepareHeader)GetProcAddress(g_hOriginal, "midiOutUnprepareHeader");
    o_AuxGetNumDevs = (pfnAuxGetNumDevs)GetProcAddress(g_hOriginal, "auxGetNumDevs");
    o_AuxGetDevCapsA = (pfnAuxGetDevCapsA)GetProcAddress(g_hOriginal, "auxGetDevCapsA");
    o_AuxGetDevCapsW = (pfnAuxGetDevCapsW)GetProcAddress(g_hOriginal, "auxGetDevCapsW");
    o_AuxGetVolume = (pfnAuxGetVolume)GetProcAddress(g_hOriginal, "auxGetVolume");
    o_AuxSetVolume = (pfnAuxSetVolume)GetProcAddress(g_hOriginal, "auxSetVolume");
    o_AuxOutMessage = (pfnAuxOutMessage)GetProcAddress(g_hOriginal, "auxOutMessage");
    o_MixerGetNumDevs = (pfnMixerGetNumDevs)GetProcAddress(g_hOriginal, "mixerGetNumDevs");
    o_MixerOpen = (pfnMixerOpen)GetProcAddress(g_hOriginal, "mixerOpen");
    o_MixerClose = (pfnMixerClose)GetProcAddress(g_hOriginal, "mixerClose");
    o_MixerGetDevCapsA = (pfnMixerGetDevCapsA)GetProcAddress(g_hOriginal, "mixerGetDevCapsA");
    o_MixerGetDevCapsW = (pfnMixerGetDevCapsW)GetProcAddress(g_hOriginal, "mixerGetDevCapsW");
    o_MixerGetLineInfoA = (pfnMixerGetLineInfoA)GetProcAddress(g_hOriginal, "mixerGetLineInfoA");
    o_MixerGetLineInfoW = (pfnMixerGetLineInfoW)GetProcAddress(g_hOriginal, "mixerGetLineInfoW");
    o_MixerGetLineControlsA = (pfnMixerGetLineControlsA)GetProcAddress(g_hOriginal, "mixerGetLineControlsA");
    o_MixerGetLineControlsW = (pfnMixerGetLineControlsW)GetProcAddress(g_hOriginal, "mixerGetLineControlsW");
    o_MixerGetControlDetailsA = (pfnMixerGetControlDetailsA)GetProcAddress(g_hOriginal, "mixerGetControlDetailsA");
    o_MixerGetControlDetailsW = (pfnMixerGetControlDetailsW)GetProcAddress(g_hOriginal, "mixerGetControlDetailsW");
    o_MixerSetControlDetails = (pfnMixerSetControlDetails)GetProcAddress(g_hOriginal, "mixerSetControlDetails");
    o_MixerGetID = (pfnMixerGetID)GetProcAddress(g_hOriginal, "mixerGetID");
    o_MixerMessage = (pfnMixerMessage)GetProcAddress(g_hOriginal, "mixerMessage");
    o_MciSendCommandA = (pfnMciSendCommandA)GetProcAddress(g_hOriginal, "mciSendCommandA");
    o_MciSendCommandW = (pfnMciSendCommandW)GetProcAddress(g_hOriginal, "mciSendCommandW");
    o_MciSendStringA = (pfnMciSendStringA)GetProcAddress(g_hOriginal, "mciSendStringA");
    o_MciSendStringW = (pfnMciSendStringW)GetProcAddress(g_hOriginal, "mciSendStringW");
    o_MciGetErrorStringA = (pfnMciGetErrorStringA)GetProcAddress(g_hOriginal, "mciGetErrorStringA");
    o_MciGetErrorStringW = (pfnMciGetErrorStringW)GetProcAddress(g_hOriginal, "mciGetErrorStringW");
    o_MciGetDeviceIDA = (pfnMciGetDeviceIDA)GetProcAddress(g_hOriginal, "mciGetDeviceIDA");
    o_MciGetDeviceIDW = (pfnMciGetDeviceIDW)GetProcAddress(g_hOriginal, "mciGetDeviceIDW");
    o_MciGetDeviceIDFromElementIDA = (pfnMciGetDeviceIDFromElementIDA)GetProcAddress(g_hOriginal, "mciGetDeviceIDFromElementIDA");
    o_MciGetDeviceIDFromElementIDW = (pfnMciGetDeviceIDFromElementIDW)GetProcAddress(g_hOriginal, "mciGetDeviceIDFromElementIDW");
    o_MciSetYieldProc = (pfnMciSetYieldProc)GetProcAddress(g_hOriginal, "mciSetYieldProc");
    o_MciGetYieldProc = (pfnMciGetYieldProc)GetProcAddress(g_hOriginal, "mciGetYieldProc");
    o_MciGetCreatorTask = (pfnMciGetCreatorTask)GetProcAddress(g_hOriginal, "mciGetCreatorTask");
    o_MciExecute = (pfnMciExecute)GetProcAddress(g_hOriginal, "mciExecute");
    o_MmioOpenA = (pfnMmioOpenA)GetProcAddress(g_hOriginal, "mmioOpenA");
    o_MmioOpenW = (pfnMmioOpenW)GetProcAddress(g_hOriginal, "mmioOpenW");
    o_MmioClose = (pfnMmioClose)GetProcAddress(g_hOriginal, "mmioClose");
    o_MmioRead = (pfnMmioRead)GetProcAddress(g_hOriginal, "mmioRead");
    o_MmioWrite = (pfnMmioWrite)GetProcAddress(g_hOriginal, "mmioWrite");
    o_MmioSeek = (pfnMmioSeek)GetProcAddress(g_hOriginal, "mmioSeek");
    o_MmioGetInfo = (pfnMmioGetInfo)GetProcAddress(g_hOriginal, "mmioGetInfo");
    o_MmioSetInfo = (pfnMmioSetInfo)GetProcAddress(g_hOriginal, "mmioSetInfo");
    o_MmioSetBuffer = (pfnMmioSetBuffer)GetProcAddress(g_hOriginal, "mmioSetBuffer");
    o_MmioFlush = (pfnMmioFlush)GetProcAddress(g_hOriginal, "mmioFlush");
    o_MmioAdvance = (pfnMmioAdvance)GetProcAddress(g_hOriginal, "mmioAdvance");
    o_MmioInstallIOProcA = (pfnMmioInstallIOProcA)GetProcAddress(g_hOriginal, "mmioInstallIOProcA");
    o_MmioInstallIOProcW = (pfnMmioInstallIOProcW)GetProcAddress(g_hOriginal, "mmioInstallIOProcW");
    o_MmioStringToFOURCCA = (pfnMmioStringToFOURCCA)GetProcAddress(g_hOriginal, "mmioStringToFOURCCA");
    o_MmioStringToFOURCCW = (pfnMmioStringToFOURCCW)GetProcAddress(g_hOriginal, "mmioStringToFOURCCW");
    o_MmioDescend = (pfnMmioDescend)GetProcAddress(g_hOriginal, "mmioDescend");
    o_MmioAscend = (pfnMmioAscend)GetProcAddress(g_hOriginal, "mmioAscend");
    o_MmioCreateChunk = (pfnMmioCreateChunk)GetProcAddress(g_hOriginal, "mmioCreateChunk");
    o_MmioRename = (pfnMmioRename)GetProcAddress(g_hOriginal, "mmioRenameA");
    o_MmioSendMessage = (pfnMmioSendMessage)GetProcAddress(g_hOriginal, "mmioSendMessage");
    
    return true;
}

// ============================================
// MD5 HASH
// ============================================
class MD5 {
public:
    MD5() { Init(); }
    void Init() { count[0]=count[1]=0; state[0]=0x67452301; state[1]=0xefcdab89; state[2]=0x98badcfe; state[3]=0x10325476; }
    void Update(const unsigned char* input, unsigned int length) {
        unsigned int index=(count[0]>>3)&0x3F; count[0]+=length<<3;
        if(count[0]<(length<<3))count[1]++; count[1]+=length>>29;
        unsigned int partLen=64-index,i=0;
        if(length>=partLen){memcpy(&buffer[index],input,partLen);Transform(state,buffer);for(i=partLen;i+63<length;i+=64)Transform(state,&input[i]);index=0;}
        memcpy(&buffer[index],&input[i],length-i);
    }
    void Final(unsigned char digest[16]) {
        unsigned char bits[8]; Encode(bits,count,8);
        unsigned int index=(count[0]>>3)&0x3f,padLen=(index<56)?(56-index):(120-index);
        static unsigned char PADDING[64]={0x80}; Update(PADDING,padLen); Update(bits,8); Encode(digest,state,16);
    }
    std::string GetHashString() { 
        unsigned char d[16]; Final(d); 
        char h[33]; 
        for(int i=0;i<16;i++) sprintf(h+i*2,"%02x",d[i]); 
        return std::string(h); 
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
    }
    void Encode(unsigned char* out, const unsigned int* in, unsigned int len) { for(unsigned int i=0,j=0;j<len;i++,j+=4){out[j]=in[i]&0xff;out[j+1]=(in[i]>>8)&0xff;out[j+2]=(in[i]>>16)&0xff;out[j+3]=(in[i]>>24)&0xff;} }
    void Decode(unsigned int* out, const unsigned char* in, unsigned int len) { for(unsigned int i=0,j=0;j<len;i++,j+=4) out[i]=in[j]|(in[j+1]<<8)|(in[j+2]<<16)|(in[j+3]<<24); }
};

// ============================================
// HWID & HASH
// ============================================
void GenHWID() {
    int cpu[4]={0}; __cpuid(cpu,0);
    DWORD vol=0; GetVolumeInformationA("C:\\",NULL,0,&vol,NULL,NULL,NULL,0);
    char pc[MAX_COMPUTERNAME_LENGTH+1]={0}; DWORD sz=sizeof(pc); GetComputerNameA(pc,&sz);
    sprintf(g_szHWID, "%08X%08X%08X", cpu[0]^cpu[1], vol, (pc[0]<<24)|(pc[1]<<16)|(pc[2]<<8)|pc[3]);
    Log("HWID: %s", g_szHWID);
}

// ============================================
// v12.2 - STEAMID TESPİTİ
// ============================================
// Yöntem 1: Registry'den aktif Steam kullanıcısı
bool GetSteamIDFromRegistry() {
    HKEY hKey;
    char steamPath[MAX_PATH] = {0};
    DWORD size = sizeof(steamPath);
    
    // Steam yolu al
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // Aktif kullanıcı (SteamID3 formatında)
        DWORD userId = 0;
        size = sizeof(userId);
        if (RegQueryValueExA(hKey, "ActiveProcess\\ActiveUser", NULL, NULL, (LPBYTE)&userId, &size) == ERROR_SUCCESS && userId > 0) {
            // SteamID64'e çevir (Universe=1, Type=1)
            // SteamID64 = (Universe << 56) | (Type << 52) | (Instance << 32) | AccountID
            // Basit format: STEAM_X:Y:Z
            // X = Universe (genelde 0 veya 1)
            // Y = AccountID'nin son biti (0 veya 1)  
            // Z = AccountID / 2
            DWORD y = userId & 1;
            DWORD z = userId >> 1;
            sprintf(g_szSteamID, "STEAM_0:%d:%d", y, z);
            Log("SteamID from Registry: %s", g_szSteamID);
            RegCloseKey(hKey);
            return true;
        }
        RegCloseKey(hKey);
    }
    
    // Yöntem 2: loginusers.vdf dosyasından
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        size = sizeof(steamPath);
        if (RegQueryValueExA(hKey, "SteamPath", NULL, NULL, (LPBYTE)steamPath, &size) == ERROR_SUCCESS) {
            char vdfPath[MAX_PATH];
            sprintf(vdfPath, "%s\\config\\loginusers.vdf", steamPath);
            
            FILE* f = fopen(vdfPath, "r");
            if (f) {
                char line[512];
                char lastSteamID64[32] = {0};
                bool foundMostRecent = false;
                
                while (fgets(line, sizeof(line), f)) {
                    // "7656119XXXXXXXXX" formatında SteamID64 ara
                    char* p = strstr(line, "\"7656119");
                    if (p) {
                        p++; // " atla
                        char* end = strchr(p, '"');
                        if (end) {
                            *end = 0;
                            strcpy(lastSteamID64, p);
                        }
                    }
                    // "mostrecent" "1" satırını ara
                    if (strstr(line, "\"mostrecent\"") && strstr(line, "\"1\"")) {
                        foundMostRecent = true;
                    }
                }
                fclose(f);
                
                if (lastSteamID64[0]) {
                    // SteamID64'ten STEAM_X:Y:Z formatına çevir
                    unsigned long long sid64 = _strtoui64(lastSteamID64, NULL, 10);
                    DWORD accountId = (DWORD)(sid64 & 0xFFFFFFFF);
                    DWORD y = accountId & 1;
                    DWORD z = accountId >> 1;
                    sprintf(g_szSteamID, "STEAM_0:%d:%d", y, z);
                    Log("SteamID from loginusers.vdf: %s (ID64: %s)", g_szSteamID, lastSteamID64);
                    RegCloseKey(hKey);
                    return true;
                }
            }
        }
        RegCloseKey(hKey);
    }
    
    return false;
}

// Yöntem 2: userdata klasöründen en son değişen ID
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
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.cFileName[0] != '.') {
                DWORD accountId = atoi(fd.cFileName);
                if (accountId > 0) {
                    // En son değişeni bul
                    if (CompareFileTime(&fd.ftLastWriteTime, &latestTime) > 0) {
                        latestTime = fd.ftLastWriteTime;
                        latestAccountId = accountId;
                    }
                }
            }
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    
    if (latestAccountId > 0) {
        DWORD y = latestAccountId & 1;
        DWORD z = latestAccountId >> 1;
        sprintf(g_szSteamID, "STEAM_0:%d:%d", y, z);
        Log("SteamID from userdata: %s (AccountID: %d)", g_szSteamID, latestAccountId);
        return true;
    }
    
    return false;
}

// Steam kullanıcı adını al (opsiyonel)
void GetSteamUsername() {
    HKEY hKey;
    DWORD size = sizeof(g_szSteamName);
    
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "LastGameNameUsed", NULL, NULL, (LPBYTE)g_szSteamName, &size) != ERROR_SUCCESS) {
            // Alternatif
            size = sizeof(g_szSteamName);
            RegQueryValueExA(hKey, "AutoLoginUser", NULL, NULL, (LPBYTE)g_szSteamName, &size);
        }
        RegCloseKey(hKey);
    }
    
    if (g_szSteamName[0]) {
        Log("Steam Username: %s", g_szSteamName);
    }
}

// SteamID tespit et (tüm yöntemleri dene)
void ResolveSteamID() {
    if (g_bSteamIDResolved) return;
    
    Log("Resolving SteamID...");
    
    if (!GetSteamIDFromRegistry()) {
        if (!GetSteamIDFromUserdata()) {
            Log("Could not resolve SteamID");
            strcpy(g_szSteamID, "STEAM_ID_UNKNOWN");
        }
    }
    
    GetSteamUsername();
    g_bSteamIDResolved = true;
}

// #9 - Hash Cache: Dosya değişmediyse tekrar hash'leme
void GetFileHash(const char* filepath, char* shortHash, char* fullHash, DWORD* fileSize) {
    shortHash[0] = fullHash[0] = 0;
    *fileSize = 0;
    
    // Dosya bilgilerini al
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(filepath, GetFileExInfoStandard, &fad)) return;
    
    *fileSize = fad.nFileSizeLow;
    
    // Cache kontrolü
    std::string key = filepath;
    auto it = g_HashCache.find(key);
    if (it != g_HashCache.end() && it->second.valid) {
        // Dosya değişmemiş mi?
        if (it->second.fileSize == *fileSize &&
            it->second.lastWrite.dwLowDateTime == fad.ftLastWriteTime.dwLowDateTime &&
            it->second.lastWrite.dwHighDateTime == fad.ftLastWriteTime.dwHighDateTime) {
            // Cache'den döndür
            strncpy(fullHash, it->second.hash.c_str(), 32); fullHash[32] = 0;
            strncpy(shortHash, it->second.hash.c_str(), AGTR_HASH_LENGTH); shortHash[AGTR_HASH_LENGTH] = 0;
            return;
        }
    }
    
    // Dosyayı oku ve hash'le
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
    Log("DLL Hash: %s", g_szDLLHash);
}

// ============================================
// SERVER DETECTION
// ============================================
bool DetectConnectedServer() {
    g_bInServer = false;
    g_szConnectedIP[0] = 0;
    g_iConnectedPort = 0;
    
    DWORD hlPid = GetCurrentProcessId();
    
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
                    
                    if (remotePort >= 27000 && remotePort <= 27100) {
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
                        if (localPort >= 27000 && localPort <= 27100) {
                            g_bInServer = true;
                            break;
                        }
                    }
                }
            }
            if (pUdpTable) free(pUdpTable);
        }
    }
    
    // v12.2 - Sunucu değişikliği tespiti
    bool serverChanged = false;
    if (g_bInServer) {
        if (strcmp(g_szConnectedIP, g_szLastConnectedIP) != 0 || g_iConnectedPort != g_iLastConnectedPort) {
            serverChanged = true;
            strcpy(g_szLastConnectedIP, g_szConnectedIP);
            g_iLastConnectedPort = g_iConnectedPort;
            g_dwConnectionStart = GetTickCount();
            g_bConnectionNotified = false;
            Log("Server changed: %s:%d", g_szConnectedIP, g_iConnectedPort);
        }
    } else {
        // Sunucudan çıkıldı
        if (g_szLastConnectedIP[0]) {
            Log("Disconnected from server");
            g_szLastConnectedIP[0] = 0;
            g_iLastConnectedPort = 0;
            g_bConnectionNotified = false;
        }
    }
    
    return g_bInServer;
}

// ============================================
// v12.2 - HIZLI BAĞLANTI BİLDİRİMİ
// ============================================
// Sunucuya bağlanır bağlanmaz API'ye bildir (heartbeat beklemeden)
void NotifyServerConnect() {
    if (!g_bInServer || g_bConnectionNotified) return;
    if (!g_szConnectedIP[0]) return;
    
    // SteamID henüz çözülmediyse çöz
    if (!g_bSteamIDResolved) {
        ResolveSteamID();
    }
    
    EnsureStringsDecrypted();
    
    char json[1024];
    sprintf(json, 
        "{\"hwid\":\"%s\","
        "\"steamid\":\"%s\","
        "\"steam_name\":\"%s\","
        "\"server_ip\":\"%s\","
        "\"server_port\":%d,"
        "\"version\":\"%s\","
        "\"trigger\":\"winmm\","
        "\"event\":\"connect\"}",
        g_szHWID, 
        g_szSteamID,
        g_szSteamName,
        g_szConnectedIP, 
        g_iConnectedPort, 
        AGTR_VERSION);
    
    Log("Quick connect notification: %s:%d (SteamID: %s)", g_szConnectedIP, g_iConnectedPort, g_szSteamID);
    
    std::string resp = HttpRequest(g_szPathConnect, json, "POST", false);
    
    if (!resp.empty()) {
        g_bConnectionNotified = true;
        
        // Token varsa kaydet
        const char* tokenStart = strstr(resp.c_str(), "\"token\":\"");
        if (tokenStart) {
            tokenStart += 9;
            const char* tokenEnd = strchr(tokenStart, '"');
            if (tokenEnd && tokenEnd - tokenStart < sizeof(g_szAuthToken) - 1) {
                strncpy(g_szAuthToken, tokenStart, tokenEnd - tokenStart);
                g_szAuthToken[tokenEnd - tokenStart] = 0;
                Log("Received auth token: %s", g_szAuthToken);
            }
        }
        
        // Ban kontrolü
        if (strstr(resp.c_str(), "\"status\":\"banned\"")) {
            Log("!!! BANNED ON CONNECT !!!");
            MessageBoxA(NULL, g_Settings.message_on_kick, "AGTR Anti-Cheat", MB_OK | MB_ICONERROR);
            ExitProcess(0);
        }
    }
}

// ============================================
// HTTP HELPER (with timeout & graceful degradation)
// ============================================
std::string HttpRequest(const wchar_t* path, const std::string& body, const std::string& method, bool canCache) {
    std::string response;
    
    // Decrypt API strings on first use
    EnsureStringsDecrypted();
    
    HINTERNET hSession = WinHttpOpen(g_szUserAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        g_bAPIOnline = false;
        g_iFailedRequests++;
        if (canCache && !body.empty()) AddToOfflineCache(body);
        return response;
    }
    
    // #3 - Timeout ayarları (5sn)
    DWORD timeout = API_TIMEOUT;
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    
    HINTERNET hConnect = WinHttpConnect(hSession, g_szAPIHost, API_PORT, 0);
    if (!hConnect) { 
        WinHttpCloseHandle(hSession);
        g_bAPIOnline = false;
        g_iFailedRequests++;
        if (canCache && !body.empty()) AddToOfflineCache(body);
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
        if (canCache && !body.empty()) AddToOfflineCache(body);
        return response;
    }
    
    std::wstring headers = L"Content-Type: application/json\r\n";
    
    BOOL result;
    if (body.empty()) {
        result = WinHttpSendRequest(hRequest, headers.c_str(), -1, NULL, 0, 0, 0);
    } else {
        result = WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)body.c_str(), body.length(), body.length(), 0);
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
            // #30 - Başarılı, API online
            g_bAPIOnline = true;
            g_iFailedRequests = 0;
        }
    }
    
    if (!result || response.empty()) {
        g_iFailedRequests++;
        // #30 - 3 ardışık hatadan sonra offline say
        if (g_iFailedRequests >= 3) {
            g_bAPIOnline = false;
            Log("API marked offline after %d failures", g_iFailedRequests);
        }
        // #6 - Offline cache'e ekle
        if (canCache && !body.empty()) {
            AddToOfflineCache(body);
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return response;
}

// #6 - Offline cache'i göndermeye çalış
void FlushOfflineCache() {
    if (g_iCacheCount == 0 || !g_bAPIOnline) return;
    
    EnsureStringsDecrypted();
    Log("Flushing offline cache (%d items)", g_iCacheCount);
    
    int sent = 0;
    for (int i = 0; i < g_iCacheCount; i++) {
        if (!g_OfflineCache[i].valid) continue;
        
        std::string resp = HttpRequest(g_szPathScan, g_OfflineCache[i].data, "POST", false);
        if (!resp.empty()) {
            g_OfflineCache[i].valid = false;
            sent++;
        } else {
            // Gönderim başarısız, durduralım
            break;
        }
        
        // Rate limiting - aralarında 1sn bekle
        Sleep(1000);
    }
    
    // Geçersizleri temizle
    int newCount = 0;
    for (int i = 0; i < g_iCacheCount; i++) {
        if (g_OfflineCache[i].valid) {
            if (i != newCount) {
                g_OfflineCache[newCount] = g_OfflineCache[i];
            }
            newCount++;
        }
    }
    g_iCacheCount = newCount;
    
    Log("Sent %d cached items, %d remaining", sent, g_iCacheCount);
}

// ============================================
// SETTINGS
// ============================================
bool FetchSettings() {
    EnsureStringsDecrypted();
    
    // v12.2 - SteamID'yi register'da da gönder
    if (!g_bSteamIDResolved) {
        ResolveSteamID();
    }
    
    char json[512];
    sprintf(json, 
        "{\"hwid\":\"%s\","
        "\"steamid\":\"%s\","
        "\"steam_name\":\"%s\","
        "\"version\":\"%s\","
        "\"trigger\":\"winmm\"}",
        g_szHWID, g_szSteamID, g_szSteamName, AGTR_VERSION);
    
    std::string resp = HttpRequest(g_szPathRegister, json);
    
    if (resp.empty()) {
        Log("Settings fetch failed");
        return false;
    }
    
    Log("Settings: %.100s...", resp.c_str());
    
    if (strstr(resp.c_str(), "\"scan_enabled\":false")) g_Settings.scan_enabled = false;
    if (strstr(resp.c_str(), "\"scan_only_in_server\":false")) g_Settings.scan_only_in_server = false;
    
    const char* intPos = strstr(resp.c_str(), "\"scan_interval\":");
    if (intPos) {
        int interval = atoi(intPos + 16);
        if (interval >= 30 && interval <= 600) {
            g_Settings.scan_interval = interval * 1000;
        }
    }
    
    // v12.2 - Token al
    const char* tokenStart = strstr(resp.c_str(), "\"token\":\"");
    if (tokenStart) {
        tokenStart += 9;
        const char* tokenEnd = strchr(tokenStart, '"');
        if (tokenEnd && tokenEnd - tokenStart < sizeof(g_szAuthToken) - 1) {
            strncpy(g_szAuthToken, tokenStart, tokenEnd - tokenStart);
            g_szAuthToken[tokenEnd - tokenStart] = 0;
            Log("Received initial token: %s", g_szAuthToken);
        }
    }
    
    if (strstr(resp.c_str(), "\"status\":\"banned\"") || strstr(resp.c_str(), "\"action\":\"kick\"")) {
        Log("!!! BANNED !!!");
        MessageBoxA(NULL, g_Settings.message_on_kick, "AGTR Anti-Cheat", MB_OK | MB_ICONERROR);
        ExitProcess(0);
        return false;
    }
    
    g_bSettingsLoaded = true;
    return true;
}

// ============================================
// HEARTBEAT
// ============================================
void SendHeartbeat() {
    DetectConnectedServer();
    
    // v12.2 - Sunucuya yeni bağlandıysa hızlı bildirim gönder
    if (g_bInServer && !g_bConnectionNotified) {
        NotifyServerConnect();
    }
    
    // #6 - API online'a döndüyse cache'i gönder
    if (g_bAPIOnline && g_iCacheCount > 0) {
        FlushOfflineCache();
    }
    
    // v12.2 - SteamID henüz çözülmediyse çöz
    if (!g_bSteamIDResolved) {
        ResolveSteamID();
    }
    
    char json[1024];
    sprintf(json, 
        "{\"hwid\":\"%s\","
        "\"steamid\":\"%s\","
        "\"steam_name\":\"%s\","
        "\"server_ip\":\"%s\","
        "\"server_port\":%d,"
        "\"in_game\":%s,"
        "\"token\":\"%s\","
        "\"trigger\":\"winmm\","
        "\"version\":\"%s\"}",
        g_szHWID, 
        g_szSteamID,
        g_szSteamName,
        g_szConnectedIP, 
        g_iConnectedPort, 
        g_bInServer ? "true" : "false", 
        g_szAuthToken,
        AGTR_VERSION);
    
    std::string resp = HttpRequest(g_szPathHeartbeat, json);
    
    if (!resp.empty()) {
        if (strstr(resp.c_str(), "\"should_scan\":false")) g_Settings.scan_enabled = false;
        if (strstr(resp.c_str(), "\"status\":\"banned\"")) {
            Log("!!! BANNED VIA HEARTBEAT !!!");
            MessageBoxA(NULL, g_Settings.message_on_kick, "AGTR Anti-Cheat", MB_OK | MB_ICONERROR);
            ExitProcess(0);
        }
        
        // Token güncelleme (sunucu yeni token vermiş olabilir)
        const char* tokenStart = strstr(resp.c_str(), "\"token\":\"");
        if (tokenStart) {
            tokenStart += 9;
            const char* tokenEnd = strchr(tokenStart, '"');
            if (tokenEnd && tokenEnd - tokenStart < sizeof(g_szAuthToken) - 1) {
                strncpy(g_szAuthToken, tokenStart, tokenEnd - tokenStart);
                g_szAuthToken[tokenEnd - tokenStart] = 0;
            }
        }
    }
    
    g_dwLastHeartbeat = GetTickCount();
}

// ============================================
// PROCESS SCANNER
// ============================================
bool IsWhitelistedProcess(const char* name) {
    char lower[MAX_PATH];
    strcpy(lower, name);
    ToLower(lower);
    for (int i = 0; g_WhitelistProc[i]; i++) {
        if (strstr(lower, g_WhitelistProc[i])) return true;
    }
    return false;
}

int ScanProcesses() {
    g_Processes.clear();
    int sus = 0;
    
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            ProcessInfo pi;
            pi.name = pe.szExeFile;
            pi.pid = pe.th32ProcessID;
            pi.suspicious = false;
            
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                char path[MAX_PATH] = {0};
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameA(hProc, 0, path, &size)) {
                    pi.path = path;
                }
                CloseHandle(hProc);
            }
            
            if (!IsWhitelistedProcess(pe.szExeFile)) {
                char name[MAX_PATH]; strcpy(name, pe.szExeFile); ToLower(name);
                
                // Cheat process kontrolü
                for (int i = 0; g_SusProc[i]; i++) {
                    if (strstr(name, g_SusProc[i])) {
                        pi.suspicious = true;
                        sus++;
                        Log("SUS PROC: %s", pe.szExeFile);
                        break;
                    }
                }
                
                // Macro/Automation tool kontrolü (sadece log, sus saymıyoruz)
                if (!pi.suspicious) {
                    for (int i = 0; g_MacroProc[i]; i++) {
                        if (strstr(name, g_MacroProc[i])) {
                            Log("MACRO TOOL: %s", pe.szExeFile);
                            break;
                        }
                    }
                }
            }
            
            g_Processes.push_back(pi);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return sus;
}

// ============================================
// MODULE SCANNER
// ============================================
int ScanModules() {
    g_Modules.clear();
    int sus = 0;
    
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    ToLower(sysDir);
    
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            ModuleInfo mi;
            mi.name = me.szModule;
            mi.path = me.szExePath;
            mi.size = me.modBaseSize;
            
            char shortH[16], fullH[64];
            DWORD fsize;
            GetFileHash(me.szExePath, shortH, fullH, &fsize);
            mi.hash = shortH;
            
            char modName[MAX_PATH]; strcpy(modName, me.szModule); ToLower(modName);
            char modPath[MAX_PATH]; strcpy(modPath, me.szExePath); ToLower(modPath);
            
            for (int i = 0; g_SusDLLs[i]; i++) {
                if (strstr(modName, g_SusDLLs[i])) {
                    if ((strcmp(g_SusDLLs[i], "opengl32.dll") == 0 || strcmp(g_SusDLLs[i], "d3d9.dll") == 0)) {
                        if (strstr(modPath, sysDir)) continue;
                    }
                    sus++;
                    Log("SUS MODULE: %s", me.szModule);
                    break;
                }
            }
            
            g_Modules.push_back(mi);
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return sus;
}

// ============================================
// WINDOW SCANNER
// ============================================
static int g_WinSus = 0;

BOOL CALLBACK EnumWinCB(HWND hwnd, LPARAM) {
    char title[256] = {0}; 
    char className[256] = {0};
    
    GetWindowTextA(hwnd, title, 256);
    GetClassNameA(hwnd, className, 256);
    
    if (title[0]) {
        WindowInfo wi;
        wi.title = title;
        wi.className = className;
        
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        wi.pid = pid;
        wi.suspicious = false;
        
        char lowerTitle[256]; strcpy(lowerTitle, title); ToLower(lowerTitle);
        for (int i = 0; g_SusWin[i]; i++) {
            if (strstr(lowerTitle, g_SusWin[i])) {
                wi.suspicious = true;
                g_WinSus++;
                Log("SUS WINDOW: %s", title);
                break;
            }
        }
        
        g_Windows.push_back(wi);
    }
    return TRUE;
}

int ScanWindows() { 
    g_Windows.clear();
    g_WinSus = 0; 
    EnumWindows(EnumWinCB, 0); 
    return g_WinSus; 
}

// ============================================
// REGISTRY SCANNER
// ============================================
int ScanRegistry() {
    int sus = 0;
    for (int i = 0; g_SusReg[i]; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, g_SusReg[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) { 
            Log("SUS REG: HKCU\\%s", g_SusReg[i]); 
            RegCloseKey(hKey); 
            sus++; 
        }
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, g_SusReg[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) { 
            Log("SUS REG: HKLM\\%s", g_SusReg[i]); 
            RegCloseKey(hKey); 
            sus++; 
        }
    }
    g_iRegistrySus = sus;
    return sus;
}

// ============================================
// FILE SCANNER
// ============================================
void ScanDir(const char* dir, const char* pattern) {
    char searchPath[MAX_PATH]; sprintf(searchPath, "%s\\%s", dir, pattern);
    WIN32_FIND_DATAA fd; HANDLE h = FindFirstFileA(searchPath, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char filepath[MAX_PATH], filename[MAX_PATH];
        sprintf(filepath, "%s\\%s", dir, fd.cFileName);
        strcpy(filename, fd.cFileName); ToLower(filename);
        
        DWORD modTime = fd.ftLastWriteTime.dwLowDateTime;
        auto it = g_FileCache.find(filename);
        if (it != g_FileCache.end() && it->second.modTime == modTime) continue;
        
        char shortH[16], fullH[64];
        DWORD fileSize;
        GetFileHash(filepath, shortH, fullH, &fileSize);
        
        if (shortH[0]) { 
            FileHashInfo fhi;
            fhi.filename = filename;
            fhi.path = filepath;
            fhi.shortHash = shortH;
            fhi.fullHash = fullH;
            fhi.size = fileSize;
            fhi.modTime = modTime;
            g_FileCache[filename] = fhi;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

void ScanAllFiles() {
    char dir[MAX_PATH];
    ScanDir(g_szGameDir, "*.dll"); ScanDir(g_szGameDir, "*.exe");
    ScanDir(g_szValveDir, "*.dll");
    sprintf(dir, "%s\\cl_dlls", g_szValveDir); ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\dlls", g_szValveDir); ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\ag", g_szGameDir); ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\ag\\cl_dlls", g_szGameDir); ScanDir(dir, "*.dll");
}

int CheckSusFiles() {
    int sus = 0;
    for (auto& p : g_FileCache) {
        for (int i = 0; g_SusFile[i]; i++) {
            if (p.first.find(g_SusFile[i]) != std::string::npos) { 
                Log("SUS FILE: %s", p.first.c_str()); 
                sus++; 
                break; 
            }
        }
    }
    return sus;
}

// ============================================
// JSON BUILDER
// ============================================
std::string EscapeJson(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.length(); i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    sprintf(buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

std::string BuildJson() {
    // v12.4 - Anti-debug check
    if (ANTI_DEBUG_ENABLED) {
        g_bDebuggerDetected = CheckDebugger();
    }
    
    // v12.4 - Generate timestamp for replay protection
    DWORD64 timestamp = GetTimestamp();
    
    std::string json = "{";
    json += "\"hwid\":\"" + std::string(g_szHWID) + "\",";
    json += "\"version\":\"" + std::string(AGTR_VERSION) + "\",";
    json += "\"dll_name\":\"" + std::string(g_szSelfName) + "\",";  // v12.4 - DLL filename
    json += "\"dll_hash\":\"" + std::string(g_szSelfHash) + "\",";  // v12.4 - Self hash
    json += "\"timestamp\":" + std::to_string(timestamp) + ",";    // v12.4 - Replay protection
    json += "\"server_ip\":\"" + std::string(g_szServerIP) + "\",";
    json += "\"server_port\":" + std::to_string(g_iServerPort) + ",";
    json += "\"passed\":" + std::string(g_bPassed ? "true" : "false") + ",";
    json += "\"sus_count\":" + std::to_string(g_iSusCount) + ",";
    json += "\"reg_sus\":" + std::to_string(g_iRegistrySus) + ",";
    
    // File hashes
    json += "\"hashes\":[";
    bool first = true;
    for (auto& h : g_FileCache) {
        if (!first) json += ",";
        json += "{\"file\":\"" + EscapeJson(h.second.filename) + "\",";
        json += "\"hash\":\"" + h.second.shortHash + "\",";
        json += "\"size\":" + std::to_string(h.second.size) + "}";
        first = false;
    }
    json += "],";
    
    // Processes (suspicious + first 20)
    json += "\"processes\":[";
    first = true;
    int procCount = 0;
    for (auto& p : g_Processes) {
        if (p.suspicious || procCount < 20) {
            if (!first) json += ",";
            json += "{\"name\":\"" + EscapeJson(p.name) + "\",";
            json += "\"suspicious\":" + std::string(p.suspicious ? "true" : "false") + "}";
            first = false;
            procCount++;
        }
    }
    json += "],";
    
    // Modules (game dir only)
    json += "\"modules\":[";
    first = true;
    char gamePathLower[MAX_PATH];
    strcpy(gamePathLower, g_szGameDir);
    ToLower(gamePathLower);
    
    for (auto& m : g_Modules) {
        char modPathLower[MAX_PATH];
        strcpy(modPathLower, m.path.c_str());
        ToLower(modPathLower);
        
        if (strstr(modPathLower, "half-life") || strstr(modPathLower, gamePathLower)) {
            if (!first) json += ",";
            json += "{\"name\":\"" + EscapeJson(m.name) + "\",";
            json += "\"hash\":\"" + m.hash + "\"}";
            first = false;
        }
    }
    json += "],";
    
    // Windows (suspicious only)
    json += "\"windows\":[";
    first = true;
    for (auto& w : g_Windows) {
        if (w.suspicious) {
            if (!first) json += ",";
            json += "{\"title\":\"" + EscapeJson(w.title) + "\"}";
            first = false;
        }
    }
    json += "],";
    
    // Security check results
    json += "\"security\":{";
    json += "\"debugger\":" + std::string(g_bDebuggerDetected ? "true" : "false") + ",";
    json += "\"vm\":" + std::string(g_bVMDetected ? "true" : "false") + ",";
    json += "\"hooks\":" + std::string(g_bHooksDetected ? "true" : "false") + ",";
    json += "\"drivers\":" + std::string(g_bDriversDetected ? "true" : "false") + ",";
    json += "\"integrity\":" + std::string(g_bIntegrityOK ? "true" : "false");
    json += "}";
    
    // v12.4 - Compute and add signature at the end
    // First close the JSON without signature to compute hash
    std::string jsonForSig = json + "}";
    char signature[65] = {0};
    SignRequest(jsonForSig.c_str(), timestamp, signature);
    
    // Now add signature to JSON
    json += ",\"signature\":\"" + std::string(signature) + "\"";
    
    json += "}";
    return json;
}

std::string ComputeSignature(const std::string& data) {
    char key[32]; Deobf(OBF_KEY, OBF_KEY_LEN, key);
    MD5 md5;
    md5.Update((unsigned char*)key, strlen(key));
    md5.Update((unsigned char*)data.c_str(), data.length());
    return md5.GetHashString();
}

// ============================================
// SEND TO API (with timeout & offline cache)
// ============================================
bool SendToAPI(const std::string& jsonData, const std::string& signature) {
    // #7 - Throttle check
    if (ShouldThrottle(jsonData)) {
        return true; // Skip but return success
    }
    
    // #30 - API offline ise cache'le ve devam et
    if (!g_bAPIOnline) {
        AddToOfflineCache(jsonData);
        Log("API offline - cached scan data");
        return false;
    }
    
    // Decrypt API strings on first use
    EnsureStringsDecrypted();
    
    HINTERNET hSession = WinHttpOpen(g_szUserAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        AddToOfflineCache(jsonData);
        return false;
    }
    
    // Timeout ayarları
    DWORD timeout = API_TIMEOUT;
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    
    HINTERNET hConnect = WinHttpConnect(hSession, g_szAPIHost, API_PORT, 0);
    if (!hConnect) { 
        WinHttpCloseHandle(hSession);
        AddToOfflineCache(jsonData);
        return false;
    }
    
    DWORD flags = API_USE_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", g_szPathScan, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { 
        WinHttpCloseHandle(hConnect); 
        WinHttpCloseHandle(hSession);
        AddToOfflineCache(jsonData);
        return false;
    }
    
    std::wstring headers = L"Content-Type: application/json\r\n";
    headers += L"X-AGTR-Signature: " + std::wstring(signature.begin(), signature.end()) + L"\r\n";
    headers += L"X-AGTR-HWID: " + std::wstring(g_szHWID, g_szHWID + strlen(g_szHWID)) + L"\r\n";
    
    BOOL result = WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)jsonData.c_str(), jsonData.length(), jsonData.length(), 0);
    bool success = false;
    
    if (result) {
        result = WinHttpReceiveResponse(hRequest, NULL);
        if (result) {
            char responseBody[4096] = {0};
            DWORD bytesRead = 0;
            WinHttpReadData(hRequest, responseBody, sizeof(responseBody) - 1, &bytesRead);
            
            if (bytesRead > 0) {
                success = true;
                g_bAPIOnline = true;
                g_dwLastSuccessfulSend = GetTickCount();
                g_dwLastDataHash = QuickDataHash(jsonData);
                
                if (strstr(responseBody, "\"action\":\"kick\"")) {
                    Log("!!! KICK !!!");
                    char* reasonStart = strstr(responseBody, "\"reason\":\"");
                    if (reasonStart) {
                        reasonStart += 10;
                        char* reasonEnd = strchr(reasonStart, '"');
                        if (reasonEnd) {
                            char reason[256] = {0};
                            strncpy(reason, reasonStart, min((int)(reasonEnd - reasonStart), 255));
                            char msg[512];
                            sprintf(msg, "AGTR Anti-Cheat\n\n%s", reason);
                            MessageBoxA(NULL, msg, "AGTR Anti-Cheat", MB_OK | MB_ICONERROR);
                            ExitProcess(0);
                        }
                    }
                }
            }
        }
    }
    
    if (!success) {
        g_iFailedRequests++;
        if (g_iFailedRequests >= 3) {
            g_bAPIOnline = false;
        }
        AddToOfflineCache(jsonData);
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return success;
}

// ============================================
// MAIN SCAN
// ============================================
// ============================================
// PERFORMANCE OPTIMIZATION FUNCTIONS (v12.1)
// ============================================

// #26 FPS Monitor - Oyunun FPS'ini tahmin et
void UpdateFPSMonitor() {
    DWORD now = GetTickCount();
    g_iFrameCount++;
    
    if (now - g_dwFPSCheckTime >= FPS_CHECK_INTERVAL) {
        g_fCurrentFPS = (float)g_iFrameCount * 1000.0f / (float)(now - g_dwFPSCheckTime);
        g_iFrameCount = 0;
        g_dwFPSCheckTime = now;
    }
}

bool IsFPSSafe() {
    return g_fCurrentFPS >= MIN_FPS_FOR_SCAN || g_fCurrentFPS > 900.0f; // 999 = henüz ölçülmedi
}

// #28 Game State Awareness
GameState DetectGameState() {
    HWND hwnd = FindWindowA("Valve001", NULL);
    if (!hwnd) return STATE_MENU;
    
    char title[256] = {0};
    GetWindowTextA(hwnd, title, sizeof(title));
    
    // Half-Life window title: "Half-Life" (menu) or "Half-Life - servername" (in game)
    if (strstr(title, " - ") == NULL) {
        return STATE_MENU;
    }
    
    // Loading kontrolü - console veya loading ekranı
    // Bu basit bir tahmin, gerçek loading tespiti zor
    static DWORD lastTitleChange = 0;
    static char lastTitle[256] = {0};
    
    if (strcmp(title, lastTitle) != 0) {
        strcpy(lastTitle, title);
        lastTitleChange = GetTickCount();
        return STATE_LOADING;
    }
    
    // Son 3 saniyede title değiştiyse hala loading olabilir
    if (GetTickCount() - lastTitleChange < 3000) {
        return STATE_LOADING;
    }
    
    return STATE_PLAYING;
}

bool CanDoHeavyWork() {
    // FPS düşükse yapma
    if (!IsFPSSafe()) {
        return false;
    }
    
    // Loading ekranındayken yapabilirsin
    if (g_CurrentGameState == STATE_LOADING) {
        return true;
    }
    
    // Menüdeyken kesinlikle yap
    if (g_CurrentGameState == STATE_MENU) {
        return true;
    }
    
    // Oyundayken dikkatli ol
    if (g_CurrentGameState == STATE_PLAYING) {
        // Son 2 saniyede hasar almışsa veya ateş etmişse yapma
        DWORD now = GetTickCount();
        if (now - g_dwLastDamageTime < 2000) return false;
        if (now - g_dwLastShotTime < 2000) return false;
    }
    
    return true;
}

// #19 Smart Throttling
ScanIntensity CalculateScanIntensity() {
    // Menüde: Deep scan
    if (g_CurrentGameState == STATE_MENU) {
        return SCAN_INTENSITY_DEEP;
    }
    
    // Loading: Normal scan
    if (g_CurrentGameState == STATE_LOADING) {
        return SCAN_INTENSITY_NORMAL;
    }
    
    // FPS düşük: Sadece signature check
    if (!IsFPSSafe()) {
        return SCAN_INTENSITY_LIGHT;
    }
    
    // Normal oyun: Normal scan
    return SCAN_INTENSITY_NORMAL;
}

// #22 Signature-First Check - Hızlı imza kontrolü
int QuickSignatureCheck() {
    int detected = 0;
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32First(hSnap, &pe)) {
        do {
            char lowerName[MAX_PATH];
            strcpy(lowerName, pe.szExeFile);
            _strlwr(lowerName);
            
            for (int i = 0; g_QuickSigs[i].pattern != NULL; i++) {
                if (strstr(lowerName, g_QuickSigs[i].pattern)) {
                    Log("[QUICK] Detected: %s (severity:%d)", 
                        g_QuickSigs[i].name, g_QuickSigs[i].severity);
                    detected++;
                    
                    // Critical severity ise hemen bildir
                    if (g_QuickSigs[i].severity >= 4) {
                        DeferredResult res;
                        res.type = "critical_process";
                        res.name = g_QuickSigs[i].name;
                        res.suspicious = true;
                        res.timestamp = GetTickCount();
                        g_DeferredResults.push_back(res);
                    }
                }
            }
        } while (Process32Next(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    return detected;
}

// #7 Delta Process Scan - Sadece yeni process'leri tara
int DeltaProcessScan() {
    int newProcesses = 0;
    int suspicious = 0;
    
    std::map<DWORD, std::string> currentProcesses;
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32First(hSnap, &pe)) {
        do {
            currentProcesses[pe.th32ProcessID] = pe.szExeFile;
            
            // Bu process daha önce var mıydı?
            if (g_LastProcesses.find(pe.th32ProcessID) == g_LastProcesses.end()) {
                // Yeni process!
                newProcesses++;
                
                char lowerName[MAX_PATH];
                strcpy(lowerName, pe.szExeFile);
                _strlwr(lowerName);
                
                // Şüpheli mi kontrol et
                for (int i = 0; g_SusProc[i] != NULL; i++) {
                    if (strstr(lowerName, g_SusProc[i])) {
                        Log("[DELTA] New suspicious process: %s (PID:%d)", 
                            pe.szExeFile, pe.th32ProcessID);
                        suspicious++;
                        
                        DeferredResult res;
                        res.type = "new_process";
                        res.name = pe.szExeFile;
                        res.suspicious = true;
                        res.timestamp = GetTickCount();
                        g_DeferredResults.push_back(res);
                        break;
                    }
                }
            }
        } while (Process32Next(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    
    // Listeyi güncelle
    g_LastProcesses = currentProcesses;
    
    if (newProcesses > 0) {
        Log("[DELTA] %d new processes, %d suspicious", newProcesses, suspicious);
    }
    
    return suspicious;
}

// #13 Micro-Batch Operations - Parça parça işlem
int MicroBatchProcessScan() {
    int suspicious = 0;
    int scanned = 0;
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    int currentPos = 0;
    
    if (Process32First(hSnap, &pe)) {
        do {
            // Batch pozisyonuna gel
            if (currentPos < g_iProcessBatchPos) {
                currentPos++;
                continue;
            }
            
            // Bu batch'te max BATCH_SIZE_PROCESS tara
            if (scanned >= BATCH_SIZE_PROCESS) {
                break;
            }
            
            char lowerName[MAX_PATH];
            strcpy(lowerName, pe.szExeFile);
            _strlwr(lowerName);
            
            // Whitelist kontrolü
            bool whitelisted = false;
            for (int i = 0; g_WhitelistProc[i] != NULL; i++) {
                if (strstr(lowerName, g_WhitelistProc[i])) {
                    whitelisted = true;
                    break;
                }
            }
            
            if (!whitelisted) {
                for (int i = 0; g_SusProc[i] != NULL; i++) {
                    if (strstr(lowerName, g_SusProc[i])) {
                        suspicious++;
                        break;
                    }
                }
            }
            
            scanned++;
            currentPos++;
            
        } while (Process32Next(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    
    // Sonraki batch için pozisyonu güncelle
    g_iProcessBatchPos = currentPos;
    
    // Liste bittiyse başa dön
    if (scanned < BATCH_SIZE_PROCESS) {
        g_iProcessBatchPos = 0;
    }
    
    return suspicious;
}

// #15 Deferred Reporting - Birikmiş sonuçları gönder
void FlushDeferredResults() {
    if (g_DeferredResults.empty()) return;
    
    DWORD now = GetTickCount();
    if (now - g_dwLastReportTime < DEFERRED_REPORT_INTERVAL) return;
    
    // JSON oluştur
    std::string json = "{\"hwid\":\"";
    json += g_szHWID;
    json += "\",\"type\":\"deferred\",\"results\":[";
    
    bool first = true;
    for (auto& res : g_DeferredResults) {
        if (!first) json += ",";
        json += "{\"type\":\"";
        json += res.type;
        json += "\",\"name\":\"";
        json += res.name;
        json += "\",\"sus\":";
        json += res.suspicious ? "true" : "false";
        json += "}";
        first = false;
    }
    
    json += "]}";
    
    Log("[DEFERRED] Flushing %d results", (int)g_DeferredResults.size());
    
    // Gönder (async olarak)
    // SendToAPI(json, ""); // Basit gönderim
    
    g_DeferredResults.clear();
    g_dwLastReportTime = now;
}

// #3 Menu-Only Deep Scan
void PerformDeepScanIfNeeded() {
    DWORD now = GetTickCount();
    
    // Menüde miyiz?
    if (g_CurrentGameState != STATE_MENU) {
        g_bDeepScanPending = true;
        return;
    }
    
    // Son deep scan'den bu yana yeterli zaman geçti mi?
    if (now - g_dwLastDeepScan < DEEP_SCAN_INTERVAL) {
        return;
    }
    
    // FPS güvenli mi?
    if (!IsFPSSafe()) {
        return;
    }
    
    Log("[DEEP] Starting deep scan (menu mode)...");
    
    // Tüm dosyaları tara
    ScanAllFiles();
    
    // Registry'yi tara
    ScanRegistry();
    
    // Memory pattern scan
    ScanMemoryPatterns();
    
    g_dwLastDeepScan = now;
    g_bDeepScanPending = false;
    
    Log("[DEEP] Deep scan completed");
}

// Optimized scan dispatcher
void DoOptimizedScan() {
    // Game state güncelle
    g_CurrentGameState = DetectGameState();
    
    // Scan intensity hesapla
    g_CurrentIntensity = CalculateScanIntensity();
    
    Log("[PERF] State:%d Intensity:%d FPS:%.1f", 
        g_CurrentGameState, g_CurrentIntensity, g_fCurrentFPS);
    
    switch (g_CurrentIntensity) {
        case SCAN_INTENSITY_NONE:
            // Hiçbir şey yapma
            break;
            
        case SCAN_INTENSITY_LIGHT:
            // Sadece hızlı signature check
            QuickSignatureCheck();
            break;
            
        case SCAN_INTENSITY_NORMAL:
            // Delta scan + signature check
            QuickSignatureCheck();
            if (g_bDeltaScanEnabled) {
                DeltaProcessScan();
            } else {
                MicroBatchProcessScan();
            }
            break;
            
        case SCAN_INTENSITY_DEEP:
            // Tam scan
            PerformDeepScanIfNeeded();
            break;
    }
    
    // Deferred sonuçları gönder
    FlushDeferredResults();
}

void DoScan() {
    Log("=== Starting Scan ===");
    
    // Standard scans
    g_iSusCount = 0;
    if (g_Settings.scan_processes) g_iSusCount += ScanProcesses();
    if (g_Settings.scan_modules) g_iSusCount += ScanModules();
    if (g_Settings.scan_windows) g_iSusCount += ScanWindows();
    if (g_Settings.scan_registry) g_iSusCount += ScanRegistry();
    if (g_Settings.scan_files) g_iSusCount += CheckSusFiles();
    
    // Security checks (#16, #17, #19, #23, #24)
    CheckDLLIntegrity();
    if (CheckDebugger()) {
        Log("!!! DEBUGGER DETECTED !!!");
        g_iSusCount++;
    }
    if (CheckAPIHooks()) {
        Log("!!! API HOOKS DETECTED !!!");
        g_iSusCount++;
    }
    if (CheckSuspiciousDrivers()) {
        Log("!!! SUSPICIOUS DRIVERS DETECTED !!!");
        // Sadece log, sus saymıyoruz (false positive riski)
    }
    CheckVirtualMachine(); // Sadece bilgi amaçlı
    
    // Memory pattern scan (#20) - sadece ilk scan'de yap (performans)
    if (!g_bFirstScanDone) {
        int memPatterns = ScanMemoryPatterns();
        if (memPatterns > 0) {
            Log("!!! %d MEMORY PATTERNS FOUND !!!", memPatterns);
            g_iSusCount += memPatterns;
        }
        g_bFirstScanDone = true;
    }
    
    g_bPassed = (g_iSusCount == 0) && g_bIntegrityOK && !g_bDebuggerDetected && !g_bHooksDetected;
    
    std::string json = BuildJson();
    std::string sig = ComputeSignature(json);
    
    Log("Scan: %s | Sus:%d | Files:%d | Size:%dKB | Cache:%d", 
        g_bPassed ? "CLEAN" : "SUS", g_iSusCount, (int)g_FileCache.size(), 
        (int)(json.length() / 1024), (int)g_HashCache.size());
    
    SendToAPI(json, sig);
}

// ============================================
// SCAN THREAD
// ============================================
DWORD WINAPI ScanThread(LPVOID) {
    // ============================================
    // #12 LOW PRIORITY THREAD - Oyuna etki etmez
    // ============================================
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
    
    // Tek CPU core kullan (opsiyonel, çok agresif olabilir)
    // SetThreadAffinityMask(GetCurrentThread(), 1);
    
    // İlk başlatma gecikmesi
    Sleep(10000);
    
    Log("=== AGTR v%s (winmm) Performance Edition ===", AGTR_VERSION);
    Log("[PERF] Thread priority: LOWEST");
    
    GenHWID();
    ComputeDLLHash();
    
    // #16 - İlk integrity check
    CheckDLLIntegrity();
    
    if (!FetchSettings()) {
        Log("Using default settings - API may be offline");
        g_bAPIOnline = false;
    }
    
    SendHeartbeat();
    
    // İlk scan - menüdeyken tam tarama yap
    g_CurrentGameState = DetectGameState();
    if (g_CurrentGameState == STATE_MENU) {
        Log("[PERF] Initial deep scan (menu mode)");
        if (g_Settings.scan_enabled) {
            ScanAllFiles();
            DoScan();
            g_dwLastScan = GetTickCount();
            g_dwLastDeepScan = GetTickCount();
        }
    } else {
        // Oyundayken başladıysa hafif başla
        Log("[PERF] Initial quick scan (in-game mode)");
        QuickSignatureCheck();
        g_dwLastScan = GetTickCount();
    }
    
    // FPS monitor başlat
    g_dwFPSCheckTime = GetTickCount();
    
    while (g_bRunning) {
        // #12 - Düşük CPU kullanımı için uzun sleep
        Sleep(1000);
        
        DWORD now = GetTickCount();
        
        // #26 - FPS Monitor güncelle (her saniye)
        UpdateFPSMonitor();
        
        // #28 - Game State güncelle
        g_CurrentGameState = DetectGameState();
        
        // #2 - Adaptive Heartbeat: serverdeyken 30sn, menüdeyken 120sn
        DWORD heartbeatInterval = GetHeartbeatInterval();
        if (now - g_dwLastHeartbeat >= heartbeatInterval) {
            SendHeartbeat();
        }
        
        // #19 - Smart Throttling: Duruma göre scan yap
        g_CurrentIntensity = CalculateScanIntensity();
        
        // Scan interval check
        DWORD scanInterval = (DWORD)g_Settings.scan_interval;
        
        // #19 - Intensity'ye göre interval ayarla
        if (g_CurrentIntensity == SCAN_INTENSITY_LIGHT) {
            scanInterval = scanInterval / 2;  // Hafif scan daha sık
        } else if (g_CurrentIntensity == SCAN_INTENSITY_DEEP) {
            scanInterval = scanInterval * 2;  // Derin scan daha seyrek
        }
        
        if (now - g_dwLastScan >= scanInterval) {
            if (!g_Settings.scan_enabled) {
                g_dwLastScan = now;
                continue;
            }
            
            // #28 - Game State Awareness: Ağır iş yapılabilir mi?
            if (!CanDoHeavyWork() && g_CurrentIntensity >= SCAN_INTENSITY_NORMAL) {
                // FPS düşük veya savaşta, hafif scan yap
                Log("[PERF] Downgrading scan (FPS:%.1f State:%d)", 
                    g_fCurrentFPS, g_CurrentGameState);
                g_CurrentIntensity = SCAN_INTENSITY_LIGHT;
            }
            
            // #22 - Signature-First: Önce hızlı kontrol
            int quickHits = QuickSignatureCheck();
            
            if (quickHits > 0) {
                // Şüpheli şey bulundu, tam scan yap
                Log("[PERF] Quick check found %d hits, doing full scan", quickHits);
                DoScan();
            } else {
                // Temiz görünüyor, intensity'ye göre devam et
                DoOptimizedScan();
            }
            
            // #15 - Deferred sonuçları gönder
            FlushDeferredResults();
            
            g_dwLastScan = now;
        }
        
        // #13 - Micro-Batch: Her 5 saniyede bir parça işlem
        if (now % 5000 < 1000) {
            if (g_bDeltaScanEnabled) {
                DeltaProcessScan();
            } else {
                MicroBatchProcessScan();
            }
        }
        
        // #3 - Menu'de deep scan kontrolü
        if (g_CurrentGameState == STATE_MENU && g_bDeepScanPending) {
            PerformDeepScanIfNeeded();
        }
    }
    
    return 0;
}

// ============================================
// EXPORTED WINMM FUNCTIONS
// ============================================
extern "C" {

__declspec(dllexport) DWORD WINAPI timeGetTime(void) {
    if (!LoadOriginal() || !o_TimeGetTime) return GetTickCount();
    return o_TimeGetTime();
}

__declspec(dllexport) MMRESULT WINAPI timeBeginPeriod(UINT uPeriod) {
    if (!LoadOriginal() || !o_TimeBeginPeriod) return MMSYSERR_ERROR;
    return o_TimeBeginPeriod(uPeriod);
}

__declspec(dllexport) MMRESULT WINAPI timeEndPeriod(UINT uPeriod) {
    if (!LoadOriginal() || !o_TimeEndPeriod) return MMSYSERR_ERROR;
    return o_TimeEndPeriod(uPeriod);
}

__declspec(dllexport) MMRESULT WINAPI timeGetDevCaps(LPTIMECAPS ptc, UINT cbtc) {
    if (!LoadOriginal() || !o_TimeGetDevCaps) return MMSYSERR_ERROR;
    return o_TimeGetDevCaps(ptc, cbtc);
}

__declspec(dllexport) MMRESULT WINAPI timeGetSystemTime(LPMMTIME pmmt, UINT cbmmt) {
    if (!LoadOriginal() || !o_TimeGetSystemTime) return MMSYSERR_ERROR;
    return o_TimeGetSystemTime(pmmt, cbmmt);
}

__declspec(dllexport) MMRESULT WINAPI timeSetEvent(UINT uDelay, UINT uResolution, LPTIMECALLBACK fptc, DWORD_PTR dwUser, UINT fuEvent) {
    if (!LoadOriginal() || !o_TimeSetEvent) return 0;
    return o_TimeSetEvent(uDelay, uResolution, fptc, dwUser, fuEvent);
}

__declspec(dllexport) MMRESULT WINAPI timeKillEvent(UINT uTimerID) {
    if (!LoadOriginal() || !o_TimeKillEvent) return MMSYSERR_ERROR;
    return o_TimeKillEvent(uTimerID);
}

__declspec(dllexport) MMRESULT WINAPI waveOutOpen(LPHWAVEOUT phwo, UINT uDeviceID, LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen) {
    if (!LoadOriginal() || !o_WaveOutOpen) return MMSYSERR_ERROR;
    return o_WaveOutOpen(phwo, uDeviceID, pwfx, dwCallback, dwInstance, fdwOpen);
}

__declspec(dllexport) MMRESULT WINAPI waveOutClose(HWAVEOUT hwo) {
    if (!o_WaveOutClose) return MMSYSERR_ERROR;
    return o_WaveOutClose(hwo);
}

__declspec(dllexport) MMRESULT WINAPI waveOutWrite(HWAVEOUT hwo, LPWAVEHDR pwh, UINT cbwh) {
    if (!o_WaveOutWrite) return MMSYSERR_ERROR;
    return o_WaveOutWrite(hwo, pwh, cbwh);
}

__declspec(dllexport) MMRESULT WINAPI waveOutPrepareHeader(HWAVEOUT hwo, LPWAVEHDR pwh, UINT cbwh) {
    if (!o_WaveOutPrepareHeader) return MMSYSERR_ERROR;
    return o_WaveOutPrepareHeader(hwo, pwh, cbwh);
}

__declspec(dllexport) MMRESULT WINAPI waveOutUnprepareHeader(HWAVEOUT hwo, LPWAVEHDR pwh, UINT cbwh) {
    if (!o_WaveOutUnprepareHeader) return MMSYSERR_ERROR;
    return o_WaveOutUnprepareHeader(hwo, pwh, cbwh);
}

__declspec(dllexport) MMRESULT WINAPI waveOutReset(HWAVEOUT hwo) { if (!o_WaveOutReset) return MMSYSERR_ERROR; return o_WaveOutReset(hwo); }
__declspec(dllexport) MMRESULT WINAPI waveOutPause(HWAVEOUT hwo) { if (!o_WaveOutPause) return MMSYSERR_ERROR; return o_WaveOutPause(hwo); }
__declspec(dllexport) MMRESULT WINAPI waveOutRestart(HWAVEOUT hwo) { if (!o_WaveOutRestart) return MMSYSERR_ERROR; return o_WaveOutRestart(hwo); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetPosition(HWAVEOUT hwo, LPMMTIME pmmt, UINT cbmmt) { if (!o_WaveOutGetPosition) return MMSYSERR_ERROR; return o_WaveOutGetPosition(hwo, pmmt, cbmmt); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetDevCapsA(UINT uDeviceID, LPWAVEOUTCAPSA pwoc, UINT cbwoc) { if (!LoadOriginal() || !o_WaveOutGetDevCapsA) return MMSYSERR_ERROR; return o_WaveOutGetDevCapsA(uDeviceID, pwoc, cbwoc); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetDevCapsW(UINT uDeviceID, LPWAVEOUTCAPSW pwoc, UINT cbwoc) { if (!LoadOriginal() || !o_WaveOutGetDevCapsW) return MMSYSERR_ERROR; return o_WaveOutGetDevCapsW(uDeviceID, pwoc, cbwoc); }
__declspec(dllexport) UINT WINAPI waveOutGetNumDevs(void) { if (!LoadOriginal() || !o_WaveOutGetNumDevs) return 0; return o_WaveOutGetNumDevs(); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetVolume(HWAVEOUT hwo, LPDWORD pdwVolume) { if (!o_WaveOutGetVolume) return MMSYSERR_ERROR; return o_WaveOutGetVolume(hwo, pdwVolume); }
__declspec(dllexport) MMRESULT WINAPI waveOutSetVolume(HWAVEOUT hwo, DWORD dwVolume) { if (!o_WaveOutSetVolume) return MMSYSERR_ERROR; return o_WaveOutSetVolume(hwo, dwVolume); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetErrorTextA(MMRESULT mmrError, LPSTR pszText, UINT cchText) { if (!LoadOriginal() || !o_WaveOutGetErrorTextA) return MMSYSERR_ERROR; return o_WaveOutGetErrorTextA(mmrError, pszText, cchText); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetErrorTextW(MMRESULT mmrError, LPWSTR pszText, UINT cchText) { if (!LoadOriginal() || !o_WaveOutGetErrorTextW) return MMSYSERR_ERROR; return o_WaveOutGetErrorTextW(mmrError, pszText, cchText); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetID(HWAVEOUT hwo, LPUINT puDeviceID) { if (!o_WaveOutGetID) return MMSYSERR_ERROR; return o_WaveOutGetID(hwo, puDeviceID); }
__declspec(dllexport) MMRESULT WINAPI waveOutMessage(HWAVEOUT hwo, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2) { if (!o_WaveOutMessage) return MMSYSERR_ERROR; return o_WaveOutMessage(hwo, uMsg, dw1, dw2); }
__declspec(dllexport) MMRESULT WINAPI waveOutBreakLoop(HWAVEOUT hwo) { if (!o_WaveOutBreakLoop) return MMSYSERR_ERROR; return o_WaveOutBreakLoop(hwo); }

__declspec(dllexport) MMRESULT WINAPI waveInOpen(LPHWAVEIN phwi, UINT uDeviceID, LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen) { if (!LoadOriginal() || !o_WaveInOpen) return MMSYSERR_ERROR; return o_WaveInOpen(phwi, uDeviceID, pwfx, dwCallback, dwInstance, fdwOpen); }
__declspec(dllexport) MMRESULT WINAPI waveInClose(HWAVEIN hwi) { if (!o_WaveInClose) return MMSYSERR_ERROR; return o_WaveInClose(hwi); }
__declspec(dllexport) UINT WINAPI waveInGetNumDevs(void) { if (!LoadOriginal() || !o_WaveInGetNumDevs) return 0; return o_WaveInGetNumDevs(); }
__declspec(dllexport) MMRESULT WINAPI waveInGetDevCapsA(UINT uDeviceID, LPWAVEINCAPSA pwic, UINT cbwic) { if (!LoadOriginal() || !o_WaveInGetDevCapsA) return MMSYSERR_ERROR; return o_WaveInGetDevCapsA(uDeviceID, pwic, cbwic); }
__declspec(dllexport) MMRESULT WINAPI waveInGetDevCapsW(UINT uDeviceID, LPWAVEINCAPSW pwic, UINT cbwic) { if (!LoadOriginal() || !o_WaveInGetDevCapsW) return MMSYSERR_ERROR; return o_WaveInGetDevCapsW(uDeviceID, pwic, cbwic); }
__declspec(dllexport) MMRESULT WINAPI waveInStart(HWAVEIN hwi) { if (!o_WaveInStart) return MMSYSERR_ERROR; return o_WaveInStart(hwi); }
__declspec(dllexport) MMRESULT WINAPI waveInStop(HWAVEIN hwi) { if (!o_WaveInStop) return MMSYSERR_ERROR; return o_WaveInStop(hwi); }
__declspec(dllexport) MMRESULT WINAPI waveInReset(HWAVEIN hwi) { if (!o_WaveInReset) return MMSYSERR_ERROR; return o_WaveInReset(hwi); }
__declspec(dllexport) MMRESULT WINAPI waveInPrepareHeader(HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh) { if (!o_WaveInPrepareHeader) return MMSYSERR_ERROR; return o_WaveInPrepareHeader(hwi, pwh, cbwh); }
__declspec(dllexport) MMRESULT WINAPI waveInUnprepareHeader(HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh) { if (!o_WaveInUnprepareHeader) return MMSYSERR_ERROR; return o_WaveInUnprepareHeader(hwi, pwh, cbwh); }
__declspec(dllexport) MMRESULT WINAPI waveInAddBuffer(HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh) { if (!o_WaveInAddBuffer) return MMSYSERR_ERROR; return o_WaveInAddBuffer(hwi, pwh, cbwh); }
__declspec(dllexport) MMRESULT WINAPI waveInGetPosition(HWAVEIN hwi, LPMMTIME pmmt, UINT cbmmt) { if (!o_WaveInGetPosition) return MMSYSERR_ERROR; return o_WaveInGetPosition(hwi, pmmt, cbmmt); }
__declspec(dllexport) MMRESULT WINAPI waveInGetID(HWAVEIN hwi, LPUINT puDeviceID) { if (!o_WaveInGetID) return MMSYSERR_ERROR; return o_WaveInGetID(hwi, puDeviceID); }
__declspec(dllexport) MMRESULT WINAPI waveInGetErrorTextA(MMRESULT mmrError, LPSTR pszText, UINT cchText) { if (!LoadOriginal() || !o_WaveInGetErrorTextA) return MMSYSERR_ERROR; return o_WaveInGetErrorTextA(mmrError, pszText, cchText); }
__declspec(dllexport) MMRESULT WINAPI waveInGetErrorTextW(MMRESULT mmrError, LPWSTR pszText, UINT cchText) { if (!LoadOriginal() || !o_WaveInGetErrorTextW) return MMSYSERR_ERROR; return o_WaveInGetErrorTextW(mmrError, pszText, cchText); }
__declspec(dllexport) MMRESULT WINAPI waveInMessage(HWAVEIN hwi, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2) { if (!o_WaveInMessage) return MMSYSERR_ERROR; return o_WaveInMessage(hwi, uMsg, dw1, dw2); }

__declspec(dllexport) BOOL WINAPI PlaySoundA(LPCSTR pszSound, HMODULE hmod, DWORD fdwSound) { if (!LoadOriginal() || !o_PlaySoundA) return FALSE; return o_PlaySoundA(pszSound, hmod, fdwSound); }
__declspec(dllexport) BOOL WINAPI PlaySoundW(LPCWSTR pszSound, HMODULE hmod, DWORD fdwSound) { if (!LoadOriginal() || !o_PlaySoundW) return FALSE; return o_PlaySoundW(pszSound, hmod, fdwSound); }
__declspec(dllexport) BOOL WINAPI sndPlaySoundA(LPCSTR pszSound, UINT fuSound) { if (!LoadOriginal() || !o_SndPlaySoundA) return FALSE; return o_SndPlaySoundA(pszSound, fuSound); }
__declspec(dllexport) BOOL WINAPI sndPlaySoundW(LPCWSTR pszSound, UINT fuSound) { if (!LoadOriginal() || !o_SndPlaySoundW) return FALSE; return o_SndPlaySoundW(pszSound, fuSound); }

__declspec(dllexport) UINT WINAPI joyGetNumDevs(void) { if (!LoadOriginal() || !o_JoyGetNumDevs) return 0; return o_JoyGetNumDevs(); }
__declspec(dllexport) MMRESULT WINAPI joyGetDevCapsA(UINT uJoyID, LPJOYCAPSA pjc, UINT cbjc) { if (!LoadOriginal() || !o_JoyGetDevCapsA) return MMSYSERR_ERROR; return o_JoyGetDevCapsA(uJoyID, pjc, cbjc); }
__declspec(dllexport) MMRESULT WINAPI joyGetDevCapsW(UINT uJoyID, LPJOYCAPSW pjc, UINT cbjc) { if (!LoadOriginal() || !o_JoyGetDevCapsW) return MMSYSERR_ERROR; return o_JoyGetDevCapsW(uJoyID, pjc, cbjc); }
__declspec(dllexport) MMRESULT WINAPI joyGetPos(UINT uJoyID, LPJOYINFO pji) { if (!LoadOriginal() || !o_JoyGetPos) return MMSYSERR_ERROR; return o_JoyGetPos(uJoyID, pji); }
__declspec(dllexport) MMRESULT WINAPI joyGetPosEx(UINT uJoyID, LPJOYINFOEX pji) { if (!LoadOriginal() || !o_JoyGetPosEx) return MMSYSERR_ERROR; return o_JoyGetPosEx(uJoyID, pji); }
__declspec(dllexport) MMRESULT WINAPI joyGetThreshold(UINT uJoyID, LPUINT puThreshold) { if (!LoadOriginal() || !o_JoyGetThreshold) return MMSYSERR_ERROR; return o_JoyGetThreshold(uJoyID, puThreshold); }
__declspec(dllexport) MMRESULT WINAPI joySetThreshold(UINT uJoyID, UINT uThreshold) { if (!LoadOriginal() || !o_JoySetThreshold) return MMSYSERR_ERROR; return o_JoySetThreshold(uJoyID, uThreshold); }
__declspec(dllexport) MMRESULT WINAPI joySetCapture(HWND hwnd, UINT uJoyID, UINT uPeriod, BOOL fChanged) { if (!LoadOriginal() || !o_JoySetCapture) return MMSYSERR_ERROR; return o_JoySetCapture(hwnd, uJoyID, uPeriod, fChanged); }
__declspec(dllexport) MMRESULT WINAPI joyReleaseCapture(UINT uJoyID) { if (!LoadOriginal() || !o_JoyReleaseCapture) return MMSYSERR_ERROR; return o_JoyReleaseCapture(uJoyID); }

__declspec(dllexport) UINT WINAPI midiOutGetNumDevs(void) { if (!LoadOriginal() || !o_MidiOutGetNumDevs) return 0; return o_MidiOutGetNumDevs(); }
__declspec(dllexport) MMRESULT WINAPI midiOutGetDevCapsA(UINT uDeviceID, LPMIDIOUTCAPSA pmoc, UINT cbmoc) { if (!LoadOriginal() || !o_MidiOutGetDevCapsA) return MMSYSERR_ERROR; return o_MidiOutGetDevCapsA(uDeviceID, pmoc, cbmoc); }
__declspec(dllexport) MMRESULT WINAPI midiOutGetDevCapsW(UINT uDeviceID, LPMIDIOUTCAPSW pmoc, UINT cbmoc) { if (!LoadOriginal() || !o_MidiOutGetDevCapsW) return MMSYSERR_ERROR; return o_MidiOutGetDevCapsW(uDeviceID, pmoc, cbmoc); }
__declspec(dllexport) MMRESULT WINAPI midiOutOpen(LPHMIDIOUT phmo, UINT uDeviceID, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen) { if (!LoadOriginal() || !o_MidiOutOpen) return MMSYSERR_ERROR; return o_MidiOutOpen(phmo, uDeviceID, dwCallback, dwInstance, fdwOpen); }
__declspec(dllexport) MMRESULT WINAPI midiOutClose(HMIDIOUT hmo) { if (!o_MidiOutClose) return MMSYSERR_ERROR; return o_MidiOutClose(hmo); }
__declspec(dllexport) MMRESULT WINAPI midiOutShortMsg(HMIDIOUT hmo, DWORD dwMsg) { if (!o_MidiOutShortMsg) return MMSYSERR_ERROR; return o_MidiOutShortMsg(hmo, dwMsg); }
__declspec(dllexport) MMRESULT WINAPI midiOutLongMsg(HMIDIOUT hmo, LPMIDIHDR pmh, UINT cbmh) { if (!o_MidiOutLongMsg) return MMSYSERR_ERROR; return o_MidiOutLongMsg(hmo, pmh, cbmh); }
__declspec(dllexport) MMRESULT WINAPI midiOutReset(HMIDIOUT hmo) { if (!o_MidiOutReset) return MMSYSERR_ERROR; return o_MidiOutReset(hmo); }
__declspec(dllexport) MMRESULT WINAPI midiOutPrepareHeader(HMIDIOUT hmo, LPMIDIHDR pmh, UINT cbmh) { if (!o_MidiOutPrepareHeader) return MMSYSERR_ERROR; return o_MidiOutPrepareHeader(hmo, pmh, cbmh); }
__declspec(dllexport) MMRESULT WINAPI midiOutUnprepareHeader(HMIDIOUT hmo, LPMIDIHDR pmh, UINT cbmh) { if (!o_MidiOutUnprepareHeader) return MMSYSERR_ERROR; return o_MidiOutUnprepareHeader(hmo, pmh, cbmh); }

__declspec(dllexport) UINT WINAPI auxGetNumDevs(void) { if (!LoadOriginal() || !o_AuxGetNumDevs) return 0; return o_AuxGetNumDevs(); }
__declspec(dllexport) MMRESULT WINAPI auxGetDevCapsA(UINT uDeviceID, LPAUXCAPSA pac, UINT cbac) { if (!LoadOriginal() || !o_AuxGetDevCapsA) return MMSYSERR_ERROR; return o_AuxGetDevCapsA(uDeviceID, pac, cbac); }
__declspec(dllexport) MMRESULT WINAPI auxGetDevCapsW(UINT uDeviceID, LPAUXCAPSW pac, UINT cbac) { if (!LoadOriginal() || !o_AuxGetDevCapsW) return MMSYSERR_ERROR; return o_AuxGetDevCapsW(uDeviceID, pac, cbac); }
__declspec(dllexport) MMRESULT WINAPI auxGetVolume(UINT uDeviceID, LPDWORD pdwVolume) { if (!LoadOriginal() || !o_AuxGetVolume) return MMSYSERR_ERROR; return o_AuxGetVolume(uDeviceID, pdwVolume); }
__declspec(dllexport) MMRESULT WINAPI auxSetVolume(UINT uDeviceID, DWORD dwVolume) { if (!LoadOriginal() || !o_AuxSetVolume) return MMSYSERR_ERROR; return o_AuxSetVolume(uDeviceID, dwVolume); }
__declspec(dllexport) MMRESULT WINAPI auxOutMessage(UINT uDeviceID, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2) { if (!LoadOriginal() || !o_AuxOutMessage) return MMSYSERR_ERROR; return o_AuxOutMessage(uDeviceID, uMsg, dw1, dw2); }

__declspec(dllexport) UINT WINAPI mixerGetNumDevs(void) { if (!LoadOriginal() || !o_MixerGetNumDevs) return 0; return o_MixerGetNumDevs(); }
__declspec(dllexport) MMRESULT WINAPI mixerOpen(LPHMIXER phmx, UINT uMxId, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen) { if (!LoadOriginal() || !o_MixerOpen) return MMSYSERR_ERROR; return o_MixerOpen(phmx, uMxId, dwCallback, dwInstance, fdwOpen); }
__declspec(dllexport) MMRESULT WINAPI mixerClose(HMIXER hmx) { if (!o_MixerClose) return MMSYSERR_ERROR; return o_MixerClose(hmx); }
__declspec(dllexport) MMRESULT WINAPI mixerGetDevCapsA(UINT uMxId, LPMIXERCAPSA pmxcaps, UINT cbmxcaps) { if (!LoadOriginal() || !o_MixerGetDevCapsA) return MMSYSERR_ERROR; return o_MixerGetDevCapsA(uMxId, pmxcaps, cbmxcaps); }
__declspec(dllexport) MMRESULT WINAPI mixerGetDevCapsW(UINT uMxId, LPMIXERCAPSW pmxcaps, UINT cbmxcaps) { if (!LoadOriginal() || !o_MixerGetDevCapsW) return MMSYSERR_ERROR; return o_MixerGetDevCapsW(uMxId, pmxcaps, cbmxcaps); }
__declspec(dllexport) MMRESULT WINAPI mixerGetLineInfoA(HMIXEROBJ hmxobj, LPMIXERLINEA pmxl, DWORD fdwInfo) { if (!LoadOriginal() || !o_MixerGetLineInfoA) return MMSYSERR_ERROR; return o_MixerGetLineInfoA(hmxobj, pmxl, fdwInfo); }
__declspec(dllexport) MMRESULT WINAPI mixerGetLineInfoW(HMIXEROBJ hmxobj, LPMIXERLINEW pmxl, DWORD fdwInfo) { if (!LoadOriginal() || !o_MixerGetLineInfoW) return MMSYSERR_ERROR; return o_MixerGetLineInfoW(hmxobj, pmxl, fdwInfo); }
__declspec(dllexport) MMRESULT WINAPI mixerGetLineControlsA(HMIXEROBJ hmxobj, LPMIXERLINECONTROLSA pmxlc, DWORD fdwControls) { if (!LoadOriginal() || !o_MixerGetLineControlsA) return MMSYSERR_ERROR; return o_MixerGetLineControlsA(hmxobj, pmxlc, fdwControls); }
__declspec(dllexport) MMRESULT WINAPI mixerGetLineControlsW(HMIXEROBJ hmxobj, LPMIXERLINECONTROLSW pmxlc, DWORD fdwControls) { if (!LoadOriginal() || !o_MixerGetLineControlsW) return MMSYSERR_ERROR; return o_MixerGetLineControlsW(hmxobj, pmxlc, fdwControls); }
__declspec(dllexport) MMRESULT WINAPI mixerGetControlDetailsA(HMIXEROBJ hmxobj, LPMIXERCONTROLDETAILS pmxcd, DWORD fdwDetails) { if (!LoadOriginal() || !o_MixerGetControlDetailsA) return MMSYSERR_ERROR; return o_MixerGetControlDetailsA(hmxobj, pmxcd, fdwDetails); }
__declspec(dllexport) MMRESULT WINAPI mixerGetControlDetailsW(HMIXEROBJ hmxobj, LPMIXERCONTROLDETAILS pmxcd, DWORD fdwDetails) { if (!LoadOriginal() || !o_MixerGetControlDetailsW) return MMSYSERR_ERROR; return o_MixerGetControlDetailsW(hmxobj, pmxcd, fdwDetails); }
__declspec(dllexport) MMRESULT WINAPI mixerSetControlDetails(HMIXEROBJ hmxobj, LPMIXERCONTROLDETAILS pmxcd, DWORD fdwDetails) { if (!LoadOriginal() || !o_MixerSetControlDetails) return MMSYSERR_ERROR; return o_MixerSetControlDetails(hmxobj, pmxcd, fdwDetails); }
__declspec(dllexport) MMRESULT WINAPI mixerGetID(HMIXEROBJ hmxobj, PUINT puMxId, DWORD fdwId) { if (!LoadOriginal() || !o_MixerGetID) return MMSYSERR_ERROR; return o_MixerGetID(hmxobj, puMxId, fdwId); }
__declspec(dllexport) DWORD WINAPI mixerMessage(HMIXER hmx, UINT uMsg, DWORD_PTR dwParam1, DWORD_PTR dwParam2) { if (!LoadOriginal() || !o_MixerMessage) return MMSYSERR_ERROR; return o_MixerMessage(hmx, uMsg, dwParam1, dwParam2); }

__declspec(dllexport) MCIERROR WINAPI mciSendCommandA(MCIDEVICEID mciId, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2) { if (!LoadOriginal() || !o_MciSendCommandA) return MCIERR_DEVICE_NOT_INSTALLED; return o_MciSendCommandA(mciId, uMsg, dw1, dw2); }
__declspec(dllexport) MCIERROR WINAPI mciSendCommandW(MCIDEVICEID mciId, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2) { if (!LoadOriginal() || !o_MciSendCommandW) return MCIERR_DEVICE_NOT_INSTALLED; return o_MciSendCommandW(mciId, uMsg, dw1, dw2); }
__declspec(dllexport) MCIERROR WINAPI mciSendStringA(LPCSTR lpstrCommand, LPSTR lpstrReturnString, UINT uReturnLength, HWND hwndCallback) { if (!LoadOriginal() || !o_MciSendStringA) return MCIERR_DEVICE_NOT_INSTALLED; return o_MciSendStringA(lpstrCommand, lpstrReturnString, uReturnLength, hwndCallback); }
__declspec(dllexport) MCIERROR WINAPI mciSendStringW(LPCWSTR lpstrCommand, LPWSTR lpstrReturnString, UINT uReturnLength, HWND hwndCallback) { if (!LoadOriginal() || !o_MciSendStringW) return MCIERR_DEVICE_NOT_INSTALLED; return o_MciSendStringW(lpstrCommand, lpstrReturnString, uReturnLength, hwndCallback); }
__declspec(dllexport) BOOL WINAPI mciGetErrorStringA(MCIERROR mcierr, LPSTR pszText, UINT cchText) { if (!LoadOriginal() || !o_MciGetErrorStringA) return FALSE; return o_MciGetErrorStringA(mcierr, pszText, cchText); }
__declspec(dllexport) BOOL WINAPI mciGetErrorStringW(MCIERROR mcierr, LPWSTR pszText, UINT cchText) { if (!LoadOriginal() || !o_MciGetErrorStringW) return FALSE; return o_MciGetErrorStringW(mcierr, pszText, cchText); }
__declspec(dllexport) MCIDEVICEID WINAPI mciGetDeviceIDA(LPCSTR pszDevice) { if (!LoadOriginal() || !o_MciGetDeviceIDA) return 0; return o_MciGetDeviceIDA(pszDevice); }
__declspec(dllexport) MCIDEVICEID WINAPI mciGetDeviceIDW(LPCWSTR pszDevice) { if (!LoadOriginal() || !o_MciGetDeviceIDW) return 0; return o_MciGetDeviceIDW(pszDevice); }
__declspec(dllexport) MCIDEVICEID WINAPI mciGetDeviceIDFromElementIDA(DWORD dwElementID, LPCSTR lpstrType) { if (!LoadOriginal() || !o_MciGetDeviceIDFromElementIDA) return 0; return o_MciGetDeviceIDFromElementIDA(dwElementID, lpstrType); }
__declspec(dllexport) MCIDEVICEID WINAPI mciGetDeviceIDFromElementIDW(DWORD dwElementID, LPCWSTR lpstrType) { if (!LoadOriginal() || !o_MciGetDeviceIDFromElementIDW) return 0; return o_MciGetDeviceIDFromElementIDW(dwElementID, lpstrType); }
__declspec(dllexport) BOOL WINAPI mciSetYieldProc(MCIDEVICEID mciId, YIELDPROC fpYieldProc, DWORD dwYieldData) { if (!LoadOriginal() || !o_MciSetYieldProc) return FALSE; return o_MciSetYieldProc(mciId, fpYieldProc, dwYieldData); }
__declspec(dllexport) YIELDPROC WINAPI mciGetYieldProc(MCIDEVICEID mciId, LPDWORD pdwYieldData) { if (!LoadOriginal() || !o_MciGetYieldProc) return NULL; return o_MciGetYieldProc(mciId, pdwYieldData); }
__declspec(dllexport) HTASK WINAPI mciGetCreatorTask(MCIDEVICEID mciId) { if (!LoadOriginal() || !o_MciGetCreatorTask) return NULL; return o_MciGetCreatorTask(mciId); }
__declspec(dllexport) BOOL WINAPI mciExecute(LPCSTR pszCommand) { if (!LoadOriginal() || !o_MciExecute) return FALSE; return o_MciExecute(pszCommand); }

__declspec(dllexport) HMMIO WINAPI mmioOpenA(LPSTR pszFileName, LPMMIOINFO pmmioinfo, DWORD fdwOpen) { if (!LoadOriginal() || !o_MmioOpenA) return NULL; return o_MmioOpenA(pszFileName, pmmioinfo, fdwOpen); }
__declspec(dllexport) HMMIO WINAPI mmioOpenW(LPWSTR pszFileName, LPMMIOINFO pmmioinfo, DWORD fdwOpen) { if (!LoadOriginal() || !o_MmioOpenW) return NULL; return o_MmioOpenW(pszFileName, pmmioinfo, fdwOpen); }
__declspec(dllexport) MMRESULT WINAPI mmioClose(HMMIO hmmio, UINT fuClose) { if (!o_MmioClose) return MMSYSERR_ERROR; return o_MmioClose(hmmio, fuClose); }
__declspec(dllexport) LONG WINAPI mmioRead(HMMIO hmmio, HPSTR pch, LONG cch) { if (!o_MmioRead) return -1; return o_MmioRead(hmmio, pch, cch); }
__declspec(dllexport) LONG WINAPI mmioWrite(HMMIO hmmio, const char* pch, LONG cch) { if (!o_MmioWrite) return -1; return o_MmioWrite(hmmio, pch, cch); }
__declspec(dllexport) LONG WINAPI mmioSeek(HMMIO hmmio, LONG lOffset, int iOrigin) { if (!o_MmioSeek) return -1; return o_MmioSeek(hmmio, lOffset, iOrigin); }
__declspec(dllexport) MMRESULT WINAPI mmioGetInfo(HMMIO hmmio, LPMMIOINFO pmmioinfo, UINT fuInfo) { if (!o_MmioGetInfo) return MMSYSERR_ERROR; return o_MmioGetInfo(hmmio, pmmioinfo, fuInfo); }
__declspec(dllexport) MMRESULT WINAPI mmioSetInfo(HMMIO hmmio, LPCMMIOINFO pmmioinfo, UINT fuInfo) { if (!o_MmioSetInfo) return MMSYSERR_ERROR; return o_MmioSetInfo(hmmio, pmmioinfo, fuInfo); }
__declspec(dllexport) MMRESULT WINAPI mmioSetBuffer(HMMIO hmmio, LPSTR pchBuffer, LONG cchBuffer, UINT fuBuffer) { if (!o_MmioSetBuffer) return MMSYSERR_ERROR; return o_MmioSetBuffer(hmmio, pchBuffer, cchBuffer, fuBuffer); }
__declspec(dllexport) MMRESULT WINAPI mmioFlush(HMMIO hmmio, UINT fuFlush) { if (!o_MmioFlush) return MMSYSERR_ERROR; return o_MmioFlush(hmmio, fuFlush); }
__declspec(dllexport) MMRESULT WINAPI mmioAdvance(HMMIO hmmio, LPMMIOINFO pmmioinfo, UINT fuAdvance) { if (!o_MmioAdvance) return MMSYSERR_ERROR; return o_MmioAdvance(hmmio, pmmioinfo, fuAdvance); }
__declspec(dllexport) LPMMIOPROC WINAPI mmioInstallIOProcA(FOURCC fccIOProc, LPMMIOPROC pIOProc, DWORD dwFlags) { if (!LoadOriginal() || !o_MmioInstallIOProcA) return NULL; return o_MmioInstallIOProcA(fccIOProc, pIOProc, dwFlags); }
__declspec(dllexport) LPMMIOPROC WINAPI mmioInstallIOProcW(FOURCC fccIOProc, LPMMIOPROC pIOProc, DWORD dwFlags) { if (!LoadOriginal() || !o_MmioInstallIOProcW) return NULL; return o_MmioInstallIOProcW(fccIOProc, pIOProc, dwFlags); }
__declspec(dllexport) FOURCC WINAPI mmioStringToFOURCCA(LPCSTR sz, UINT uFlags) { if (!LoadOriginal() || !o_MmioStringToFOURCCA) return 0; return o_MmioStringToFOURCCA(sz, uFlags); }
__declspec(dllexport) FOURCC WINAPI mmioStringToFOURCCW(LPCWSTR sz, UINT uFlags) { if (!LoadOriginal() || !o_MmioStringToFOURCCW) return 0; return o_MmioStringToFOURCCW(sz, uFlags); }
__declspec(dllexport) MMRESULT WINAPI mmioDescend(HMMIO hmmio, LPMMCKINFO pmmcki, const MMCKINFO* pmmckiParent, UINT fuDescend) { if (!o_MmioDescend) return MMSYSERR_ERROR; return o_MmioDescend(hmmio, pmmcki, pmmckiParent, fuDescend); }
__declspec(dllexport) MMRESULT WINAPI mmioAscend(HMMIO hmmio, LPMMCKINFO pmmcki, UINT fuAscend) { if (!o_MmioAscend) return MMSYSERR_ERROR; return o_MmioAscend(hmmio, pmmcki, fuAscend); }
__declspec(dllexport) MMRESULT WINAPI mmioCreateChunk(HMMIO hmmio, LPMMCKINFO pmmcki, UINT fuCreate) { if (!o_MmioCreateChunk) return MMSYSERR_ERROR; return o_MmioCreateChunk(hmmio, pmmcki, fuCreate); }
__declspec(dllexport) MMRESULT WINAPI mmioRenameA(LPCSTR pszFileName, LPCSTR pszNewFileName, LPCMMIOINFO pmmioinfo, DWORD fdwRename) { if (!LoadOriginal() || !o_MmioRename) return MMSYSERR_ERROR; return o_MmioRename(pszFileName, pszNewFileName, pmmioinfo, fdwRename); }
__declspec(dllexport) LRESULT WINAPI mmioSendMessage(HMMIO hmmio, UINT uMsg, LPARAM lParam1, LPARAM lParam2) { if (!o_MmioSendMessage) return 0; return o_MmioSendMessage(hmmio, uMsg, lParam1, lParam2); }

} // extern "C"

// ============================================
// INIT/SHUTDOWN
// ============================================
void Init() {
    InitializeCriticalSection(&g_csLog);
    
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) *slash = 0;
    
    strcpy(g_szGameDir, path);
    sprintf(g_szValveDir, "%s\\valve", path);
    
    // v12.4 - Security initialization
    EnsureStringsDecrypted();
    CalculateSelfHash();
    
    // v12.4 - Initial anti-debug check
    if (ANTI_DEBUG_ENABLED) {
        g_bDebuggerDetected = CheckDebugger();
        if (g_bDebuggerDetected) {
            Log("WARNING: Debugger detected!");
        }
    }
    
    Log("Init: %s (v%s)", g_szGameDir, AGTR_VERSION);
    Log("Security: DLL=%s Hash=%s", g_szSelfName, g_szSelfHash);
}

void StartScanThread() {
    if (g_bThreadStarted) return;
    g_bThreadStarted = true;
    g_bRunning = true;
    g_hThread = CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
}

void Shutdown() {
    g_bRunning = false;
    if (g_hThread) { WaitForSingleObject(g_hThread, 2000); CloseHandle(g_hThread); }
    if (g_LogFile) { fclose(g_LogFile); g_LogFile = NULL; }
    DeleteCriticalSection(&g_csLog);
}

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
