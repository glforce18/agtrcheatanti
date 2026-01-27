/*
 * AGTR v15.0 - Anti-Bypass Protection System
 * ===========================================
 * Dynamic blacklists, hash-based detection, behavior scoring
 *
 * This file contains v15.0 additions to minimize bypass risk
 */

#pragma once

#include <string>
#include <set>
#include <map>
#include <vector>

// ============================================
// v15.0 - DYNAMIC BLACKLIST SYSTEM
// ============================================

// Dynamic blacklist containers (fetched from server)
struct DynamicBlacklists {
    std::set<std::string> processes;
    std::set<std::string> dlls;
    std::set<std::string> windows;
    std::set<std::string> strings;
    std::set<std::string> registry;
    std::set<std::string> drivers;
    std::map<std::string, std::string> hashes;  // hash -> filename

    DWORD lastUpdateTime;
    DWORD updateInterval;  // milliseconds (default: 1 hour)
    bool initialized;

    DynamicBlacklists() : lastUpdateTime(0), updateInterval(3600000), initialized(false) {}
};

extern DynamicBlacklists g_Blacklists;

// Fetch blacklists from server
bool FetchBlacklistFromServer();
bool ParseBlacklistJSON(const char* json, DynamicBlacklists& bl);
bool ShouldUpdateBlacklist();

// ============================================
// v15.0 - HASH-BASED DETECTION
// ============================================

// Calculate file hashes
std::string CalculateMD5(const std::wstring& filePath);
std::string CalculateSHA256(const std::wstring& filePath);
std::string CalculateFileHash(const std::wstring& filePath, bool useSHA256 = false);

// Process hash checking
bool IsProcessBlacklistedByHash(DWORD processId, std::string& detectedName);
std::wstring GetProcessPath(DWORD processId);

// ============================================
// v15.0 - BEHAVIOR SCORING SYSTEM
// ============================================

struct BehaviorScore {
    int readMemoryCount;
    int writeMemoryCount;
    int virtualProtectCount;
    int createRemoteThreadCount;
    int setWindowsHookCount;
    int dllInjectionCount;
    int debuggerAPICount;
    int suspiciousRegistryCount;

    DWORD lastResetTime;

    BehaviorScore() :
        readMemoryCount(0), writeMemoryCount(0),
        virtualProtectCount(0), createRemoteThreadCount(0),
        setWindowsHookCount(0), dllInjectionCount(0),
        debuggerAPICount(0), suspiciousRegistryCount(0),
        lastResetTime(GetTickCount()) {}

    int GetTotalScore() const {
        return readMemoryCount * 5 +
               writeMemoryCount * 10 +
               virtualProtectCount * 15 +
               createRemoteThreadCount * 20 +
               setWindowsHookCount * 10 +
               dllInjectionCount * 30 +
               debuggerAPICount * 15 +
               suspiciousRegistryCount * 8;
    }

    void Reset() {
        readMemoryCount = writeMemoryCount = 0;
        virtualProtectCount = createRemoteThreadCount = 0;
        setWindowsHookCount = dllInjectionCount = 0;
        debuggerAPICount = suspiciousRegistryCount = 0;
        lastResetTime = GetTickCount();
    }

    bool ShouldReset() {
        // Reset every 5 minutes
        return (GetTickCount() - lastResetTime) > 300000;
    }
};

extern BehaviorScore g_BehaviorScore;

// Monitor suspicious API calls
void MonitorAPICall(const char* apiName);
void CheckBehaviorScore();

// ============================================
// v15.0 - ENHANCED ANTI-TAMPER
// ============================================

struct IntegrityCheck {
    DWORD expectedCodeHash;
    DWORD expectedDataHash;
    bool verified;
    DWORD lastCheckTime;

    IntegrityCheck() : expectedCodeHash(0), expectedDataHash(0),
                       verified(false), lastCheckTime(0) {}
};

extern IntegrityCheck g_Integrity;

bool VerifyDLLIntegrity();
DWORD CalculateSectionHash(const char* sectionName);
void ReportTampering(const char* details);

// ============================================
// v15.0 - STRING ENCRYPTION HELPERS
// ============================================

// Enhanced XOR encryption for remaining strings
void DecryptStringV15(const BYTE* encrypted, size_t len, char* output);
void EncryptStringV15(const char* plaintext, BYTE* output, size_t len);

// Encrypted blacklist fallback (if server unreachable)
namespace FallbackBlacklist {
    extern const BYTE ENC_FALLBACK_PROCS[];
    extern const size_t ENC_FALLBACK_PROCS_LEN;

    void LoadFallbackBlacklists(DynamicBlacklists& bl);
}

// ============================================
// v15.0 - UTILITY FUNCTIONS
// ============================================

// JSON parsing helpers (minimal, no dependencies)
bool SimpleJSONGetArray(const char* json, const char* key, std::vector<std::string>& output);
bool SimpleJSONGetString(const char* json, const char* key, std::string& output);
bool SimpleJSONGetInt(const char* json, const char* key, int& output);

// String helpers
std::string ToLower(const std::string& str);
bool ContainsSubstring(const std::string& haystack, const std::string& needle);

// HTTP helpers for blacklist fetching
char* HTTPGet(const char* endpoint);  // Returns allocated buffer, caller must free

// ============================================
// v15.0 - DETECTION ENHANCEMENT
// ============================================

// Enhanced scanning with dynamic blacklists
int ScanProcesses_v15();
int ScanModules_v15();
int ScanWindows_v15();
int ScanMemoryStrings_v15();
int ScanRegistry_v15();
int ScanDrivers_v15();

// Hash-based detection
int ScanProcessHashes_v15();

// Report to backend with behavior score
void ReportScanWithBehavior(const char* hwid, int susCount, int behaviorScore);
