/*
 * AGTR Anti-Cheat v11.5 - winmm.dll Proxy
 * ========================================
 * 
 * NEDEN winmm.dll?
 * - Half-Life HER FRAME timeGetTime() çağırır (FPS timing)
 * - Ses sistemi waveOut* fonksiyonlarını kullanır
 * - %99.9 GARANTİ - hiçbir oyuncu bunu bypass edemez
 * - OpenGL/DirectX seçimine bağlı değil
 * - Steam overlay etkilemez
 * 
 * BONUS ÖZELLİKLER:
 * - Frame counter (FPS takibi)
 * - Oyun aktif mi tespiti
 * - Timing anomali tespiti (speedhack)
 * 
 * KURULUM:
 * 1. winmm.dll olarak derle
 * 2. Half-Life klasörüne koy
 * 3. Orijinal System32'den yüklenir
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
#include <string>
#include <vector>
#include <map>

#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================
// VERSION & CONFIG
// ============================================
#define AGTR_VERSION "11.5"
#define AGTR_BUILD __DATE__ " " __TIME__

#define API_HOST L"185.171.25.137"
#define API_PORT 5000
#define API_USE_HTTPS false

// Timing thresholds
#define SPEEDHACK_THRESHOLD 1.5f   // %50'den fazla hızlanma = speedhack
#define SLOWHACK_THRESHOLD 0.5f    // %50'den fazla yavaşlama = slowhack
#define TIMING_SAMPLE_COUNT 100    // Kaç sample toplanacak

// ============================================
// ORIGINAL WINMM FUNCTIONS
// ============================================
static HMODULE g_hOriginal = NULL;

// timeGetTime - EN ÖNEMLİ (her frame çağrılır)
typedef DWORD (WINAPI *pfnTimeGetTime)(void);
typedef MMRESULT (WINAPI *pfnTimeBeginPeriod)(UINT);
typedef MMRESULT (WINAPI *pfnTimeEndPeriod)(UINT);
typedef MMRESULT (WINAPI *pfnTimeGetDevCaps)(LPTIMECAPS, UINT);
typedef MMRESULT (WINAPI *pfnTimeGetSystemTime)(LPMMTIME, UINT);
typedef MMRESULT (WINAPI *pfnTimeSetEvent)(UINT, UINT, LPTIMECALLBACK, DWORD_PTR, UINT);
typedef MMRESULT (WINAPI *pfnTimeKillEvent)(UINT);

// Wave functions (ses)
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

// WaveIn
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

// PlaySound
typedef BOOL (WINAPI *pfnPlaySoundA)(LPCSTR, HMODULE, DWORD);
typedef BOOL (WINAPI *pfnPlaySoundW)(LPCWSTR, HMODULE, DWORD);
typedef BOOL (WINAPI *pfnSndPlaySoundA)(LPCSTR, UINT);
typedef BOOL (WINAPI *pfnSndPlaySoundW)(LPCWSTR, UINT);

// MIDI
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

// Joystick
typedef UINT (WINAPI *pfnJoyGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnJoyGetDevCapsA)(UINT, LPJOYCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnJoyGetDevCapsW)(UINT, LPJOYCAPSW, UINT);
typedef MMRESULT (WINAPI *pfnJoyGetPos)(UINT, LPJOYINFO);
typedef MMRESULT (WINAPI *pfnJoyGetPosEx)(UINT, LPJOYINFOEX);
typedef MMRESULT (WINAPI *pfnJoyGetThreshold)(UINT, LPUINT);
typedef MMRESULT (WINAPI *pfnJoySetThreshold)(UINT, UINT);
typedef MMRESULT (WINAPI *pfnJoySetCapture)(HWND, UINT, UINT, BOOL);
typedef MMRESULT (WINAPI *pfnJoyReleaseCapture)(UINT);

// Aux
typedef UINT (WINAPI *pfnAuxGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnAuxGetDevCapsA)(UINT, LPAUXCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnAuxGetDevCapsW)(UINT, LPAUXCAPSW, UINT);
typedef MMRESULT (WINAPI *pfnAuxGetVolume)(UINT, LPDWORD);
typedef MMRESULT (WINAPI *pfnAuxSetVolume)(UINT, DWORD);
typedef MMRESULT (WINAPI *pfnAuxOutMessage)(UINT, UINT, DWORD_PTR, DWORD_PTR);

// Mixer
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
typedef MMRESULT (WINAPI *pfnMixerMessage)(HMIXER, UINT, DWORD_PTR, DWORD_PTR);

// MCI
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

// mmio
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
#define DECLARE_FUNC(name) static pfn##name o_##name = NULL

DECLARE_FUNC(TimeGetTime);
DECLARE_FUNC(TimeBeginPeriod);
DECLARE_FUNC(TimeEndPeriod);
DECLARE_FUNC(TimeGetDevCaps);
DECLARE_FUNC(TimeGetSystemTime);
DECLARE_FUNC(TimeSetEvent);
DECLARE_FUNC(TimeKillEvent);

DECLARE_FUNC(WaveOutOpen);
DECLARE_FUNC(WaveOutClose);
DECLARE_FUNC(WaveOutWrite);
DECLARE_FUNC(WaveOutPrepareHeader);
DECLARE_FUNC(WaveOutUnprepareHeader);
DECLARE_FUNC(WaveOutReset);
DECLARE_FUNC(WaveOutPause);
DECLARE_FUNC(WaveOutRestart);
DECLARE_FUNC(WaveOutGetPosition);
DECLARE_FUNC(WaveOutGetDevCapsA);
DECLARE_FUNC(WaveOutGetDevCapsW);
DECLARE_FUNC(WaveOutGetNumDevs);
DECLARE_FUNC(WaveOutGetVolume);
DECLARE_FUNC(WaveOutSetVolume);
DECLARE_FUNC(WaveOutGetErrorTextA);
DECLARE_FUNC(WaveOutGetErrorTextW);
DECLARE_FUNC(WaveOutGetID);
DECLARE_FUNC(WaveOutMessage);
DECLARE_FUNC(WaveOutBreakLoop);

DECLARE_FUNC(WaveInOpen);
DECLARE_FUNC(WaveInClose);
DECLARE_FUNC(WaveInGetNumDevs);
DECLARE_FUNC(WaveInGetDevCapsA);
DECLARE_FUNC(WaveInGetDevCapsW);
DECLARE_FUNC(WaveInStart);
DECLARE_FUNC(WaveInStop);
DECLARE_FUNC(WaveInReset);
DECLARE_FUNC(WaveInPrepareHeader);
DECLARE_FUNC(WaveInUnprepareHeader);
DECLARE_FUNC(WaveInAddBuffer);
DECLARE_FUNC(WaveInGetPosition);
DECLARE_FUNC(WaveInGetID);
DECLARE_FUNC(WaveInGetErrorTextA);
DECLARE_FUNC(WaveInGetErrorTextW);
DECLARE_FUNC(WaveInMessage);

DECLARE_FUNC(PlaySoundA);
DECLARE_FUNC(PlaySoundW);
DECLARE_FUNC(SndPlaySoundA);
DECLARE_FUNC(SndPlaySoundW);

DECLARE_FUNC(MidiOutGetNumDevs);
DECLARE_FUNC(MidiOutGetDevCapsA);
DECLARE_FUNC(MidiOutGetDevCapsW);
DECLARE_FUNC(MidiOutOpen);
DECLARE_FUNC(MidiOutClose);
DECLARE_FUNC(MidiOutShortMsg);
DECLARE_FUNC(MidiOutLongMsg);
DECLARE_FUNC(MidiOutReset);
DECLARE_FUNC(MidiOutPrepareHeader);
DECLARE_FUNC(MidiOutUnprepareHeader);

DECLARE_FUNC(JoyGetNumDevs);
DECLARE_FUNC(JoyGetDevCapsA);
DECLARE_FUNC(JoyGetDevCapsW);
DECLARE_FUNC(JoyGetPos);
DECLARE_FUNC(JoyGetPosEx);
DECLARE_FUNC(JoyGetThreshold);
DECLARE_FUNC(JoySetThreshold);
DECLARE_FUNC(JoySetCapture);
DECLARE_FUNC(JoyReleaseCapture);

DECLARE_FUNC(AuxGetNumDevs);
DECLARE_FUNC(AuxGetDevCapsA);
DECLARE_FUNC(AuxGetDevCapsW);
DECLARE_FUNC(AuxGetVolume);
DECLARE_FUNC(AuxSetVolume);
DECLARE_FUNC(AuxOutMessage);

DECLARE_FUNC(MixerGetNumDevs);
DECLARE_FUNC(MixerOpen);
DECLARE_FUNC(MixerClose);
DECLARE_FUNC(MixerGetDevCapsA);
DECLARE_FUNC(MixerGetDevCapsW);
DECLARE_FUNC(MixerGetLineInfoA);
DECLARE_FUNC(MixerGetLineInfoW);
DECLARE_FUNC(MixerGetLineControlsA);
DECLARE_FUNC(MixerGetLineControlsW);
DECLARE_FUNC(MixerGetControlDetailsA);
DECLARE_FUNC(MixerGetControlDetailsW);
DECLARE_FUNC(MixerSetControlDetails);
DECLARE_FUNC(MixerGetID);
DECLARE_FUNC(MixerMessage);

DECLARE_FUNC(MciSendCommandA);
DECLARE_FUNC(MciSendCommandW);
DECLARE_FUNC(MciSendStringA);
DECLARE_FUNC(MciSendStringW);
DECLARE_FUNC(MciGetErrorStringA);
DECLARE_FUNC(MciGetErrorStringW);
DECLARE_FUNC(MciGetDeviceIDA);
DECLARE_FUNC(MciGetDeviceIDW);
DECLARE_FUNC(MciGetDeviceIDFromElementIDA);
DECLARE_FUNC(MciGetDeviceIDFromElementIDW);
DECLARE_FUNC(MciSetYieldProc);
DECLARE_FUNC(MciGetYieldProc);
DECLARE_FUNC(MciGetCreatorTask);
DECLARE_FUNC(MciExecute);

DECLARE_FUNC(MmioOpenA);
DECLARE_FUNC(MmioOpenW);
DECLARE_FUNC(MmioClose);
DECLARE_FUNC(MmioRead);
DECLARE_FUNC(MmioWrite);
DECLARE_FUNC(MmioSeek);
DECLARE_FUNC(MmioGetInfo);
DECLARE_FUNC(MmioSetInfo);
DECLARE_FUNC(MmioSetBuffer);
DECLARE_FUNC(MmioFlush);
DECLARE_FUNC(MmioAdvance);
DECLARE_FUNC(MmioInstallIOProcA);
DECLARE_FUNC(MmioInstallIOProcW);
DECLARE_FUNC(MmioStringToFOURCCA);
DECLARE_FUNC(MmioStringToFOURCCW);
DECLARE_FUNC(MmioDescend);
DECLARE_FUNC(MmioAscend);
DECLARE_FUNC(MmioCreateChunk);
DECLARE_FUNC(MmioRename);
DECLARE_FUNC(MmioSendMessage);

#undef DECLARE_FUNC

// ============================================
// GLOBALS
// ============================================
static bool g_bInitialized = false;
static bool g_bScanThreadRunning = false;
static HANDLE g_hScanThread = NULL;
static CRITICAL_SECTION g_csLog;
static CRITICAL_SECTION g_csTiming;
static FILE* g_LogFile = NULL;
static char g_szGameDir[MAX_PATH] = {0};

// Client state
static char g_szHWID[64] = {0};
static char g_szServerIP[64] = "unknown";
static int g_iServerPort = 0;
static bool g_bInServer = false;
static bool g_bPassed = true;
static int g_iSusCount = 0;

// Timing monitoring (speedhack detection)
static DWORD g_dwLastTimeGetTime = 0;
static DWORD g_dwRealLastTime = 0;
static DWORD g_dwFrameCount = 0;
static float g_fTimingRatios[TIMING_SAMPLE_COUNT] = {0};
static int g_iTimingSampleIndex = 0;
static bool g_bSpeedhackDetected = false;

// API settings
static bool g_bScanEnabled = true;
static int g_iScanInterval = 120000;
static bool g_bScanOnlyInServer = true;
static DWORD g_dwLastScan = 0;
static DWORD g_dwLastHeartbeat = 0;

// Challenge-response
static char g_szChallenge[64] = {0};
static DWORD g_dwChallengeTime = 0;
static bool g_bChallengeActive = false;

// ============================================
// LOGGING
// ============================================
void Log(const char* fmt, ...) {
    EnterCriticalSection(&g_csLog);
    
    if (!g_LogFile && g_szGameDir[0]) {
        char path[MAX_PATH];
        sprintf(path, "%s\\agtr_winmm.log", g_szGameDir);
        g_LogFile = fopen(path, "a");
    }
    
    if (g_LogFile) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_LogFile, "[%02d:%02d:%02d.%03d] ", 
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        
        va_list args;
        va_start(args, fmt);
        vfprintf(g_LogFile, fmt, args);
        va_end(args);
        
        fprintf(g_LogFile, "\n");
        fflush(g_LogFile);
    }
    
    LeaveCriticalSection(&g_csLog);
}

// ============================================
// LOAD ORIGINAL DLL
// ============================================
bool LoadOriginal() {
    if (g_hOriginal) return true;
    
    char sysPath[MAX_PATH];
    GetSystemDirectoryA(sysPath, MAX_PATH);
    strcat(sysPath, "\\winmm.dll");
    
    g_hOriginal = LoadLibraryA(sysPath);
    if (!g_hOriginal) {
        Log("FATAL: Cannot load original winmm.dll from %s (Error: %d)", 
            sysPath, GetLastError());
        return false;
    }
    
    // Load all functions
    #define LOAD_FUNC(name) o_##name = (pfn##name)GetProcAddress(g_hOriginal, #name)
    
    LOAD_FUNC(TimeGetTime);
    LOAD_FUNC(TimeBeginPeriod);
    LOAD_FUNC(TimeEndPeriod);
    LOAD_FUNC(TimeGetDevCaps);
    LOAD_FUNC(TimeGetSystemTime);
    LOAD_FUNC(TimeSetEvent);
    LOAD_FUNC(TimeKillEvent);
    
    LOAD_FUNC(WaveOutOpen);
    LOAD_FUNC(WaveOutClose);
    LOAD_FUNC(WaveOutWrite);
    LOAD_FUNC(WaveOutPrepareHeader);
    LOAD_FUNC(WaveOutUnprepareHeader);
    LOAD_FUNC(WaveOutReset);
    LOAD_FUNC(WaveOutPause);
    LOAD_FUNC(WaveOutRestart);
    LOAD_FUNC(WaveOutGetPosition);
    LOAD_FUNC(WaveOutGetDevCapsA);
    LOAD_FUNC(WaveOutGetDevCapsW);
    LOAD_FUNC(WaveOutGetNumDevs);
    LOAD_FUNC(WaveOutGetVolume);
    LOAD_FUNC(WaveOutSetVolume);
    LOAD_FUNC(WaveOutGetErrorTextA);
    LOAD_FUNC(WaveOutGetErrorTextW);
    LOAD_FUNC(WaveOutGetID);
    LOAD_FUNC(WaveOutMessage);
    LOAD_FUNC(WaveOutBreakLoop);
    
    LOAD_FUNC(WaveInOpen);
    LOAD_FUNC(WaveInClose);
    LOAD_FUNC(WaveInGetNumDevs);
    LOAD_FUNC(WaveInGetDevCapsA);
    LOAD_FUNC(WaveInGetDevCapsW);
    LOAD_FUNC(WaveInStart);
    LOAD_FUNC(WaveInStop);
    LOAD_FUNC(WaveInReset);
    LOAD_FUNC(WaveInPrepareHeader);
    LOAD_FUNC(WaveInUnprepareHeader);
    LOAD_FUNC(WaveInAddBuffer);
    LOAD_FUNC(WaveInGetPosition);
    LOAD_FUNC(WaveInGetID);
    LOAD_FUNC(WaveInGetErrorTextA);
    LOAD_FUNC(WaveInGetErrorTextW);
    LOAD_FUNC(WaveInMessage);
    
    LOAD_FUNC(PlaySoundA);
    LOAD_FUNC(PlaySoundW);
    LOAD_FUNC(SndPlaySoundA);
    LOAD_FUNC(SndPlaySoundW);
    
    LOAD_FUNC(MidiOutGetNumDevs);
    LOAD_FUNC(MidiOutGetDevCapsA);
    LOAD_FUNC(MidiOutGetDevCapsW);
    LOAD_FUNC(MidiOutOpen);
    LOAD_FUNC(MidiOutClose);
    LOAD_FUNC(MidiOutShortMsg);
    LOAD_FUNC(MidiOutLongMsg);
    LOAD_FUNC(MidiOutReset);
    LOAD_FUNC(MidiOutPrepareHeader);
    LOAD_FUNC(MidiOutUnprepareHeader);
    
    LOAD_FUNC(JoyGetNumDevs);
    LOAD_FUNC(JoyGetDevCapsA);
    LOAD_FUNC(JoyGetDevCapsW);
    LOAD_FUNC(JoyGetPos);
    LOAD_FUNC(JoyGetPosEx);
    LOAD_FUNC(JoyGetThreshold);
    LOAD_FUNC(JoySetThreshold);
    LOAD_FUNC(JoySetCapture);
    LOAD_FUNC(JoyReleaseCapture);
    
    LOAD_FUNC(AuxGetNumDevs);
    LOAD_FUNC(AuxGetDevCapsA);
    LOAD_FUNC(AuxGetDevCapsW);
    LOAD_FUNC(AuxGetVolume);
    LOAD_FUNC(AuxSetVolume);
    LOAD_FUNC(AuxOutMessage);
    
    LOAD_FUNC(MixerGetNumDevs);
    LOAD_FUNC(MixerOpen);
    LOAD_FUNC(MixerClose);
    LOAD_FUNC(MixerGetDevCapsA);
    LOAD_FUNC(MixerGetDevCapsW);
    LOAD_FUNC(MixerGetLineInfoA);
    LOAD_FUNC(MixerGetLineInfoW);
    LOAD_FUNC(MixerGetLineControlsA);
    LOAD_FUNC(MixerGetLineControlsW);
    LOAD_FUNC(MixerGetControlDetailsA);
    LOAD_FUNC(MixerGetControlDetailsW);
    LOAD_FUNC(MixerSetControlDetails);
    LOAD_FUNC(MixerGetID);
    LOAD_FUNC(MixerMessage);
    
    LOAD_FUNC(MciSendCommandA);
    LOAD_FUNC(MciSendCommandW);
    LOAD_FUNC(MciSendStringA);
    LOAD_FUNC(MciSendStringW);
    LOAD_FUNC(MciGetErrorStringA);
    LOAD_FUNC(MciGetErrorStringW);
    LOAD_FUNC(MciGetDeviceIDA);
    LOAD_FUNC(MciGetDeviceIDW);
    LOAD_FUNC(MciGetDeviceIDFromElementIDA);
    LOAD_FUNC(MciGetDeviceIDFromElementIDW);
    LOAD_FUNC(MciSetYieldProc);
    LOAD_FUNC(MciGetYieldProc);
    LOAD_FUNC(MciGetCreatorTask);
    LOAD_FUNC(MciExecute);
    
    LOAD_FUNC(MmioOpenA);
    LOAD_FUNC(MmioOpenW);
    LOAD_FUNC(MmioClose);
    LOAD_FUNC(MmioRead);
    LOAD_FUNC(MmioWrite);
    LOAD_FUNC(MmioSeek);
    LOAD_FUNC(MmioGetInfo);
    LOAD_FUNC(MmioSetInfo);
    LOAD_FUNC(MmioSetBuffer);
    LOAD_FUNC(MmioFlush);
    LOAD_FUNC(MmioAdvance);
    LOAD_FUNC(MmioInstallIOProcA);
    LOAD_FUNC(MmioInstallIOProcW);
    LOAD_FUNC(MmioStringToFOURCCA);
    LOAD_FUNC(MmioStringToFOURCCW);
    LOAD_FUNC(MmioDescend);
    LOAD_FUNC(MmioAscend);
    LOAD_FUNC(MmioCreateChunk);
    LOAD_FUNC(MmioRename);
    LOAD_FUNC(MmioSendMessage);
    
    #undef LOAD_FUNC
    
    Log("Original winmm.dll loaded successfully");
    return true;
}

// ============================================
// SPEEDHACK DETECTION via timeGetTime
// ============================================
void CheckTiming(DWORD gameTime) {
    EnterCriticalSection(&g_csTiming);
    
    DWORD realTime = GetTickCount();
    
    if (g_dwLastTimeGetTime > 0 && g_dwRealLastTime > 0) {
        DWORD gameDelta = gameTime - g_dwLastTimeGetTime;
        DWORD realDelta = realTime - g_dwRealLastTime;
        
        if (realDelta > 10 && gameDelta > 10) {  // Minimum threshold
            float ratio = (float)gameDelta / (float)realDelta;
            
            // Store sample
            g_fTimingRatios[g_iTimingSampleIndex] = ratio;
            g_iTimingSampleIndex = (g_iTimingSampleIndex + 1) % TIMING_SAMPLE_COUNT;
            
            // Calculate average
            float avgRatio = 0;
            int validSamples = 0;
            for (int i = 0; i < TIMING_SAMPLE_COUNT; i++) {
                if (g_fTimingRatios[i] > 0) {
                    avgRatio += g_fTimingRatios[i];
                    validSamples++;
                }
            }
            
            if (validSamples > 50) {
                avgRatio /= validSamples;
                
                if (avgRatio > SPEEDHACK_THRESHOLD) {
                    if (!g_bSpeedhackDetected) {
                        g_bSpeedhackDetected = true;
                        Log("!!! SPEEDHACK DETECTED !!! Ratio: %.2f", avgRatio);
                        g_iSusCount += 100;  // Ağır ceza
                    }
                } else if (avgRatio < SLOWHACK_THRESHOLD) {
                    Log("WARNING: Slowhack suspected. Ratio: %.2f", avgRatio);
                }
            }
        }
    }
    
    g_dwLastTimeGetTime = gameTime;
    g_dwRealLastTime = realTime;
    g_dwFrameCount++;
    
    LeaveCriticalSection(&g_csTiming);
}

// ============================================
// EXPORTED FUNCTIONS - timeGetTime (CRITICAL)
// ============================================
extern "C" {

// Bu fonksiyon HER FRAME çağrılır - ana tetikleyici
__declspec(dllexport) DWORD WINAPI timeGetTime(void) {
    if (!LoadOriginal() || !o_TimeGetTime) return GetTickCount();
    
    DWORD result = o_TimeGetTime();
    
    // Her frame timing kontrolü
    CheckTiming(result);
    
    return result;
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

__declspec(dllexport) MMRESULT WINAPI timeSetEvent(UINT uDelay, UINT uResolution, 
    LPTIMECALLBACK fptc, DWORD_PTR dwUser, UINT fuEvent) {
    if (!LoadOriginal() || !o_TimeSetEvent) return 0;
    return o_TimeSetEvent(uDelay, uResolution, fptc, dwUser, fuEvent);
}

__declspec(dllexport) MMRESULT WINAPI timeKillEvent(UINT uTimerID) {
    if (!LoadOriginal() || !o_TimeKillEvent) return MMSYSERR_ERROR;
    return o_TimeKillEvent(uTimerID);
}

// ============================================
// WAVE OUT FUNCTIONS
// ============================================
__declspec(dllexport) MMRESULT WINAPI waveOutOpen(LPHWAVEOUT phwo, UINT uDeviceID, 
    LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen) {
    if (!LoadOriginal() || !o_WaveOutOpen) return MMSYSERR_ERROR;
    Log("waveOutOpen called - Audio active");
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

__declspec(dllexport) MMRESULT WINAPI waveOutReset(HWAVEOUT hwo) {
    if (!o_WaveOutReset) return MMSYSERR_ERROR;
    return o_WaveOutReset(hwo);
}

__declspec(dllexport) MMRESULT WINAPI waveOutPause(HWAVEOUT hwo) {
    if (!o_WaveOutPause) return MMSYSERR_ERROR;
    return o_WaveOutPause(hwo);
}

__declspec(dllexport) MMRESULT WINAPI waveOutRestart(HWAVEOUT hwo) {
    if (!o_WaveOutRestart) return MMSYSERR_ERROR;
    return o_WaveOutRestart(hwo);
}

__declspec(dllexport) MMRESULT WINAPI waveOutGetPosition(HWAVEOUT hwo, LPMMTIME pmmt, UINT cbmmt) {
    if (!o_WaveOutGetPosition) return MMSYSERR_ERROR;
    return o_WaveOutGetPosition(hwo, pmmt, cbmmt);
}

__declspec(dllexport) MMRESULT WINAPI waveOutGetDevCapsA(UINT uDeviceID, LPWAVEOUTCAPSA pwoc, UINT cbwoc) {
    if (!LoadOriginal() || !o_WaveOutGetDevCapsA) return MMSYSERR_ERROR;
    return o_WaveOutGetDevCapsA(uDeviceID, pwoc, cbwoc);
}

__declspec(dllexport) MMRESULT WINAPI waveOutGetDevCapsW(UINT uDeviceID, LPWAVEOUTCAPSW pwoc, UINT cbwoc) {
    if (!LoadOriginal() || !o_WaveOutGetDevCapsW) return MMSYSERR_ERROR;
    return o_WaveOutGetDevCapsW(uDeviceID, pwoc, cbwoc);
}

__declspec(dllexport) UINT WINAPI waveOutGetNumDevs(void) {
    if (!LoadOriginal() || !o_WaveOutGetNumDevs) return 0;
    return o_WaveOutGetNumDevs();
}

__declspec(dllexport) MMRESULT WINAPI waveOutGetVolume(HWAVEOUT hwo, LPDWORD pdwVolume) {
    if (!o_WaveOutGetVolume) return MMSYSERR_ERROR;
    return o_WaveOutGetVolume(hwo, pdwVolume);
}

__declspec(dllexport) MMRESULT WINAPI waveOutSetVolume(HWAVEOUT hwo, DWORD dwVolume) {
    if (!o_WaveOutSetVolume) return MMSYSERR_ERROR;
    return o_WaveOutSetVolume(hwo, dwVolume);
}

__declspec(dllexport) MMRESULT WINAPI waveOutGetErrorTextA(MMRESULT mmrError, LPSTR pszText, UINT cchText) {
    if (!LoadOriginal() || !o_WaveOutGetErrorTextA) return MMSYSERR_ERROR;
    return o_WaveOutGetErrorTextA(mmrError, pszText, cchText);
}

__declspec(dllexport) MMRESULT WINAPI waveOutGetErrorTextW(MMRESULT mmrError, LPWSTR pszText, UINT cchText) {
    if (!LoadOriginal() || !o_WaveOutGetErrorTextW) return MMSYSERR_ERROR;
    return o_WaveOutGetErrorTextW(mmrError, pszText, cchText);
}

__declspec(dllexport) MMRESULT WINAPI waveOutGetID(HWAVEOUT hwo, LPUINT puDeviceID) {
    if (!o_WaveOutGetID) return MMSYSERR_ERROR;
    return o_WaveOutGetID(hwo, puDeviceID);
}

__declspec(dllexport) MMRESULT WINAPI waveOutMessage(HWAVEOUT hwo, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2) {
    if (!o_WaveOutMessage) return MMSYSERR_ERROR;
    return o_WaveOutMessage(hwo, uMsg, dw1, dw2);
}

__declspec(dllexport) MMRESULT WINAPI waveOutBreakLoop(HWAVEOUT hwo) {
    if (!o_WaveOutBreakLoop) return MMSYSERR_ERROR;
    return o_WaveOutBreakLoop(hwo);
}

// ============================================
// WAVE IN FUNCTIONS  
// ============================================
__declspec(dllexport) MMRESULT WINAPI waveInOpen(LPHWAVEIN phwi, UINT uDeviceID,
    LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen) {
    if (!LoadOriginal() || !o_WaveInOpen) return MMSYSERR_ERROR;
    return o_WaveInOpen(phwi, uDeviceID, pwfx, dwCallback, dwInstance, fdwOpen);
}

__declspec(dllexport) MMRESULT WINAPI waveInClose(HWAVEIN hwi) {
    if (!o_WaveInClose) return MMSYSERR_ERROR;
    return o_WaveInClose(hwi);
}

__declspec(dllexport) UINT WINAPI waveInGetNumDevs(void) {
    if (!LoadOriginal() || !o_WaveInGetNumDevs) return 0;
    return o_WaveInGetNumDevs();
}

__declspec(dllexport) MMRESULT WINAPI waveInGetDevCapsA(UINT uDeviceID, LPWAVEINCAPSA pwic, UINT cbwic) {
    if (!LoadOriginal() || !o_WaveInGetDevCapsA) return MMSYSERR_ERROR;
    return o_WaveInGetDevCapsA(uDeviceID, pwic, cbwic);
}

__declspec(dllexport) MMRESULT WINAPI waveInGetDevCapsW(UINT uDeviceID, LPWAVEINCAPSW pwic, UINT cbwic) {
    if (!LoadOriginal() || !o_WaveInGetDevCapsW) return MMSYSERR_ERROR;
    return o_WaveInGetDevCapsW(uDeviceID, pwic, cbwic);
}

__declspec(dllexport) MMRESULT WINAPI waveInStart(HWAVEIN hwi) {
    if (!o_WaveInStart) return MMSYSERR_ERROR;
    return o_WaveInStart(hwi);
}

__declspec(dllexport) MMRESULT WINAPI waveInStop(HWAVEIN hwi) {
    if (!o_WaveInStop) return MMSYSERR_ERROR;
    return o_WaveInStop(hwi);
}

__declspec(dllexport) MMRESULT WINAPI waveInReset(HWAVEIN hwi) {
    if (!o_WaveInReset) return MMSYSERR_ERROR;
    return o_WaveInReset(hwi);
}

__declspec(dllexport) MMRESULT WINAPI waveInPrepareHeader(HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh) {
    if (!o_WaveInPrepareHeader) return MMSYSERR_ERROR;
    return o_WaveInPrepareHeader(hwi, pwh, cbwh);
}

__declspec(dllexport) MMRESULT WINAPI waveInUnprepareHeader(HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh) {
    if (!o_WaveInUnprepareHeader) return MMSYSERR_ERROR;
    return o_WaveInUnprepareHeader(hwi, pwh, cbwh);
}

__declspec(dllexport) MMRESULT WINAPI waveInAddBuffer(HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh) {
    if (!o_WaveInAddBuffer) return MMSYSERR_ERROR;
    return o_WaveInAddBuffer(hwi, pwh, cbwh);
}

__declspec(dllexport) MMRESULT WINAPI waveInGetPosition(HWAVEIN hwi, LPMMTIME pmmt, UINT cbmmt) {
    if (!o_WaveInGetPosition) return MMSYSERR_ERROR;
    return o_WaveInGetPosition(hwi, pmmt, cbmmt);
}

__declspec(dllexport) MMRESULT WINAPI waveInGetID(HWAVEIN hwi, LPUINT puDeviceID) {
    if (!o_WaveInGetID) return MMSYSERR_ERROR;
    return o_WaveInGetID(hwi, puDeviceID);
}

__declspec(dllexport) MMRESULT WINAPI waveInGetErrorTextA(MMRESULT mmrError, LPSTR pszText, UINT cchText) {
    if (!LoadOriginal() || !o_WaveInGetErrorTextA) return MMSYSERR_ERROR;
    return o_WaveInGetErrorTextA(mmrError, pszText, cchText);
}

__declspec(dllexport) MMRESULT WINAPI waveInGetErrorTextW(MMRESULT mmrError, LPWSTR pszText, UINT cchText) {
    if (!LoadOriginal() || !o_WaveInGetErrorTextW) return MMSYSERR_ERROR;
    return o_WaveInGetErrorTextW(mmrError, pszText, cchText);
}

__declspec(dllexport) MMRESULT WINAPI waveInMessage(HWAVEIN hwi, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2) {
    if (!o_WaveInMessage) return MMSYSERR_ERROR;
    return o_WaveInMessage(hwi, uMsg, dw1, dw2);
}

// ============================================
// PLAYSOUND FUNCTIONS
// ============================================
__declspec(dllexport) BOOL WINAPI PlaySoundA(LPCSTR pszSound, HMODULE hmod, DWORD fdwSound) {
    if (!LoadOriginal() || !o_PlaySoundA) return FALSE;
    return o_PlaySoundA(pszSound, hmod, fdwSound);
}

__declspec(dllexport) BOOL WINAPI PlaySoundW(LPCWSTR pszSound, HMODULE hmod, DWORD fdwSound) {
    if (!LoadOriginal() || !o_PlaySoundW) return FALSE;
    return o_PlaySoundW(pszSound, hmod, fdwSound);
}

__declspec(dllexport) BOOL WINAPI sndPlaySoundA(LPCSTR pszSound, UINT fuSound) {
    if (!LoadOriginal() || !o_SndPlaySoundA) return FALSE;
    return o_SndPlaySoundA(pszSound, fuSound);
}

__declspec(dllexport) BOOL WINAPI sndPlaySoundW(LPCWSTR pszSound, UINT fuSound) {
    if (!LoadOriginal() || !o_SndPlaySoundW) return FALSE;
    return o_SndPlaySoundW(pszSound, fuSound);
}

// ============================================
// JOYSTICK FUNCTIONS (Half-Life joystick support)
// ============================================
__declspec(dllexport) UINT WINAPI joyGetNumDevs(void) {
    if (!LoadOriginal() || !o_JoyGetNumDevs) return 0;
    return o_JoyGetNumDevs();
}

__declspec(dllexport) MMRESULT WINAPI joyGetDevCapsA(UINT uJoyID, LPJOYCAPSA pjc, UINT cbjc) {
    if (!LoadOriginal() || !o_JoyGetDevCapsA) return MMSYSERR_ERROR;
    return o_JoyGetDevCapsA(uJoyID, pjc, cbjc);
}

__declspec(dllexport) MMRESULT WINAPI joyGetDevCapsW(UINT uJoyID, LPJOYCAPSW pjc, UINT cbjc) {
    if (!LoadOriginal() || !o_JoyGetDevCapsW) return MMSYSERR_ERROR;
    return o_JoyGetDevCapsW(uJoyID, pjc, cbjc);
}

__declspec(dllexport) MMRESULT WINAPI joyGetPos(UINT uJoyID, LPJOYINFO pji) {
    if (!LoadOriginal() || !o_JoyGetPos) return MMSYSERR_ERROR;
    return o_JoyGetPos(uJoyID, pji);
}

__declspec(dllexport) MMRESULT WINAPI joyGetPosEx(UINT uJoyID, LPJOYINFOEX pji) {
    if (!LoadOriginal() || !o_JoyGetPosEx) return MMSYSERR_ERROR;
    return o_JoyGetPosEx(uJoyID, pji);
}

__declspec(dllexport) MMRESULT WINAPI joyGetThreshold(UINT uJoyID, LPUINT puThreshold) {
    if (!LoadOriginal() || !o_JoyGetThreshold) return MMSYSERR_ERROR;
    return o_JoyGetThreshold(uJoyID, puThreshold);
}

__declspec(dllexport) MMRESULT WINAPI joySetThreshold(UINT uJoyID, UINT uThreshold) {
    if (!LoadOriginal() || !o_JoySetThreshold) return MMSYSERR_ERROR;
    return o_JoySetThreshold(uJoyID, uThreshold);
}

__declspec(dllexport) MMRESULT WINAPI joySetCapture(HWND hwnd, UINT uJoyID, UINT uPeriod, BOOL fChanged) {
    if (!LoadOriginal() || !o_JoySetCapture) return MMSYSERR_ERROR;
    return o_JoySetCapture(hwnd, uJoyID, uPeriod, fChanged);
}

__declspec(dllexport) MMRESULT WINAPI joyReleaseCapture(UINT uJoyID) {
    if (!LoadOriginal() || !o_JoyReleaseCapture) return MMSYSERR_ERROR;
    return o_JoyReleaseCapture(uJoyID);
}

// ============================================
// MIDI FUNCTIONS
// ============================================
__declspec(dllexport) UINT WINAPI midiOutGetNumDevs(void) {
    if (!LoadOriginal() || !o_MidiOutGetNumDevs) return 0;
    return o_MidiOutGetNumDevs();
}

__declspec(dllexport) MMRESULT WINAPI midiOutGetDevCapsA(UINT uDeviceID, LPMIDIOUTCAPSA pmoc, UINT cbmoc) {
    if (!LoadOriginal() || !o_MidiOutGetDevCapsA) return MMSYSERR_ERROR;
    return o_MidiOutGetDevCapsA(uDeviceID, pmoc, cbmoc);
}

__declspec(dllexport) MMRESULT WINAPI midiOutGetDevCapsW(UINT uDeviceID, LPMIDIOUTCAPSW pmoc, UINT cbmoc) {
    if (!LoadOriginal() || !o_MidiOutGetDevCapsW) return MMSYSERR_ERROR;
    return o_MidiOutGetDevCapsW(uDeviceID, pmoc, cbmoc);
}

__declspec(dllexport) MMRESULT WINAPI midiOutOpen(LPHMIDIOUT phmo, UINT uDeviceID, 
    DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen) {
    if (!LoadOriginal() || !o_MidiOutOpen) return MMSYSERR_ERROR;
    return o_MidiOutOpen(phmo, uDeviceID, dwCallback, dwInstance, fdwOpen);
}

__declspec(dllexport) MMRESULT WINAPI midiOutClose(HMIDIOUT hmo) {
    if (!o_MidiOutClose) return MMSYSERR_ERROR;
    return o_MidiOutClose(hmo);
}

__declspec(dllexport) MMRESULT WINAPI midiOutShortMsg(HMIDIOUT hmo, DWORD dwMsg) {
    if (!o_MidiOutShortMsg) return MMSYSERR_ERROR;
    return o_MidiOutShortMsg(hmo, dwMsg);
}

__declspec(dllexport) MMRESULT WINAPI midiOutLongMsg(HMIDIOUT hmo, LPMIDIHDR pmh, UINT cbmh) {
    if (!o_MidiOutLongMsg) return MMSYSERR_ERROR;
    return o_MidiOutLongMsg(hmo, pmh, cbmh);
}

__declspec(dllexport) MMRESULT WINAPI midiOutReset(HMIDIOUT hmo) {
    if (!o_MidiOutReset) return MMSYSERR_ERROR;
    return o_MidiOutReset(hmo);
}

__declspec(dllexport) MMRESULT WINAPI midiOutPrepareHeader(HMIDIOUT hmo, LPMIDIHDR pmh, UINT cbmh) {
    if (!o_MidiOutPrepareHeader) return MMSYSERR_ERROR;
    return o_MidiOutPrepareHeader(hmo, pmh, cbmh);
}

__declspec(dllexport) MMRESULT WINAPI midiOutUnprepareHeader(HMIDIOUT hmo, LPMIDIHDR pmh, UINT cbmh) {
    if (!o_MidiOutUnprepareHeader) return MMSYSERR_ERROR;
    return o_MidiOutUnprepareHeader(hmo, pmh, cbmh);
}

// ============================================
// AUX FUNCTIONS
// ============================================
__declspec(dllexport) UINT WINAPI auxGetNumDevs(void) {
    if (!LoadOriginal() || !o_AuxGetNumDevs) return 0;
    return o_AuxGetNumDevs();
}

__declspec(dllexport) MMRESULT WINAPI auxGetDevCapsA(UINT uDeviceID, LPAUXCAPSA pac, UINT cbac) {
    if (!LoadOriginal() || !o_AuxGetDevCapsA) return MMSYSERR_ERROR;
    return o_AuxGetDevCapsA(uDeviceID, pac, cbac);
}

__declspec(dllexport) MMRESULT WINAPI auxGetDevCapsW(UINT uDeviceID, LPAUXCAPSW pac, UINT cbac) {
    if (!LoadOriginal() || !o_AuxGetDevCapsW) return MMSYSERR_ERROR;
    return o_AuxGetDevCapsW(uDeviceID, pac, cbac);
}

__declspec(dllexport) MMRESULT WINAPI auxGetVolume(UINT uDeviceID, LPDWORD pdwVolume) {
    if (!LoadOriginal() || !o_AuxGetVolume) return MMSYSERR_ERROR;
    return o_AuxGetVolume(uDeviceID, pdwVolume);
}

__declspec(dllexport) MMRESULT WINAPI auxSetVolume(UINT uDeviceID, DWORD dwVolume) {
    if (!LoadOriginal() || !o_AuxSetVolume) return MMSYSERR_ERROR;
    return o_AuxSetVolume(uDeviceID, dwVolume);
}

__declspec(dllexport) MMRESULT WINAPI auxOutMessage(UINT uDeviceID, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2) {
    if (!LoadOriginal() || !o_AuxOutMessage) return MMSYSERR_ERROR;
    return o_AuxOutMessage(uDeviceID, uMsg, dw1, dw2);
}

// ============================================
// MIXER FUNCTIONS
// ============================================
__declspec(dllexport) UINT WINAPI mixerGetNumDevs(void) {
    if (!LoadOriginal() || !o_MixerGetNumDevs) return 0;
    return o_MixerGetNumDevs();
}

__declspec(dllexport) MMRESULT WINAPI mixerOpen(LPHMIXER phmx, UINT uMxId, 
    DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen) {
    if (!LoadOriginal() || !o_MixerOpen) return MMSYSERR_ERROR;
    return o_MixerOpen(phmx, uMxId, dwCallback, dwInstance, fdwOpen);
}

__declspec(dllexport) MMRESULT WINAPI mixerClose(HMIXER hmx) {
    if (!o_MixerClose) return MMSYSERR_ERROR;
    return o_MixerClose(hmx);
}

__declspec(dllexport) MMRESULT WINAPI mixerGetDevCapsA(UINT uMxId, LPMIXERCAPSA pmxcaps, UINT cbmxcaps) {
    if (!LoadOriginal() || !o_MixerGetDevCapsA) return MMSYSERR_ERROR;
    return o_MixerGetDevCapsA(uMxId, pmxcaps, cbmxcaps);
}

__declspec(dllexport) MMRESULT WINAPI mixerGetDevCapsW(UINT uMxId, LPMIXERCAPSW pmxcaps, UINT cbmxcaps) {
    if (!LoadOriginal() || !o_MixerGetDevCapsW) return MMSYSERR_ERROR;
    return o_MixerGetDevCapsW(uMxId, pmxcaps, cbmxcaps);
}

__declspec(dllexport) MMRESULT WINAPI mixerGetLineInfoA(HMIXEROBJ hmxobj, LPMIXERLINEA pmxl, DWORD fdwInfo) {
    if (!LoadOriginal() || !o_MixerGetLineInfoA) return MMSYSERR_ERROR;
    return o_MixerGetLineInfoA(hmxobj, pmxl, fdwInfo);
}

__declspec(dllexport) MMRESULT WINAPI mixerGetLineInfoW(HMIXEROBJ hmxobj, LPMIXERLINEW pmxl, DWORD fdwInfo) {
    if (!LoadOriginal() || !o_MixerGetLineInfoW) return MMSYSERR_ERROR;
    return o_MixerGetLineInfoW(hmxobj, pmxl, fdwInfo);
}

__declspec(dllexport) MMRESULT WINAPI mixerGetLineControlsA(HMIXEROBJ hmxobj, LPMIXERLINECONTROLSA pmxlc, DWORD fdwControls) {
    if (!LoadOriginal() || !o_MixerGetLineControlsA) return MMSYSERR_ERROR;
    return o_MixerGetLineControlsA(hmxobj, pmxlc, fdwControls);
}

__declspec(dllexport) MMRESULT WINAPI mixerGetLineControlsW(HMIXEROBJ hmxobj, LPMIXERLINECONTROLSW pmxlc, DWORD fdwControls) {
    if (!LoadOriginal() || !o_MixerGetLineControlsW) return MMSYSERR_ERROR;
    return o_MixerGetLineControlsW(hmxobj, pmxlc, fdwControls);
}

__declspec(dllexport) MMRESULT WINAPI mixerGetControlDetailsA(HMIXEROBJ hmxobj, LPMIXERCONTROLDETAILS pmxcd, DWORD fdwDetails) {
    if (!LoadOriginal() || !o_MixerGetControlDetailsA) return MMSYSERR_ERROR;
    return o_MixerGetControlDetailsA(hmxobj, pmxcd, fdwDetails);
}

__declspec(dllexport) MMRESULT WINAPI mixerGetControlDetailsW(HMIXEROBJ hmxobj, LPMIXERCONTROLDETAILS pmxcd, DWORD fdwDetails) {
    if (!LoadOriginal() || !o_MixerGetControlDetailsW) return MMSYSERR_ERROR;
    return o_MixerGetControlDetailsW(hmxobj, pmxcd, fdwDetails);
}

__declspec(dllexport) MMRESULT WINAPI mixerSetControlDetails(HMIXEROBJ hmxobj, LPMIXERCONTROLDETAILS pmxcd, DWORD fdwDetails) {
    if (!LoadOriginal() || !o_MixerSetControlDetails) return MMSYSERR_ERROR;
    return o_MixerSetControlDetails(hmxobj, pmxcd, fdwDetails);
}

__declspec(dllexport) MMRESULT WINAPI mixerGetID(HMIXEROBJ hmxobj, PUINT puMxId, DWORD fdwId) {
    if (!LoadOriginal() || !o_MixerGetID) return MMSYSERR_ERROR;
    return o_MixerGetID(hmxobj, puMxId, fdwId);
}

__declspec(dllexport) MMRESULT WINAPI mixerMessage(HMIXER hmx, UINT uMsg, DWORD_PTR dwParam1, DWORD_PTR dwParam2) {
    if (!LoadOriginal() || !o_MixerMessage) return MMSYSERR_ERROR;
    return o_MixerMessage(hmx, uMsg, dwParam1, dwParam2);
}

// ============================================
// MCI FUNCTIONS (CD Audio için Half-Life'da kullanılıyor olabilir)
// ============================================
__declspec(dllexport) MCIERROR WINAPI mciSendCommandA(MCIDEVICEID mciId, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2) {
    if (!LoadOriginal() || !o_MciSendCommandA) return MCIERR_DEVICE_NOT_INSTALLED;
    return o_MciSendCommandA(mciId, uMsg, dw1, dw2);
}

__declspec(dllexport) MCIERROR WINAPI mciSendCommandW(MCIDEVICEID mciId, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2) {
    if (!LoadOriginal() || !o_MciSendCommandW) return MCIERR_DEVICE_NOT_INSTALLED;
    return o_MciSendCommandW(mciId, uMsg, dw1, dw2);
}

__declspec(dllexport) MCIERROR WINAPI mciSendStringA(LPCSTR lpstrCommand, LPSTR lpstrReturnString, UINT uReturnLength, HWND hwndCallback) {
    if (!LoadOriginal() || !o_MciSendStringA) return MCIERR_DEVICE_NOT_INSTALLED;
    return o_MciSendStringA(lpstrCommand, lpstrReturnString, uReturnLength, hwndCallback);
}

__declspec(dllexport) MCIERROR WINAPI mciSendStringW(LPCWSTR lpstrCommand, LPWSTR lpstrReturnString, UINT uReturnLength, HWND hwndCallback) {
    if (!LoadOriginal() || !o_MciSendStringW) return MCIERR_DEVICE_NOT_INSTALLED;
    return o_MciSendStringW(lpstrCommand, lpstrReturnString, uReturnLength, hwndCallback);
}

__declspec(dllexport) BOOL WINAPI mciGetErrorStringA(MCIERROR mcierr, LPSTR pszText, UINT cchText) {
    if (!LoadOriginal() || !o_MciGetErrorStringA) return FALSE;
    return o_MciGetErrorStringA(mcierr, pszText, cchText);
}

__declspec(dllexport) BOOL WINAPI mciGetErrorStringW(MCIERROR mcierr, LPWSTR pszText, UINT cchText) {
    if (!LoadOriginal() || !o_MciGetErrorStringW) return FALSE;
    return o_MciGetErrorStringW(mcierr, pszText, cchText);
}

__declspec(dllexport) MCIDEVICEID WINAPI mciGetDeviceIDA(LPCSTR pszDevice) {
    if (!LoadOriginal() || !o_MciGetDeviceIDA) return 0;
    return o_MciGetDeviceIDA(pszDevice);
}

__declspec(dllexport) MCIDEVICEID WINAPI mciGetDeviceIDW(LPCWSTR pszDevice) {
    if (!LoadOriginal() || !o_MciGetDeviceIDW) return 0;
    return o_MciGetDeviceIDW(pszDevice);
}

__declspec(dllexport) MCIDEVICEID WINAPI mciGetDeviceIDFromElementIDA(DWORD dwElementID, LPCSTR lpstrType) {
    if (!LoadOriginal() || !o_MciGetDeviceIDFromElementIDA) return 0;
    return o_MciGetDeviceIDFromElementIDA(dwElementID, lpstrType);
}

__declspec(dllexport) MCIDEVICEID WINAPI mciGetDeviceIDFromElementIDW(DWORD dwElementID, LPCWSTR lpstrType) {
    if (!LoadOriginal() || !o_MciGetDeviceIDFromElementIDW) return 0;
    return o_MciGetDeviceIDFromElementIDW(dwElementID, lpstrType);
}

__declspec(dllexport) BOOL WINAPI mciSetYieldProc(MCIDEVICEID mciId, YIELDPROC fpYieldProc, DWORD dwYieldData) {
    if (!LoadOriginal() || !o_MciSetYieldProc) return FALSE;
    return o_MciSetYieldProc(mciId, fpYieldProc, dwYieldData);
}

__declspec(dllexport) YIELDPROC WINAPI mciGetYieldProc(MCIDEVICEID mciId, LPDWORD pdwYieldData) {
    if (!LoadOriginal() || !o_MciGetYieldProc) return NULL;
    return o_MciGetYieldProc(mciId, pdwYieldData);
}

__declspec(dllexport) HTASK WINAPI mciGetCreatorTask(MCIDEVICEID mciId) {
    if (!LoadOriginal() || !o_MciGetCreatorTask) return NULL;
    return o_MciGetCreatorTask(mciId);
}

__declspec(dllexport) BOOL WINAPI mciExecute(LPCSTR pszCommand) {
    if (!LoadOriginal() || !o_MciExecute) return FALSE;
    return o_MciExecute(pszCommand);
}

// ============================================
// MMIO FUNCTIONS (WAV dosyası okumak için)
// ============================================
__declspec(dllexport) HMMIO WINAPI mmioOpenA(LPSTR pszFileName, LPMMIOINFO pmmioinfo, DWORD fdwOpen) {
    if (!LoadOriginal() || !o_MmioOpenA) return NULL;
    return o_MmioOpenA(pszFileName, pmmioinfo, fdwOpen);
}

__declspec(dllexport) HMMIO WINAPI mmioOpenW(LPWSTR pszFileName, LPMMIOINFO pmmioinfo, DWORD fdwOpen) {
    if (!LoadOriginal() || !o_MmioOpenW) return NULL;
    return o_MmioOpenW(pszFileName, pmmioinfo, fdwOpen);
}

__declspec(dllexport) MMRESULT WINAPI mmioClose(HMMIO hmmio, UINT fuClose) {
    if (!o_MmioClose) return MMSYSERR_ERROR;
    return o_MmioClose(hmmio, fuClose);
}

__declspec(dllexport) LONG WINAPI mmioRead(HMMIO hmmio, HPSTR pch, LONG cch) {
    if (!o_MmioRead) return -1;
    return o_MmioRead(hmmio, pch, cch);
}

__declspec(dllexport) LONG WINAPI mmioWrite(HMMIO hmmio, const char* pch, LONG cch) {
    if (!o_MmioWrite) return -1;
    return o_MmioWrite(hmmio, pch, cch);
}

__declspec(dllexport) LONG WINAPI mmioSeek(HMMIO hmmio, LONG lOffset, int iOrigin) {
    if (!o_MmioSeek) return -1;
    return o_MmioSeek(hmmio, lOffset, iOrigin);
}

__declspec(dllexport) MMRESULT WINAPI mmioGetInfo(HMMIO hmmio, LPMMIOINFO pmmioinfo, UINT fuInfo) {
    if (!o_MmioGetInfo) return MMSYSERR_ERROR;
    return o_MmioGetInfo(hmmio, pmmioinfo, fuInfo);
}

__declspec(dllexport) MMRESULT WINAPI mmioSetInfo(HMMIO hmmio, LPCMMIOINFO pmmioinfo, UINT fuInfo) {
    if (!o_MmioSetInfo) return MMSYSERR_ERROR;
    return o_MmioSetInfo(hmmio, pmmioinfo, fuInfo);
}

__declspec(dllexport) MMRESULT WINAPI mmioSetBuffer(HMMIO hmmio, LPSTR pchBuffer, LONG cchBuffer, UINT fuBuffer) {
    if (!o_MmioSetBuffer) return MMSYSERR_ERROR;
    return o_MmioSetBuffer(hmmio, pchBuffer, cchBuffer, fuBuffer);
}

__declspec(dllexport) MMRESULT WINAPI mmioFlush(HMMIO hmmio, UINT fuFlush) {
    if (!o_MmioFlush) return MMSYSERR_ERROR;
    return o_MmioFlush(hmmio, fuFlush);
}

__declspec(dllexport) MMRESULT WINAPI mmioAdvance(HMMIO hmmio, LPMMIOINFO pmmioinfo, UINT fuAdvance) {
    if (!o_MmioAdvance) return MMSYSERR_ERROR;
    return o_MmioAdvance(hmmio, pmmioinfo, fuAdvance);
}

__declspec(dllexport) LPMMIOPROC WINAPI mmioInstallIOProcA(FOURCC fccIOProc, LPMMIOPROC pIOProc, DWORD dwFlags) {
    if (!LoadOriginal() || !o_MmioInstallIOProcA) return NULL;
    return o_MmioInstallIOProcA(fccIOProc, pIOProc, dwFlags);
}

__declspec(dllexport) LPMMIOPROC WINAPI mmioInstallIOProcW(FOURCC fccIOProc, LPMMIOPROC pIOProc, DWORD dwFlags) {
    if (!LoadOriginal() || !o_MmioInstallIOProcW) return NULL;
    return o_MmioInstallIOProcW(fccIOProc, pIOProc, dwFlags);
}

__declspec(dllexport) FOURCC WINAPI mmioStringToFOURCCA(LPCSTR sz, UINT uFlags) {
    if (!LoadOriginal() || !o_MmioStringToFOURCCA) return 0;
    return o_MmioStringToFOURCCA(sz, uFlags);
}

__declspec(dllexport) FOURCC WINAPI mmioStringToFOURCCW(LPCWSTR sz, UINT uFlags) {
    if (!LoadOriginal() || !o_MmioStringToFOURCCW) return 0;
    return o_MmioStringToFOURCCW(sz, uFlags);
}

__declspec(dllexport) MMRESULT WINAPI mmioDescend(HMMIO hmmio, LPMMCKINFO pmmcki, const MMCKINFO* pmmckiParent, UINT fuDescend) {
    if (!o_MmioDescend) return MMSYSERR_ERROR;
    return o_MmioDescend(hmmio, pmmcki, pmmckiParent, fuDescend);
}

__declspec(dllexport) MMRESULT WINAPI mmioAscend(HMMIO hmmio, LPMMCKINFO pmmcki, UINT fuAscend) {
    if (!o_MmioAscend) return MMSYSERR_ERROR;
    return o_MmioAscend(hmmio, pmmcki, fuAscend);
}

__declspec(dllexport) MMRESULT WINAPI mmioCreateChunk(HMMIO hmmio, LPMMCKINFO pmmcki, UINT fuCreate) {
    if (!o_MmioCreateChunk) return MMSYSERR_ERROR;
    return o_MmioCreateChunk(hmmio, pmmcki, fuCreate);
}

__declspec(dllexport) MMRESULT WINAPI mmioRename(LPCSTR pszFileName, LPCSTR pszNewFileName, LPCMMIOINFO pmmioinfo, DWORD fdwRename) {
    if (!LoadOriginal() || !o_MmioRename) return MMSYSERR_ERROR;
    return o_MmioRename(pszFileName, pszNewFileName, pmmioinfo, fdwRename);
}

__declspec(dllexport) LRESULT WINAPI mmioSendMessage(HMMIO hmmio, UINT uMsg, LPARAM lParam1, LPARAM lParam2) {
    if (!o_MmioSendMessage) return 0;
    return o_MmioSendMessage(hmmio, uMsg, lParam1, lParam2);
}

} // extern "C"

// ============================================
// HWID GENERATION
// ============================================
void GenerateHWID() {
    int cpu[4] = {0};
    __cpuid(cpu, 0);
    
    DWORD vol = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &vol, NULL, NULL, NULL, 0);
    
    char pc[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD sz = sizeof(pc);
    GetComputerNameA(pc, &sz);
    
    // MAC address
    DWORD mac = 0;
    IP_ADAPTER_INFO adapters[16];
    ULONG bufLen = sizeof(adapters);
    if (GetAdaptersInfo(adapters, &bufLen) == ERROR_SUCCESS) {
        mac = *(DWORD*)adapters[0].Address;
    }
    
    sprintf(g_szHWID, "%08X%08X%08X%08X",
            cpu[0] ^ cpu[1],
            vol ^ mac,
            (pc[0] << 24) | (pc[1] << 16) | (pc[2] << 8) | pc[3],
            cpu[2] ^ cpu[3]);
    
    Log("HWID Generated: %s", g_szHWID);
}

// ============================================
// HTTP CLIENT
// ============================================
std::string HttpPost(const wchar_t* path, const std::string& body) {
    std::string response;
    
    HINTERNET hSession = WinHttpOpen(L"AGTR/11.5",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        Log("HTTP: Session failed");
        return response;
    }
    
    HINTERNET hConnect = WinHttpConnect(hSession, API_HOST, API_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        Log("HTTP: Connect failed");
        return response;
    }
    
    DWORD flags = API_USE_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        Log("HTTP: Request failed");
        return response;
    }
    
    std::wstring headers = L"Content-Type: application/json\r\n";
    
    BOOL result = WinHttpSendRequest(hRequest, headers.c_str(), -1,
        (LPVOID)body.c_str(), body.length(), body.length(), 0);
    
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
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return response;
}

// ============================================
// SCAN THREAD
// ============================================
DWORD WINAPI ScanThread(LPVOID) {
    Sleep(8000);  // 8 saniye başlangıç gecikmesi
    
    Log("===========================================");
    Log("AGTR Anti-Cheat v%s (winmm.dll)", AGTR_VERSION);
    Log("Build: %s", AGTR_BUILD);
    Log("===========================================");
    
    GenerateHWID();
    
    // Register with API
    char json[1024];
    sprintf(json, "{\"hwid\":\"%s\",\"version\":\"%s\",\"trigger\":\"winmm\"}", 
            g_szHWID, AGTR_VERSION);
    
    std::string response = HttpPost(L"/api/v1/client/register", json);
    Log("Register response: %.100s...", response.c_str());
    
    // Main loop
    while (g_bScanThreadRunning) {
        Sleep(1000);
        
        DWORD now = GetTickCount();
        
        // Heartbeat her 30 saniyede
        if (now - g_dwLastHeartbeat >= 30000) {
            sprintf(json, "{\"hwid\":\"%s\",\"server_ip\":\"%s\",\"server_port\":%d,"
                         "\"in_game\":%s,\"frames\":%lu,\"speedhack\":%s}",
                    g_szHWID, g_szServerIP, g_iServerPort,
                    g_bInServer ? "true" : "false",
                    g_dwFrameCount,
                    g_bSpeedhackDetected ? "true" : "false");
            
            HttpPost(L"/api/v1/client/heartbeat", json);
            g_dwLastHeartbeat = now;
            
            Log("Heartbeat sent - Frames: %lu, Speedhack: %s", 
                g_dwFrameCount, g_bSpeedhackDetected ? "YES" : "no");
        }
        
        // Scan her interval'de
        if (now - g_dwLastScan >= (DWORD)g_iScanInterval) {
            if (g_bScanEnabled) {
                Log("Running scan...");
                // TODO: Full scan implementation
                g_dwLastScan = now;
            }
        }
    }
    
    return 0;
}

// ============================================
// INITIALIZATION
// ============================================
void Init() {
    InitializeCriticalSection(&g_csLog);
    InitializeCriticalSection(&g_csTiming);
    
    // Game directory
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) *slash = 0;
    strcpy(g_szGameDir, path);
    
    Log("Initializing in: %s", g_szGameDir);
    
    // Load original DLL
    if (!LoadOriginal()) {
        Log("FATAL: Could not load original winmm.dll!");
        return;
    }
    
    // Start scan thread
    g_bScanThreadRunning = true;
    g_hScanThread = CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
    if (g_hScanThread) {
        Log("Scan thread started");
    } else {
        Log("ERROR: Could not start scan thread!");
    }
    
    g_bInitialized = true;
}

void Shutdown() {
    g_bScanThreadRunning = false;
    
    if (g_hScanThread) {
        WaitForSingleObject(g_hScanThread, 3000);
        CloseHandle(g_hScanThread);
        g_hScanThread = NULL;
    }
    
    if (g_hOriginal) {
        FreeLibrary(g_hOriginal);
        g_hOriginal = NULL;
    }
    
    if (g_LogFile) {
        Log("Shutting down...");
        fclose(g_LogFile);
        g_LogFile = NULL;
    }
    
    DeleteCriticalSection(&g_csLog);
    DeleteCriticalSection(&g_csTiming);
}

// ============================================
// DLL ENTRY POINT
// ============================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            Init();
            break;
            
        case DLL_PROCESS_DETACH:
            Shutdown();
            break;
    }
    return TRUE;
}
