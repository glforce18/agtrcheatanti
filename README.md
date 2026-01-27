# AGTR Anti-Cheat v14.1 - Multi-DLL Proxy System

## Genel Bakış

Bu sistem 3 DLL proxy'den oluşur:
- **winmm.dll** - Ana anti-cheat modülü (tam tarama)
- **dinput8.dll** - Tetikleyici proxy (winmm'i yükler)
- **dsound.dll** - Tetikleyici proxy (winmm'i yükler)

## v14.1 Yenilikler (Server Detection Fix)

### Server IP Detection İyileştirmesi
- **Genişletilmiş Port Aralığı:** 27000-27200 (önceden 27000-27100)
- **Daha İyi Server Tespiti:** Tüm port konfigürasyonları destekleniyor
- **Admin Panel Fix:** Artık "unknown server" problemi yok
- **Geriye Uyumlu:** Eski serverlar da destekleniyor

### Değişiklikler
```cpp
// Önceki: 27000-27100
if (remotePort >= 27000 && remotePort <= 27100)

// Yeni: 27000-27200
if (remotePort >= 27000 && remotePort <= 27200)
```

## v12.1 Yenilikler (Security Edition)

### Şifreli String Sistemi
- Tüm API endpoint'leri runtime'da decrypt edilir
- XOR + rotating key ile obfuscation
- Static analiz araçlarına karşı koruma
- User-Agent string de şifreli

### Güvenlik Özellikleri
- DLL Integrity Check
- Anti-Debug Detection (4 method)
- API Hook Detection
- Suspicious Driver Detection
- VM Detection
- Memory Pattern Scan

### Performance Optimizasyonları
- Adaptive Heartbeat (server: 30s, menu: 120s)
- Smart Throttling (aynı veriyi 5dk'da bir)
- Offline Cache (10 request)
- Hash Cache (dosya değişmediyse skip)
- Lazy Loading

## Kurulum

Half-Life klasörüne kopyala:
```
Half-Life/
├── hl.exe
├── winmm.dll      ← Ana modül (ZORUNLU)
├── dinput8.dll    ← Opsiyonel tetikleyici
└── dsound.dll     ← Opsiyonel tetikleyici
```

## Derleme

### Gereksinimler
- Visual Studio 2022
- Windows SDK 10.0.19041.0

### Manuel Derleme
```batch
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars32.bat"

:: winmm.dll (Ana modül)
cl.exe /O2 /MT /LD /EHsc /DWIN32 /D_WINDOWS src\agtr_winmm.cpp ^
  /link /DEF:src\winmm.def winhttp.lib advapi32.lib user32.lib psapi.lib shell32.lib ^
  /OUT:winmm.dll

:: dinput8.dll
cl.exe /O2 /MT /LD /EHsc /DWIN32 /D_WINDOWS src\agtr_dinput8.cpp ^
  /link /DEF:src\dinput8.def winhttp.lib advapi32.lib user32.lib ^
  /OUT:dinput8.dll

:: dsound.dll
cl.exe /O2 /MT /LD /EHsc /DWIN32 /D_WINDOWS src\agtr_dsound.cpp ^
  /link /DEF:src\dsound.def winhttp.lib advapi32.lib user32.lib ^
  /OUT:dsound.dll
```

### GitHub Actions
Repository'e push yaptığında otomatik derlenir.

## API Endpoints

| Endpoint | Açıklama |
|----------|----------|
| `/api/v1/client/register` | İlk kayıt ve ayarlar |
| `/api/v1/client/heartbeat` | Periyodik durum bildirimi |
| `/api/v1/scan` | Tarama sonuçları |

## Tarama Modülleri

1. **Process Scanner** - Cheat engine, artmoney, debugger vs.
2. **Module Scanner** - Inject edilmiş DLL'ler
3. **Window Scanner** - Şüpheli pencere başlıkları
4. **Registry Scanner** - Cheat yazılımı kayıtları
5. **File Scanner** - Oyun klasöründeki şüpheli dosyalar
6. **Memory Pattern Scanner** - Bellekteki cheat signature'ları

## Log Dosyası

`Half-Life/agtr_client.log` dosyasında detaylı loglar tutulur.

## Şifreli String Değiştirme

API IP/port değiştirmek için `agtr_winmm.cpp` dosyasındaki encrypt değerlerini güncelleyin:

```python
# Python ile yeni encrypt değerleri üretme
key = [0xA7, 0x3F, 0x8C, 0x51, 0xD2, 0x6E, 0xB9, 0x04]

def encrypt(text):
    return [ord(c) ^ key[i % len(key)] for i, c in enumerate(text)]

print(encrypt("YENİ_IP_ADRES"))
```

## Lisans

AGTR Private - Tüm hakları saklıdır.
