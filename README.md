# AGTR Anti-Cheat v11.5

Half-Life / Adrenaline Gamer için profesyonel anti-cheat sistemi.

## 🎯 Özellikler

- **%99.9 Garantili Tetikleme** - winmm.dll proxy ile her oyuncuda çalışır
- **Speedhack Tespiti** - Otomatik timing analizi
- **Process Scanner** - Şüpheli programları tespit eder
- **Blacklist Sistemi** - Hash bazlı cheat tespiti
- **Discord Webhook** - Anlık bildirimler
- **Admin Panel** - Web tabanlı yönetim

## 📦 İndirme

[Releases](../../releases) sayfasından en son sürümü indirin.

## 🔧 Kurulum

### Client (Oyuncu) Kurulumu

1. `winmm.dll` dosyasını indirin
2. Half-Life klasörüne kopyalayın:
   ```
   C:\Program Files (x86)\Steam\steamapps\common\Half-Life\winmm.dll
   ```
3. Oyunu başlatın
4. `agtr_winmm.log` dosyasını kontrol edin

### Server (Sunucu) Kurulumu

1. `agtr_api.py` dosyasını sunucunuza yükleyin
2. MySQL veritabanını yapılandırın
3. API'yi başlatın: `python agtr_api.py`
4. Admin paneline erişin: `http://sunucu-ip:5000/admin`

## 🏗️ Derleme (Build)

GitHub Actions otomatik olarak derler. Manuel derleme için:

```cmd
# x86 Native Tools Command Prompt açın
cd src
cl /O2 /MT /LD agtr_winmm.cpp /link /DEF:winmm.def /OUT:winmm.dll ^
   winmm.lib winhttp.lib ws2_32.lib iphlpapi.lib psapi.lib advapi32.lib
```

## ⚙️ Yapılandırma

`agtr_winmm.cpp` içinde:

```cpp
#define API_HOST L"185.171.25.137"  // API sunucu IP
#define API_PORT 5000                // API port
```

## 📊 Nasıl Çalışır?

```
Half-Life başlar
       │
       ▼
winmm.dll yüklenir (bizim proxy)
       │
       ▼
timeGetTime() her frame hook'lanır
       │
       ├─► Speedhack tespiti (timing ratio)
       ├─► Frame sayacı
       └─► Heartbeat gönderimi
       │
       ▼
API'ye veri gönderilir
       │
       ▼
Blacklist kontrolü + Ban sistemi
```

## 🛡️ Tespit Edilen Hileler

- Speedhack (timing manipulation)
- Cheat Engine
- Process Hacker
- ArtMoney
- Bilinen cheat DLL'leri
- Şüpheli pencere başlıkları

## 📝 Log Dosyası

`Half-Life/agtr_winmm.log`:

```
[12:34:56.789] AGTR Anti-Cheat v11.5 (winmm.dll)
[12:34:56.790] HWID Generated: XXXXXXXX...
[12:34:56.791] Scan thread started
[12:35:26.800] Heartbeat sent - Frames: 1847, Speedhack: no
```

## 🔗 İlgili Projeler

- [AGTR Discord Bot](link) - Oyuncu istatistikleri
- [AGTR AMX Plugin](link) - Sunucu tarafı entegrasyon

## 📄 Lisans

Bu proje AGTR (Adrenaline Gamer Turkey) tarafından geliştirilmiştir.

## 🤝 Katkıda Bulunma

Pull request'ler kabul edilir. Büyük değişiklikler için önce issue açın.
