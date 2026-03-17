# WiFi Controller Pro

Windows icin basit bir yerel ag yonetim araci. Agdaki cihazlari tarar, cihazlara isim verebilir ve secilen cihazin internet erisimini gecici olarak kesip geri verebilir. Arayuz customtkinter ile yazilmistir.

## Ozellikler

- Yerel ag cihazlarini tarama (IP/MAC/cihaz adi)
- Cihaza ozel isim atama ve kalici kaydetme
- Secilen cihazin internetini gecici kesme / geri verme
- Canli trafik logu (hedef cihazdan gelen paketleri gosterir)
- Nmap ile cihaz isletim sistemi tahmini

## Gereksinimler

- Windows 10/11
- Python 3.10+ (onerilir)
- Npcap (Scapy icin gerekli)
- Nmap (OS tespiti icin gerekli)

## Kurulum

1) Sanal ortam olustur:

```bash
python -m venv .venv
```

2) Ortami aktif et:

PowerShell:

```bash
.venv\Scripts\Activate.ps1
```

CMD:

```bash
.venv\Scripts\activate
```

3) Bagimliliklari kur:

```bash
pip install -r requirements.txt
```

4) Npcap ve Nmap kur:

- Npcap: https://npcap.com/
- Nmap: https://nmap.org/download.html

## Calistirma

```bash
python main.py
```

## Yapilandirma

Ag tarama ve ag gecidi IP'lerini kendi agina gore guncelle.

- Tarama araligi: [gui_app.py](gui_app.py#L40) icindeki `scan_network("192.***.*.*/**")`
- Gateway IP: [gui_app.py](gui_app.py#L77) icindeki `gateway_ip = "192.***.*.*"`

## Dosyalar

- [main.py](main.py) Uygulama giris noktasi
- [gui_app.py](gui_app.py) Arayuz ve kullanici aksiyonlari
- [network_manager.py](network_manager.py) Ag tarama ve ARP spoofing mantigi
- [known_devices.json](known_devices.json) Cihaz isimleri veritabani
- [requirements.txt](requirements.txt) Python bagimliliklari

## Guvenlik ve Sorumluluk Reddi

Bu proje yalnizca kendi aginizda, izinli cihazlar uzerinde test amaciyla kullanilmalidir. Yetkisiz kullanim yasal sorumluluk dogurabilir.
