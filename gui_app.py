import customtkinter as ctk
from tkinter import messagebox
import threading
from network_manager import NetworkManager
import time

class WifiApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("WiFi Controller Pro - v2.0")
        self.geometry("750x650")
        self.nm = NetworkManager()
        self.active_kill_ip = None # Şu an engellenen cihazı takip eder

        # Başlık ve Tarama Butonu
        self.label = ctk.CTkLabel(self, text="Ağ Kontrol Paneli", font=("Arial", 24, "bold"))
        self.label.pack(pady=20)

        self.scan_btn = ctk.CTkButton(self, text="Cihazları Tara", command=self.start_scan_thread, height=40)
        self.scan_btn.pack(pady=10)

        self.status_label = ctk.CTkLabel(self, text="Durum: Hazır", text_color="gray")
        self.status_label.pack(pady=5)

        self.scroll_frame = ctk.CTkScrollableFrame(self, width=650, height=400, label_text="Ağdaki Cihazlar")
        self.scroll_frame.pack(pady=20, padx=20)

        self.log_label = ctk.CTkLabel(self, text="Canlı Trafik İzleyici", font=("Arial", 14, "bold"))
        self.log_label.pack(pady=(10, 0))

        self.log_box = ctk.CTkTextbox(self, width=650, height=100, fg_color="#1a1a1a", text_color="#00ff00")
        self.log_box.pack(pady=10, padx=20)

    def start_scan_thread(self):
        self.scan_btn.configure(state="disabled", text="Taranıyor...")
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        # Kendi ağ aralığınıza göre düzenleyin
        devices = self.nm.scan_network("192.168.1.1/24")
        self.after(0, lambda: self.render_devices(devices))

    def render_devices(self, devices):
        if not devices:
            ctk.CTkLabel(self.scroll_frame, text="Cihaz bulunamadı.").pack()
        else:
            for dev in devices:
                self.create_device_item(dev)
        self.scan_btn.configure(state="normal", text="Cihazları Tara")

    def create_device_item(self, dev):
        frame = ctk.CTkFrame(self.scroll_frame)
        frame.pack(fill="x", pady=5, padx=5)

        info_text = f"Cihaz: {dev['name']}\nIP: {dev['ip']} | MAC: {dev['mac']}"
        label = ctk.CTkLabel(frame, text=info_text, justify="left", font=("Arial", 12))
        label.pack(side="left", padx=15, pady=10)

        # Butonu oluştururken referansını saklıyoruz ki durumunu değiştirebilelim
        action_btn = ctk.CTkButton(frame, text="İnterneti Kes", fg_color="#d32f2f", hover_color="#b71c1c", width=140)
        action_btn.configure(command=lambda d=dev, b=action_btn: self.toggle_connection(d, b))
        action_btn.pack(side="right", padx=15)

        rename_btn = ctk.CTkButton(frame, text="İsim Ver", width=80, fg_color="#5c5c5c", 
                           command=lambda d=dev: self.open_rename_dialog(d))
        rename_btn.pack(side="right", padx=5)

        monitor_btn = ctk.CTkButton(frame, text="Takip Et", fg_color="#fb8c00", hover_color="#ef6c00", 
                            width=100, command=lambda d=dev: self.toggle_monitoring(d, monitor_btn))
        monitor_btn.pack(side="right", padx=10)

    def toggle_connection(self, device, button):
        # Eğer buton "İnterneti Kes" modundaysa (Kırmızı)
        if button.cget("text") == "İnterneti Kes":
            confirm = messagebox.askyesno("Onay", f"{device['ip']} cihazının internetini kesmek istiyor musunuz?")
            if confirm:
                # Başka bir cihaz engelliyse önce onu durdur
                if self.active_kill_ip:
                    self.nm.stop_disconnect()
                
                # Engellemeyi başlat
                gateway_ip = "192.168.1.1" # Kendi modem IP'nizle güncelleyin
                self.nm.start_disconnect(device['ip'], gateway_ip, device['mac'], self.update_log)
                self.active_kill_ip = device['ip']
                
                # Butonun durumunu güncelle
                button.configure(text="Bağlantıyı Geri Ver", fg_color="#2e7d32", hover_color="#1b5e20")
                self.status_label.configure(text=f"Engelleniyor: {device['ip']}", text_color="#d32f2f")
        
        # Eğer buton "Bağlantıyı Geri Ver" modundaysa (Yeşil)
        else:
            self.nm.stop_disconnect()
            self.active_kill_ip = None
            button.configure(text="İnterneti Kes", fg_color="#d32f2f", hover_color="#b71c1c")
            self.status_label.configure(text="Durum: Bağlantı Geri Verildi", text_color="gray")
            messagebox.showinfo("Bilgi", "Cihazın internet erişimi tekrar sağlandı.")

    def open_rename_dialog(self, device):
       #"""Cihaz ismini değiştirmek için input penceresi açar."""
        dialog = ctk.CTkInputDialog(text=f"{device['ip']} için bir isim girin:", title="Cihazı Tanımla")
        new_name = dialog.get_input()
            
        if new_name:
            self.nm.save_custom_name(device['mac'], new_name)
            messagebox.showinfo("Başarılı", f"'{new_name}' ismi kaydedildi.\nListeyi güncellemek için tekrar tarama yapın.")
    
    def update_log(self, message):
        """NetworkManager'dan gelen mesajları ekrana yazar."""
        timestamp = time.strftime("%H:%M:%S")
        self.log_box.insert("end", f"[{timestamp}] {message}\n")
        self.log_box.see("end") # Otomatik aşağı kaydır

    def toggle_monitoring(self, device, button):
        if button.cget("text") == "Takip Et":
            # Takibi başlat
            gateway_ip = "192.168.1.1" # Kendi gateway IP'n
            self.nm.start_monitoring(device['ip'], gateway_ip, device['mac'], self.update_log)
            
            button.configure(text="Takibi Bırak", fg_color="#546e7a", hover_color="#455a64")
            self.status_label.configure(text=f"İzleniyor: {device['ip']}", text_color="#fb8c00")
        else:
            # Takibi durdur
            self.nm.stop_monitoring()
            button.configure(text="Takip Et", fg_color="#fb8c00", hover_color="#ef6c00")
            self.status_label.configure(text="Durum: İzleme Durduruldu", text_color="gray")

if __name__ == "__main__":
    app = WifiApp()
    app.mainloop()