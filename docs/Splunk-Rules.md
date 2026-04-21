# Sentryfy — Splunk Tabanlı Gerçek Zamanlı SIEM Dashboard

Windows loglarını Splunk ile izleyen, SPL sorguları ve özel kurallarla logları tespit eden, Telegram bildirimi gönderen ve canlı React dashboard'u olan bir güvenlik izleme projesi.

---

## Mimari

```
Windows Event Logs → Splunk Enterprise → Alert (Webhook) → Node.js Backend → React Dashboard
                                                                         ↓
                                                                  Telegram Bot
```

---

### A- BRUTE FORCE 

### 1. Sigma ile Brute Force Kuralı Yazıyoruz

Rules klasöründe yazmış olduğumuz Brute Force saldırılarını tespit etmemize imkan sağlayan kuralımızı Sigma formatında yazıyoruz. Ardından bu kuralı Splunk formatına convert ediyoruz. Sigma bize otomatik olarak Splunk sorgusu üretiyor. Bu sorguyu Splunk sisteminde log tespiti ve alert üretmek gibi alanlarda daha sonra kullanacağız.

Kural Dosyasına ulaşmak için linke tıklayınız.
- [Sigma Rule (YML Format)](../Rules/brute-force.yml) 👈 

### 2. PowerShell ile Test Amaaçlı Brute Force Denemesi

Powershell'i yönetici olarak çalıştırıyoruz. Ardından Windows loglarını izleyen Splunk için aşağıdaki komut ile sahte bir brute force saldırısı gerçekleştiriyoruz.

![splunk alert config](../screenshots/splunk-bruteforce-2.png?v=2)

### 3. Splunk Sisteminde Log Kontrolü 

Convert etmiş olduğumuz Splunk sorgusunu kullanma vakti geldi. Splunk'ın Search&Reporting kısmındaki Search Bar'a convert etmiş olduğumuz sorguyu yapıştırıyoruz. Test sonucunda Splunk sistemine brute force logunun düştüğünü görüyoruz. Bu logu ister alert olarak ister Splunk içerisinde oluşturacağımız Dashboard alanında grafik olarak yakalayabiliriz. 

![backend webhook code](../screenshots/splunk-bruteforce-1.png?v=2)

### 4. Splunk Dashboard 
"HackerTurkoglu" adlı kullanıcıya yapmış olduğumuz brute force saldırısını Splunk'ta oluşturmuş olduğumuz Dashboard ekranında Pie Chart grafiği ile takip edebiliyoruz. Bu grafikte her kullanıcıya yapılan saldırı miktarını takip edebiliriz.

![sigma rule](../screenshots/splunk-bruteforce-3.png?v=2)



### 5. Telegram Bildirimi

Telegram uygulamasına express ile yapılandırdığımız bot araclığıyla anlık bildirimlerin gelmesi 

![splunk search results](../screenshots/splunk-bruteforce-4.png?v=2)


---

### B- SUSPICIOUS POWERSHELL COMMAND

### 1. Sigma Aracılığıyla Kural Yazımı

Şüpheli powershell komutlarını tespit etmek amacıyla Sigma ile kural yazıyoruz ve convert ile Splunk sorgusu formatına uyarlıyoruz.

Yazdığımız kuralda bazı şüpheli komutları yakalamak istememizin sebebi:
-enc komutu : Base64 encode edip komutun içeriğini gizlemek için kullanılır.
-w hidden komutu : script arka planda çalışır ve kullanıcıya herhangi bir pencerede gösterilmez.

Kural Dosyasına ulaşmak için linke tıklayınız.
- [Sigma Rule (YML Format)](../Rules/suspicious-command.yml) 👈 


### 2. Kuralı test etme aşaması 

Yazdığımız kuralı test etmek için kasıtlı olarak powershell üzerinden test gerçekleştiriyoruz.

![splunk rule test](../screenshots/splunk-ps-1.png?v=2)


### 3. Splunk Üzerinden Log Kontrolü

Testimizi yaptıktan sonra Splunk Search üzerinden convert etmiş olduğumuz sorgu ile arama gerçekleştiriyoruz.

![splunk search results](../screenshots/splunk-ps-2.png?v=2)

Yazdığımız sorgunun aynı zamanda standart Windows süreçlerinde false positive (noise) ürettiğini görüyoruz :

![splunk search results](../screenshots/splunk-ps-3.png?v=2)

Dolayısıyla Sigma kuralında ve Splunk sorgusunda bu durumu gidermemiz için eklemeler yapmamız gerekiyor:

``
filter_driverstore:
    ParentProcessName|contains:
      - '\DriverStore\FileRepository\'
      - '\Windows\System32\msiexec.exe'
      - '\Windows\SoftwareDistribution\'
``  
filter_driverstore ile eğer bu şüpheli görünen PowerShell işlemini başlatan "baba" süreç (ParentProcessName), sürücü deposu (DriverStore), Windows Installer (msiexec.exe) veya Windows Update (SoftwareDistribution) klasöründen geliyorsa, "Bu sistemin kendi işidir, dokunma" diyoruz.

NOT: Diyelim ki bir saldırgan sisteme sızdı ve bir şekilde msiexec.exe (Windows Installer) sürecine kod enjekte etti. Eğer saldırgan, PowerShell zararlısını bu "güvenilir" görünen msiexec.exe üzerinden başlatırsa yazdığımız kural filtreye takılır ve alarm üretmez.

Bknz: 
MITRE ATT&CK
T1218.007 — Signed Binary Proxy Execution: Msiexec
T1055 — Process Injection

Buna önlem olarak; her detection rule'un filter vs coverage trade-off'u vardır. Msiexec'i filtrelemek FP'yi azaltır ama T1218.007 defense evasion vektörünü açar. Bu yüzden Sentryfy'da defense-in-depth yaklaşımını kullanacağız:

Layer 1: Process creation (4688) — filter'lı, low noise
Layer 2: Process injection (Sysmon 8/10) — filter'sız, injection yakalar
Layer 3: Parent chain correlation — anormal parent-of-parent ilişkileri tespit eder


Splunk sorgumuzu yazmış olduğumuz yeni kurala göre güncelledikten sonra log kontrolümüzü yapıyoruz ve false positive bildirimlerinin kaybolduğunu gözlemliyoruz

![splunk search results](../screenshots/splunk-ps-4.png?v=2) 



### C- Unauthorized USB Device Connected

Sistemimize yabancı USB araçları takıldığında alert üretmesi için kural yazıyoruz

### 1. Sigma Aracılığıyla Kural Yazımı : 

Kural Dosyasına ulaşmak için linke tıklayınız.
- [Sigma Rule (YML Format)](../Rules/unauthorize_usb.yml) 👈 


### 2. Kuralı test etme aşaması

Kuraldaki whitelist alanında bulunmayab bir USB cihazını bilgisayarımıza takıyoruz.

### 3. Splunk üzerinden log kontrolü 

Gördüğümüz gibi Windows'un yazıcı sürücüleri ve ses aygıtları da "Plug and Play"(Tak-Çalıştır) mekanizmasına ait olduğu için bu aygıtların loglarını da false positive olarak almaya başladık. Oysa bizim isteğimiz sadece dışarıdan fiziksel olarak takılan yabancı USB cihazlarını tespit etmek

![splunk search results](../screenshots/splunk-usb-1.png?v=2)

Bu sebeple kuralımıza aşağıdaki filtrelemeyi ekliyoruz:

``
filter_noise:
    win.eventdata.className:
      - 'PrintQueue'          # Sanal yazıcı kuyrukları
      - 'SoftwareDevice'      # Yazılımsal sanal cihazlar
      - 'AudioEndpoint'       # Ses aygıtı tak/çıkar gürültüsü
    win.eventdata.deviceDescription|contains:
      - 'Microsoft Print to PDF'
      - 'Root Print Queue'
      - 'Generic software device
``

Aşağıda gördüğümüz gibi false positive logları engellemiş olduk

![splunk search results](../screenshots/splunk-usb-2.png?v=2)