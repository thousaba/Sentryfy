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
