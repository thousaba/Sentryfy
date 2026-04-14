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

## Kurulum & Yapılandırma

### 1. SPL Sorgusu — Brute Force Tespiti

Windows Security loglarından başarısız giriş denemeleri (EventCode=4625) sorgulandı. Aynı host'tan 3'ten fazla başarısız giriş brute force olarak işaretlendi. Henüz yapılandırılmış bir kural olmadığı tespit edildi.

![splunk spl search](screenshots/splunk-ss1.png?v=2)

### 2. Splunk Alert Tanımlama

Brute force tespiti için `Brute Force - Failed Login Detection` adında Real-time alert oluşturuldu. Alert tetiklendiğinde backend'e webhook POST isteği gönderecek şekilde yapılandırıldı.

![splunk alert config](screenshots/splunk-ss2.png?v=2)

### 3. Backend Webhook Kodu

Express ile gelen Splunk alert verisini işleyen endpoint yazıldı. Alert alındığında Telegram Bot üzerinden anlık bildirim gönderildi.

![backend webhook code](screenshots/splunk-ss3.png?v=2)

### 4. Sigma Kural Dosyası

Brute force tespiti için taşınabilir Sigma formatında kural tanımlandı ve Splunk SPL sorgusuna dönüştürüldü.

![sigma rule](screenshots/splunk-ss5.png?v=2)

---

## Test

### Başarısız Giriş Denemelerinin Splunk'ta Görünmesi

EventCode=4625 olaylarının Splunk'a düştüğü ve sorgunun sonuç ürettiği doğrulandı.

![splunk search results](screenshots/splunk-ss4.png?v=2)


## Telegram Bildirimi

Telegram uygulamasına express ile yapılandırdığımız bot araclığıyla anlık bildirimlerin gelmesi 

![splunk search results](screenshots/splunk-ss6.png?v=2)

