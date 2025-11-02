Telegram Phishing Domain Detector


Bu proje, belirlenen bir domain listesini sürekli olarak izleyen ve phishing (oltalama) belirtileri gösteren web sitelerini tespit eden gelişmiş bir Python botudur. Şüpheli bir domain bulunduğunda, bot anında Telegram üzerinden ilgili gruba tüm analiz detaylarını içeren bir uyarı mesajı gönderir.

🌟 Temel Özellikler
Gelişmiş Analiz: Sadece domain adına bakmaz; HTTP içeriğini, DNS kayıtlarını ve WHOIS bilgilerini analiz eder.

Akıllı Skorlama: Bir sitenin ne kadar tehlikeli olduğunu belirlemek için birden fazla faktörü (şifre giriş formları, domain yaşı, şüpheli anahtar kelimeler) kullanan bir skorlama sistemi kullanır.

Anlık Telegram Bildirimleri: Tespit edilen her şüpheli domain için anında, zengin formatlı ve detaylı bir Telegram mesajı gönderir.

Etkileşimli Bot Arayüzü: Telegram komutları (/tara, /durdur, /bilgi) ve butonlar aracılığıyla kolayca yönetilebilir.

Sürekli & Tek Seferlik Tarama: Hem anlık tek seferlik tarama yapabilir hem de sürekli izleme modunda çalışabilir.

Detaylı Loglama: Tüm işlemleri monitor.log dosyasına ve bulunan tüm şüpheli domainleri found_suspicious_domains.txt dosyasına kaydeder.

📸 Örnek Bildirim Görüntüsü
Bot şüpheli bir domain bulduğunda, gruba aşağıdaki gibi detaylı bir rapor gönderir:

🔴 *ŞÜPHELİ DOMAIN TESPİT EDİLDİ*
━━━━━━━━━━━━━━━━━━━━━━━━━━━

🌐 *Domain:*
`orneksite-giris.com`

📊 *Tehlike Seviyesi:* KRİTİK
📈 *Güvenlik Skoru:* 14/20
🔗 *IP Adresi:* `123.45.67.89`

🌐 *WEB BİLGİLERİ*
━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔗 *Tam URL:*
`https_//orneksite-giris.com/login/auth.php`

📄 *Sayfa Başlığı:*
_Banka Hesabınıza Giriş Yapın_

📋 *WHOIS BİLGİLERİ*
━━━━━━━━━━━━━━━━━━━━━━━━━━━
📅 *Kayıt Tarihi:* 01 Kasım 2025
⏳ *Domain Yaşı:* 1 gün ⚠️ *ÇOK YENİ*

⚠️ *TESPİT NEDENLERİ*
━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Şifre giriş formu tespit edildi
2. Başlıkta şüpheli kelime: giriş
3. Çok yeni domain (1 gün)
4. URL'de şüpheli yol: login, auth

🕐 *Tespit Zamanı:*
02 Kasım 2025, 18:00:00
🛠️ Kurulum
Projeyi çalıştırmak için aşağıdaki adımları izleyin:

1. Projeyi Klonlayın:

Bash

git clone https://github.com/SENIN_KULLANICI_ADIN/telegram-phishing-domain-detector.git
cd telegram-phishing-domain-detector


2. (Öneri) Sanal Ortam (Virtual Environment) Oluşturun:

Bash

python -m venv venv
Linux/macOS: source venv/bin/activate

Windows: .\venv\Scripts\activate



3. Gerekli Bağımlılıkları Yükleyin: Proje dizininde bulunan requirements.txt dosyasını kullanarak tüm gerekli Python kütüphanelerini kurun.

Bash

pip install -r requirements.txt


⚙️ Yapılandırma
Botu çalıştırabilmek için iki temel bilgiye ihtiyacınız var: Telegram Bot Token ve Grup Chat ID.

1. Telegram Bot Token Alın:

Telegram'da @BotFather ile bir konuşma başlatın.

/newbot komutunu gönderin ve botunuz için bir isim ve kullanıcı adı belirleyin.

BotFather size 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11 formatında bir API token verecektir. Bu token'ı kopyalayın.



2. Grup Chat ID Alın:

Oluşturduğunuz botu uyarıları göndermek istediğiniz Telegram grubuna ekleyin ve yönetici yapın.

Gruba herhangi bir mesaj gönderin.

Botun Chat ID'sini almanın en kolay yolu, bota @userinfobot gibi bir botu gruba ekleyip ID'yi öğrenmek veya aşağıdaki URL'i kullanmaktır: https://api.telegram.org/bot<TOKEN_BURAYA>/getUpdates (Tarayıcıda bu adresi açtığınızda, chat bölümünde -100... ile başlayan ID'yi bulun.)



3. Kodu Düzenleyin: monitor_bot.py dosyasını açın ve en üstteki yapılandırma bölümünü kendi bilgilerinizle doldurun:

Python

# ------------- YAPILANDIRMA - BURAYI DÜZENLE! -------------
TELEGRAM_TOKEN = "BURAYA_BOT_TOKENINIZI_GIRIN"
GROUP_CHAT_ID = "-100ILE_BASLAYAN_GRUP_ID_GIRIN"
# ---------------------------------------------------------
🚀 Çalıştırma
1. Domain Listenizi Oluşturun: Proje ana dizininde domains.txt adında bir dosya oluşturun. İzlemek istediğiniz domain'leri her satıra bir tane gelecek şekilde bu dosyaya ekleyin.

Örnek domains.txt içeriği:

google.com
ornek-bankasi-giris.com
facebook.com
benim-sitem.net
login-hesap-dogrulama.org
2. Botu Başlatın: Terminal üzerinden aşağıdaki komut ile botu başlatın.

Bash

python monitor_bot.py
Bot başarıyla başlatıldığında terminalde "BOT ÇALIŞIYOR!" mesajını göreceksiniz.



🤖 Bot Komutları
Botu yönetmek için Telegram grubunuzda aşağıdaki komutları kullanabilirsiniz (Yalnızca grup yöneticileri kullanabilir):

/start veya /baslat: Botu başlatır ve temel bilgileri gösterir.

/tara: domains.txt listesini tek seferlik tarar.

/surekli_tarama: Taramayı sürekli moda alır. Bot, bir tarama bittikten sonra belirlediğiniz aralıkla (veya anında) yeni taramaya başlar.

/durdur: Aktif olan taramayı durdurur.

/bilgi: Mevcut taramanın anlık durumunu gösterir (ilerleme, bulunanlar, kalan süre vb.).

/istatistik: Toplam tespit sayısı, en tehlikeli domainler gibi genel istatistikleri sunar.

/gecmis: Tespit edilen son 10 şüpheli domain'i listeler.

/yardim: Tüm komutların listesini ve açıklamalarını gösterir.





⚖️ Lisans
Bu proje MIT Lisansı altında lisanslanmıştır. Detaylar için LICENSE dosyasına bakınız.



⚠️ Sorumluluk Reddi
Bu araç, siber güvenlik araştırmaları ve eğitim amaçlı oluşturulmuştur. Aracın kullanımıyla ilgili tüm sorumluluk kullanıcıya aittir. Yasa dışı faaliyetler için kullanılması kesinlikle tavsiye edilmez.
