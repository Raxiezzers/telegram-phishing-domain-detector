# monitor_bot.py
# Versiyon 8.5 - Gelişmiş Telegram Bot - Sürekli Tarama & Detaylı Raporlama

import os
import re
import time
import logging
import requests
import dns.resolver
import whois
import asyncio
import threading
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackContext, CallbackQueryHandler
from telegram.constants import ParseMode

# ------------- YAPILANDIRMA - BURAYI DÜZENLE! -------------
TELEGRAM_TOKEN = "bot-token"
GROUP_CHAT_ID = "-1 ile başlayan grup id niz"
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOMAINS_FILE = os.path.join(BASE_DIR, 'domains.txt')
LOG_FILE = os.path.join(BASE_DIR, 'monitor.log')
FOUND_DOMAINS_FILE = os.path.join(BASE_DIR, 'found_suspicious_domains.txt')

MAX_WORKERS = 5
REQUEST_TIMEOUT = 10
DNS_TIMEOUT = 10
RATE_LIMIT_DELAY = 0.5

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "password", "şifre", "parola", "hesap", "kart",
    "verify", "doğrula", "otp", "giriş", "giris", "banka", "bankası",
    "yatırım", "mobil", "şube", "müşteri", "hesabım", "account"
]
SUSPICION_THRESHOLD = 3

REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'tr-TR,tr;q=0.9,en;q=0.8',
    'Connection': 'close'
}

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# ------------- LOGLAMA -------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ------------- GLOBAL APPLICATION DEĞİŞKENİ -------------
bot_application = None  # Global olarak Application nesnesini saklayacağız
scan_status = {
    "is_scanning": False,
    "stop_requested": False,
    "processed_count": 0,
    "total_domains": 0,
    "suspicious_found": 0,
    "failed_count": 0,
    "start_time": None,
    "last_found": None,
    "scan_number": 0,
    "continuous_mode": False,
    "scan_interval": 300  # Varsayılan 5 dakika
}
status_lock = threading.Lock()
detected_history = []

# ------------- YARDIMCI FONKSİYONLAR -------------
def escape_md(text):
    """MarkdownV2 için özel karakterleri escape eder"""
    if not text:
        return ""
    special = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    for char in special:
        text = str(text).replace(char, f'\\{char}')
    return text

def format_duration(seconds):
    """Süreyi okunabilir formata çevirir"""
    if seconds < 60:
        return f"{int(seconds)} saniye"
    elif seconds < 3600:
        return f"{int(seconds/60)} dakika {int(seconds%60)} saniye"
    else:
        return f"{int(seconds/3600)} saat {int((seconds%3600)/60)} dakika"

def normalize_domain(d):
    if not d:
        return None
    d = d.strip().lower()
    if not d or d.startswith('#'):
        return None
    if d.startswith(('http://', 'https://')):
        d = urlparse(d).netloc
    if d.startswith('www.'):
        d = d[4:]
    return d if d else None

def safe_parse_date(value):
    if not value:
        return None
    if isinstance(value, list):
        value = value[0]
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    return None

# ------------- AĞ FONKSİYONLARI -------------
def resolve_domain_ip(domain):
    dns_servers = [['8.8.8.8', '8.8.4.4'], ['1.1.1.1', '1.0.0.1'], ['208.67.222.222', '208.67.220.220']]
    for servers in dns_servers:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = servers
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT
            try:
                return resolver.resolve(domain, 'A')[0].to_text()
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                try:
                    return f"CNAME:{resolver.resolve(domain, 'CNAME')[0].to_text()}"
                except:
                    pass
        except:
            continue
    return None

def get_http_info(domain):
    for proto in ('https://', 'http://'):
        try:
            resp = requests.get(proto + domain, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
            if resp.status_code < 400:
                resp.encoding = resp.apparent_encoding or 'utf-8'
                soup = BeautifulSoup(resp.text or "", 'html.parser')
                title = soup.title.string.strip() if soup.title and soup.title.string else "Başlık Yok"
                return {'url': resp.url, 'status_code': resp.status_code, 'title': title, 'raw_text': resp.text, 'protocol': proto.replace('://', '')}
        except:
            continue
    return None

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        creation = safe_parse_date(w.creation_date)
        return {
            'creation_date': creation,
            'registrar': w.registrar if hasattr(w, 'registrar') else None,
            'country': w.country if hasattr(w, 'country') else None
        }
    except:
        return {'creation_date': None, 'registrar': None, 'country': None}

def calculate_score(domain, http_info, whois_info):
    score, reasons = 0, []
    
    if http_info:
        raw = http_info.get('raw_text', '').lower()
        title = http_info.get('title', '').lower()
        url = http_info.get('url', '').lower()
        
        # Şifre formu
        if any(re.search(p, raw, re.I) for p in [r'type\s*=\s*["\']password["\']', r'name\s*=\s*["\']pass']):
            score += 6
            reasons.append("Şifre giriş formu tespit edildi")
        
        # Kullanıcı adı formu
        if any(re.search(p, raw, re.I) for p in [r'name\s*=\s*["\']username["\']', r'name\s*=\s*["\']user["\']']):
            score += 3
            reasons.append("Kullanıcı adı alanı bulundu")
        
        # Başlıkta şüpheli kelime
        keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if re.search(r'\b' + re.escape(kw) + r'\b', title)]
        if keywords_found:
            score += 3
            reasons.append(f"Başlıkta şüpheli kelime: {', '.join(keywords_found[:3])}")
        
        # URL'de şüpheli kelime
        url_keywords = [kw for kw in ['login', 'giris', 'signin', 'auth', 'verify'] if kw in url]
        if url_keywords:
            score += 2
            reasons.append(f"URL'de şüpheli yol: {', '.join(url_keywords)}")
        
        # İçerik yoğunluğu
        keyword_count = sum(raw.count(kw) for kw in SUSPICIOUS_KEYWORDS)
        if keyword_count >= 8:
            score += 2
            reasons.append(f"Yüksek şüpheli kelime yoğunluğu ({keyword_count})")
    
    # Domain yaşı
    if whois_info and whois_info.get('creation_date'):
        age = (datetime.now(timezone.utc) - whois_info['creation_date']).days
        if age < 30:
            score += 5
            reasons.append(f"Çok yeni domain ({age} gün)")
        elif age < 90:
            score += 3
            reasons.append(f"Yeni domain ({age} gün)")
        elif age < 180:
            score += 1
            reasons.append(f"Nispeten yeni domain ({age} gün)")
    elif http_info:
        score += 1
        reasons.append("WHOIS bilgileri gizli/erişilemez")
    
    return score, reasons

def check_domain(domain):
    try:
        time.sleep(RATE_LIMIT_DELAY)
        domain = normalize_domain(domain)
        if not domain:
            return None
        
        ip = resolve_domain_ip(domain)
        if not ip:
            return None
        
        http_info = get_http_info(domain)
        whois_info = get_whois_info(domain)
        score, reasons = calculate_score(domain, http_info, whois_info)
        
        if score >= SUSPICION_THRESHOLD:
            logging.warning(f"🚨 {domain} (Skor: {score})")
            return {
                'domain': domain,
                'ip': ip,
                'status': 'ŞÜPHELİ',
                'score': score,
                'reasons': reasons,
                'http_info': http_info,
                'whois_info': whois_info,
                'detected_at': datetime.now()
            }
        else:
            logging.info(f"✓ {domain} - Güvenli (Skor: {score})")
            return None
            
    except Exception as e:
        logging.error(f"❌ {domain}: {e}")
        return None

# ------------- TELEGRAM BİLDİRİM FONKSİYONLARI -------------
async def send_alert(app, result):
    """Anlık tespit bildirimi gönderir - TÜM DETAYLARLA"""
    try:
        domain = result['domain']
        score = result['score']
        
        # Tehlike seviyesi
        if score >= 10:
            emoji, level = "🔴", "KRİTİK"
        elif score >= 6:
            emoji, level = "🟠", "YÜKSEK"
        else:
            emoji, level = "🟡", "ORTA"
        
        # BAŞLIK
        msg = f"{emoji} *ŞÜPHELİ DOMAIN TESPİT EDİLDİ*\n"
        msg += "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        
        # GENEL BİLGİLER
        msg += f"🌐 *Domain:*\n`{escape_md(domain)}`\n\n"
        msg += f"📊 *Tehlike Seviyesi:* {level}\n"
        msg += f"📈 *Güvenlik Skoru:* {score}/20\n"
        msg += f"🔗 *IP Adresi:* `{escape_md(result.get('ip', 'N/A'))}`\n\n"
        
        # WEB BİLGİLERİ
        if result.get('http_info'):
            http = result['http_info']
            msg += "🌐 *WEB BİLGİLERİ*\n"
            msg += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            
            # URL
            url = http.get('url', '')
            if url:
                url_short = url[:70] + '\\.\\.\\.' if len(url) > 70 else url
                msg += f"🔗 *Tam URL:*\n`{escape_md(url_short)}`\n\n"
            
            # Protokol ve HTTP durum
            protocol = http.get('protocol', 'N/A').upper()
            status = http.get('status_code', 'N/A')
            msg += f"🔒 *Protokol:* {protocol}\n"
            msg += f"📡 *HTTP Durum:* {status}\n\n"
            
            # Sayfa başlığı
            title = http.get('title', 'Başlık bulunamadı')
            title_short = (title[:100] + '\\.\\.\\.') if len(title) > 100 else title
            msg += f"📄 *Sayfa Başlığı:*\n_{escape_md(title_short)}_\n\n"
        
        # WHOIS BİLGİLERİ
        if result.get('whois_info'):
            whois = result['whois_info']
            if whois.get('creation_date') or whois.get('registrar') or whois.get('country'):
                msg += "📋 *WHOIS BİLGİLERİ*\n"
                msg += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                
                if whois.get('creation_date'):
                    date_obj = whois['creation_date']
                    date = date_obj.strftime('%d %B %Y')
                    age = (datetime.now(timezone.utc) - date_obj).days
                    
                    # Yaş uyarısı
                    if age < 30:
                        age_warning = "⚠️ *ÇOK YENİ*"
                    elif age < 90:
                        age_warning = "⚠️ Yeni"
                    elif age < 180:
                        age_warning = "⚡ Nispeten yeni"
                    else:
                        age_warning = "✓ Eski"
                    
                    msg += f"📅 *Kayıt Tarihi:* {escape_md(date)}\n"
                    msg += f"⏳ *Domain Yaşı:* {age} gün {age_warning}\n"
                
                if whois.get('registrar'):
                    registrar = whois['registrar'][:50]
                    msg += f"🏢 *Registrar:* {escape_md(registrar)}\n"
                
                if whois.get('country'):
                    msg += f"🌍 *Ülke:* {escape_md(whois['country'])}\n"
                
                msg += "\n"
        
        # TESPİT NEDENLERİ (EN ÖNEMLİ KISIM)
        msg += "⚠️ *TESPİT NEDENLERİ*\n"
        msg += "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        for i, reason in enumerate(result['reasons'], 1):
            msg += f"{i}\\. {escape_md(reason)}\n"
        
        # TESPİT ZAMANI
        msg += f"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        now = datetime.now()
        time_str = now.strftime('%d %B %Y, %H:%M:%S')
        msg += f"🕐 *Tespit Zamanı:*\n{escape_md(time_str)}"
        
        # BUTONLAR YOK - direkt gönder
        await app.bot.send_message(
            chat_id=GROUP_CHAT_ID,
            text=msg,
            parse_mode=ParseMode.MARKDOWN_V2
        )
        
        # Geçmişe ekle
        detected_history.append(result)
        if len(detected_history) > 100:
            detected_history.pop(0)
            
    except Exception as e:
        logging.error(f"Telegram bildirimi hatası: {e}", exc_info=True)

async def save_and_report(result, app):
    """Dosyaya kaydeder VE ANLIK bildirim gönderir"""
    try:
        # Dosyaya kaydet
        with open(FOUND_DOMAINS_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\n")
            f.write(f"Domain: {result['domain']}\n")
            f.write(f"IP: {result.get('ip')}\n")
            f.write(f"Skor: {result['score']}\n")
            f.write(f"Nedenler:\n")
            for r in result['reasons']:
                f.write(f"  - {r}\n")
            if result.get('http_info'):
                f.write(f"URL: {result['http_info'].get('url')}\n")
                f.write(f"Başlık: {result['http_info'].get('title')}\n")
            f.write("="*70 + "\n\n")
    except Exception as e:
        logging.error(f"Dosya yazma hatası: {e}")
    
    # ANLIK bildirim gönder
    try:
        await send_alert(app, result)
        logging.info(f"✅ Bildirim gönderildi: {result['domain']}")
    except Exception as e:
        logging.error(f"Bildirim gönderme hatası: {e}", exc_info=True)

# ------------- TARAMA DÖNGÜSÜ -------------
def scan_logic(app):
    """Ana tarama döngüsü"""
    # Yeni event loop oluştur
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    while True:
        with status_lock:
            if scan_status["stop_requested"]:
                scan_status.update({
                    "is_scanning": False,
                    "stop_requested": False,
                    "continuous_mode": False
                })
                logging.info("❌ Tarama durduruldu")
                break
            
            scan_status["scan_number"] += 1
            scan_status.update({
                "is_scanning": True,
                "processed_count": 0,
                "suspicious_found": 0,
                "failed_count": 0,
                "start_time": datetime.now()
            })
        
        # Domain listesi
        try:
            with open(DOMAINS_FILE, 'r', encoding='utf-8') as f:
                domains = list(set([normalize_domain(line) for line in f if normalize_domain(line)]))
            with status_lock:
                scan_status["total_domains"] = len(domains)
            logging.info(f"🔍 Tarama #{scan_status['scan_number']} başladı - {len(domains)} domain")
        except FileNotFoundError:
            logging.error(f"❌ Domain listesi bulunamadı: {DOMAINS_FILE}")
            with status_lock:
                scan_status["is_scanning"] = False
            time.sleep(60)
            continue
        
        # Domain tarama
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(check_domain, d): d for d in domains}
            for future in as_completed(futures):
                with status_lock:
                    if scan_status["stop_requested"]:
                        logging.warning("⚠️ Durdurma isteği, tarama sonlandırılıyor...")
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    scan_status["processed_count"] += 1
                
                try:
                    result = future.result()
                    if result:
                        with status_lock:
                            scan_status["suspicious_found"] += 1
                            scan_status["last_found"] = result['domain']
                        
                        # ANLIK bildirim gönder - YENİ YÖNTEMle
                        try:
                            # Async fonksiyonu sync context'te çalıştır
                            loop.run_until_complete(save_and_report(result, app))
                        except Exception as e:
                            logging.error(f"Bildirim hatası: {e}", exc_info=True)
                        
                except Exception as e:
                    with status_lock:
                        scan_status["failed_count"] += 1
                    logging.error(f"Kontrol hatası: {e}")
        
        # Tur tamamlandı
        with status_lock:
            if scan_status["stop_requested"]:
                continue
            
            elapsed = (datetime.now() - scan_status["start_time"]).total_seconds()
            is_continuous = scan_status["continuous_mode"]
            interval = scan_status["scan_interval"]
        
        logging.info(f"✓ Tarama #{scan_status['scan_number']} tamamlandı - "
                    f"Şüpheli: {scan_status['suspicious_found']}, "
                    f"Süre: {format_duration(elapsed)}")
        
        # Sürekli tarama kontrolü
        if not is_continuous:
            with status_lock:
                scan_status["is_scanning"] = False
            logging.info("📴 Tek tarama modu - durdu")
            break
        
        # Bir sonraki tarama için bekle
        if interval > 0:
            logging.info(f"⏳ {format_duration(interval)} sonra yeni tarama...")
            time.sleep(interval)
        else:
            logging.info("♻️ Anında yeni tarama başlıyor...")
            time.sleep(2)  # Kısa bir nefes

# ------------- BOT KOMUTLARI -------------
async def is_admin(update):
    if update.effective_chat.type == 'private':
        return True
    try:
        admins = await update.effective_chat.get_administrators()
        return any(a.user.id == update.effective_user.id for a in admins)
    except:
        return False

async def start_cmd(update, context):
    msg = ("🤖 *Domain Taklit Tespit Sistemi v8\\.5*\n\n"
           "Komutlar:\n\n"
           "`/tara` \\- Tek seferlik tarama\n"
           "`/surekli_tarama` \\- Sürekli tarama ayarla\n"
           "`/durdur` \\- Taramayı durdur\n"
           "`/bilgi` \\- Anlık durum\n"
           "`/istatistik` \\- Detaylı istatistikler\n"
           "`/gecmis` \\- Tespit geçmişi\n"
           "`/yardim` \\- Tüm komutlar")
    
    keyboard = [[
        InlineKeyboardButton("🔍 Tek Tarama", callback_data="quick_scan"),
        InlineKeyboardButton("♻️ Sürekli Tarama", callback_data="continuous")
    ]]
    
    await update.message.reply_text(
        msg,
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def scan_cmd(update, context):
    """Tek seferlik tarama"""
    if not await is_admin(update):
        await update.message.reply_text("⛔ Sadece yöneticiler")
        return
    
    with status_lock:
        if scan_status["is_scanning"]:
            await update.message.reply_text("⚠️ Zaten tarama devam ediyor\\. `/bilgi`", parse_mode=ParseMode.MARKDOWN_V2)
            return
        scan_status["stop_requested"] = False
        scan_status["continuous_mode"] = False
    
    await update.message.reply_text("✅ Tek seferlik tarama başlatılıyor...")
    threading.Thread(target=scan_logic, args=(context.application,), daemon=True).start()
    await asyncio.sleep(2)
    
    with status_lock:
        total = scan_status["total_domains"]
    
    msg = f"🔍 *Tek Tarama Başladı*\n\n📋 Toplam: {total} domain\n\n💡 Tespit edilen domain'ler anında bildirilecek\\!"
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN_V2)

async def continuous_scan_cmd(update, context):
    """Sürekli tarama ayarları"""
    if not await is_admin(update):
        await update.message.reply_text("⛔ Sadece yöneticiler")
        return
    
    with status_lock:
        if scan_status["is_scanning"]:
            await update.message.reply_text("⚠️ Önce mevcut taramayı durdurun: /durdur")
            return
    
    keyboard = [
        [InlineKeyboardButton("⚡ Anında", callback_data="interval_0")],
        [InlineKeyboardButton("❌ İptal", callback_data="cancel")]
    ]
    
    msg = ("♻️ *SÜREKLİ TARAMA AYARI*\n\n"
           "Taramalar arasında ne kadar süre beklensin?\n\n"
           "⚡ *Anında:* Bir tarama biter bitmez yeni tarama başlar\n"
           "⏱️ *Aralıklı:* Belirlenen süre bekledikten sonra yeni tarama")
    
    await update.message.reply_text(
        msg,
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def info_cmd(update, context):
    """Anlık durum bilgisi"""
    with status_lock:
        if not scan_status["is_scanning"]:
            msg = ("💤 *Aktif Tarama Yok*\n\n"
                   "Tarama başlatmak için:\n"
                   "`/tara` \\- Tek tarama\n"
                   "`/surekli_tarama` \\- Sürekli tarama")
            await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN_V2)
            return
        
        p = scan_status["processed_count"]
        t = scan_status["total_domains"]
        f = scan_status["suspicious_found"]
        failed = scan_status["failed_count"]
        num = scan_status["scan_number"]
        start = scan_status["start_time"]
        is_cont = scan_status["continuous_mode"]
        interval = scan_status["scan_interval"]
    
    elapsed = (datetime.now() - start).total_seconds()
    perc = (p / t * 100) if t > 0 else 0
    
    # İlerleme çubuğu
    bar_len = 10
    filled = int(bar_len * perc / 100)
    bar = "█" * filled + "░" * (bar_len - filled)
    
    # ETA
    if p > 0 and p < t:
        avg_time = elapsed / p
        remaining_secs = (t - p) * avg_time
        eta = escape_md(format_duration(remaining_secs))
    else:
        eta = "\\-"
    
    elapsed_str = escape_md(format_duration(elapsed))
    perc_str = f"{perc:.1f}".replace('.', '\\.')
    
    mode_text = "♻️ Sürekli" if is_cont else "🔍 Tek Tarama"
    if is_cont:
        if interval == 0:
            mode_text += " \\(Anında\\)"
        else:
            mode_text += f" \\({escape_md(format_duration(interval))} aralık\\)"
    
    msg = (f"📊 *TARAMA DURUMU*\n\n"
           f"🔄 *Tarama \\#{num}*\n"
           f"📍 *Mod:* {mode_text}\n"
           f"`{bar}` {perc_str}%\n\n"
           f"📈 *İlerleme:* {p} / {t}\n"
           f"🚨 *Tespit:* {f} domain\n"
           f"❌ *Başarısız:* {failed}\n"
           f"⏱️ *Geçen:* {elapsed_str}\n"
           f"⏳ *Kalan:* {eta}")
    
    keyboard = [[InlineKeyboardButton("🔄 Yenile", callback_data="refresh_status")]]
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=InlineKeyboardMarkup(keyboard))

async def stats_cmd(update, context):
    """Detaylı istatistikler"""
    with status_lock:
        num = scan_status["scan_number"]
        scanning = scan_status["is_scanning"]
    
    total_detect = len(detected_history)
    
    try:
        with open(DOMAINS_FILE, 'r', encoding='utf-8') as f:
            monitored = len(set([normalize_domain(l) for l in f if normalize_domain(l)]))
    except:
        monitored = 0
    
    msg = f"📊 *DETAYLI İSTATİSTİKLER*\n\n"
    msg += f"🔄 *Tamamlanan Tarama:* {num}\n"
    msg += f"📋 *İzlenen Domain:* {monitored}\n"
    msg += f"🚨 *Toplam Tespit:* {total_detect}\n"
    msg += f"⚡ *Durum:* {'🟢 Aktif' if scanning else '🔴 Beklemede'}\n\n"
    
    if detected_history:
        # En yüksek skorlu domain'ler
        top_5 = sorted(detected_history, key=lambda x: x['score'], reverse=True)[:5]
        msg += "🏆 *En Tehlikeli Domain'ler:*\n"
        for i, item in enumerate(top_5, 1):
            domain_short = item['domain'][:35]
            score = item['score']
            msg += f"{i}\\. `{escape_md(domain_short)}` \\({score} puan\\)\n"
        
        msg += "\n"
        
        # Son 24 saatte tespit edilenler
        now = datetime.now()
        last_24h = [d for d in detected_history if (now - d['detected_at']).total_seconds() < 86400]
        msg += f"📅 *Son 24 Saat:* {len(last_24h)} tespit\n"
        
        # En sık görülen nedenler
        all_reasons = []
        for d in detected_history:
            all_reasons.extend(d['reasons'])
        
        if all_reasons:
            from collections import Counter
            top_reasons = Counter(all_reasons).most_common(3)
            msg += "\n⚠️ *En Sık Tespit Nedenleri:*\n"
            for reason, count in top_reasons:
                msg += f"• {escape_md(reason[:40])} \\({count}x\\)\n"
    
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN_V2)

async def history_cmd(update, context):
    """Son tespit edilen domain'ler"""
    if not detected_history:
        await update.message.reply_text("📭 Henüz hiç tespit yapılmadı")
        return
    
    recent = list(reversed(detected_history[-10:]))
    msg = "📜 *SON TESPİT EDİLEN DOMAIN'LER*\n\n"
    
    for i, item in enumerate(recent, 1):
        domain_short = item['domain'][:35]
        score = item['score']
        time_str = item['detected_at'].strftime('%d/%m %H:%M')
        
        # Tehlike seviyesi emojisi
        if score >= 10:
            emoji = "🔴"
        elif score >= 6:
            emoji = "🟠"
        else:
            emoji = "🟡"
        
        msg += f"{i}\\. {emoji} `{escape_md(domain_short)}`\n"
        msg += f"   Skor: {score} \\| Zaman: {escape_md(time_str)}\n\n"
    
    keyboard = [[InlineKeyboardButton("🔄 Yenile", callback_data="refresh_history")]]
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=InlineKeyboardMarkup(keyboard))

async def stop_cmd(update, context):
    """Taramayı durdurma komutu"""
    if not await is_admin(update):
        await update.message.reply_text("⛔ Sadece yöneticiler")
        return
    
    with status_lock:
        if not scan_status["is_scanning"]:
            await update.message.reply_text("💤 Zaten aktif bir tarama yok")
            return
    
    keyboard = [[
        InlineKeyboardButton("✅ Evet, Durdur", callback_data="stop_yes"),
        InlineKeyboardButton("❌ Hayır, Devam", callback_data="stop_no")
    ]]
    
    await update.message.reply_text(
        "🛑 Taramayı durdurmak istediğinize emin misiniz?",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def help_cmd(update, context):
    """Yardım mesajı"""
    msg = ("📖 *KOMUT KILAVUZU*\n\n"
           "*🔍 Tarama Komutları:*\n"
           "`/tara` \\- Tek seferlik tarama başlatır\n"
           "`/surekli_tarama` \\- Otomatik tekrarlayan tarama ayarlar\n"
           "`/durdur` \\- Devam eden taramayı durdurur\n\n"
           "*📊 Bilgi Komutları:*\n"
           "`/bilgi` \\- Anlık tarama durumunu gösterir\n"
           "`/istatistik` \\- Detaylı istatistikler ve en tehlikeli domain'leri gösterir\n"
           "`/gecmis` \\- Son 10 tespit edilen domain'i listeler\n\n"
           "*ℹ️ Genel:*\n"
           "`/start` \\- Bot hakkında bilgi\n"
           "`/yardim` \\- Bu mesaj\n\n"
           "*🎯 Özellikler:*\n"
           "• Tespit edilen domain'ler *anında* bildirilir\n"
           "• Sürekli tarama modunda otomatik tekrar eder\n"
           "• Her domain için detaylı analiz raporu\n"
           "• Yönetici kontrolleri ile güvenli kullanım")
    
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN_V2)

# ------------- BUTON İŞLEYİCİSİ -------------
async def button_handler(update, context):
    """Inline butonları işler"""
    query = update.callback_query
    await query.answer()
    
    if query.data == "quick_scan":
        # Tek tarama başlat
        if not await is_admin(update):
            await query.edit_message_text("⛔ Bu işlemi sadece yöneticiler yapabilir")
            return
        
        with status_lock:
            if scan_status["is_scanning"]:
                await query.edit_message_text("⚠️ Zaten tarama devam ediyor")
                return
            scan_status["stop_requested"] = False
            scan_status["continuous_mode"] = False
        
        await query.edit_message_text("✅ Tek tarama başlatılıyor...")
        threading.Thread(target=scan_logic, args=(context.application,), daemon=True).start()
        
    elif query.data == "continuous":
        # Sürekli tarama ayarları
        if not await is_admin(update):
            await query.edit_message_text("⛔ Bu işlemi sadece yöneticiler yapabilir")
            return
        
        keyboard = [
            [InlineKeyboardButton("⚡ Anında", callback_data="interval_0")],
            [InlineKeyboardButton("❌ İptal", callback_data="cancel")]
        ]
        
        msg = ("♻️ *SÜREKLİ TARAMA AYARI*\n\n"
               "Taramalar arasındaki bekleme süresini seçin:")
        
        await query.edit_message_text(
            msg,
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data.startswith("interval_"):
        # Tarama aralığını ayarla ve başlat
        if not await is_admin(update):
            await query.edit_message_text("⛔ Bu işlemi sadece yöneticiler yapabilir")
            return
        
        interval_min = int(query.data.split("_")[1])
        interval_sec = interval_min * 60
        
        with status_lock:
            if scan_status["is_scanning"]:
                await query.edit_message_text("⚠️ Önce mevcut taramayı durdurun")
                return
            scan_status["stop_requested"] = False
            scan_status["continuous_mode"] = True
            scan_status["scan_interval"] = interval_sec
        
        if interval_min == 0:
            msg = "✅ *Sürekli tarama başlatıldı*\n\nMod: ⚡ Anında \\(taramalar arasında bekleme yok\\)"
        else:
            msg = f"✅ *Sürekli tarama başlatıldı*\n\nMod: ♻️ Her {interval_min} dakikada bir tekrar"
        
        await query.edit_message_text(msg, parse_mode=ParseMode.MARKDOWN_V2)
        threading.Thread(target=scan_logic, args=(context.application,), daemon=True).start()
    
    elif query.data == "refresh_status":
        # Durum bilgisini yenile
        with status_lock:
            if not scan_status["is_scanning"]:
                await query.edit_message_text("💤 Tarama artık aktif değil")
                return
            
            p = scan_status["processed_count"]
            t = scan_status["total_domains"]
            f = scan_status["suspicious_found"]
            failed = scan_status["failed_count"]
            num = scan_status["scan_number"]
            start = scan_status["start_time"]
            is_cont = scan_status["continuous_mode"]
            interval = scan_status["scan_interval"]
        
        elapsed = (datetime.now() - start).total_seconds()
        perc = (p / t * 100) if t > 0 else 0
        
        bar_len = 10
        filled = int(bar_len * perc / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        
        if p > 0 and p < t:
            avg_time = elapsed / p
            remaining_secs = (t - p) * avg_time
            eta = escape_md(format_duration(remaining_secs))
        else:
            eta = "\\-"
        
        elapsed_str = escape_md(format_duration(elapsed))
        perc_str = f"{perc:.1f}".replace('.', '\\.')
        
        mode_text = "♻️ Sürekli" if is_cont else "🔍 Tek Tarama"
        if is_cont:
            if interval == 0:
                mode_text += " \\(Anında\\)"
            else:
                mode_text += f" \\({escape_md(format_duration(interval))} aralık\\)"
        
        msg = (f"📊 *TARAMA DURUMU*\n\n"
               f"🔄 *Tarama \\#{num}*\n"
               f"📍 *Mod:* {mode_text}\n"
               f"`{bar}` {perc_str}%\n\n"
               f"📈 *İlerleme:* {p} / {t}\n"
               f"🚨 *Tespit:* {f} domain\n"
               f"❌ *Başarısız:* {failed}\n"
               f"⏱️ *Geçen:* {elapsed_str}\n"
               f"⏳ *Kalan:* {eta}")
        
        keyboard = [[InlineKeyboardButton("🔄 Yenile", callback_data="refresh_status")]]
        
        try:
            await query.edit_message_text(
                msg,
                parse_mode=ParseMode.MARKDOWN_V2,
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
        except Exception as e:
            # Mesaj değişmemişse hata vermez
            logging.debug(f"Mesaj güncelleme hatası: {e}")
    
    elif query.data == "refresh_history":
        # Geçmişi yenile
        if not detected_history:
            await query.edit_message_text("📭 Henüz hiç tespit yapılmadı")
            return
        
        recent = list(reversed(detected_history[-10:]))
        msg = "📜 *SON TESPİT EDİLEN DOMAIN'LER*\n\n"
        
        for i, item in enumerate(recent, 1):
            domain_short = item['domain'][:35]
            score = item['score']
            time_str = item['detected_at'].strftime('%d/%m %H:%M')
            
            if score >= 10:
                emoji = "🔴"
            elif score >= 6:
                emoji = "🟠"
            else:
                emoji = "🟡"
            
            msg += f"{i}\\. {emoji} `{escape_md(domain_short)}`\n"
            msg += f"   Skor: {score} \\| Zaman: {escape_md(time_str)}\n\n"
        
        keyboard = [[InlineKeyboardButton("🔄 Yenile", callback_data="refresh_history")]]
        await query.edit_message_text(msg, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=InlineKeyboardMarkup(keyboard))
    
    elif query.data.startswith("detail_"):
        # Detaylı rapor artık kullanılmıyor (zaten ana mesajda tüm detaylar var)
        await query.answer("ℹ️ Tüm detaylar ana mesajda mevcut", show_alert=True)
    
    elif query.data.startswith("approve_"):
        # Onay butonu kaldırıldı - artık kullanılmıyor
        await query.answer("Bu özellik devre dışı", show_alert=True)
    
    elif query.data == "stop_yes":
        # Taramayı durdur
        if not await is_admin(update):
            await query.edit_message_text("⛔ Bu işlemi sadece yöneticiler yapabilir")
            return
        
        with status_lock:
            if scan_status["is_scanning"]:
                scan_status["stop_requested"] = True
                logging.info("🛑 Durdurma isteği alındı")
                await query.edit_message_text("🛑 Tarama durduruldu\\.", parse_mode=ParseMode.MARKDOWN_V2)
            else:
                await query.edit_message_text("⚠️ Tarama zaten aktif değil")
    
    elif query.data == "stop_no":
        # Durdurma iptal
        await query.edit_message_text("✅ İşlem iptal edildi. Tarama devam ediyor.")
    
    elif query.data == "cancel":
        # İşlem iptal
        await query.edit_message_text("❌ İşlem iptal edildi")

# ------------- MAIN -------------
def main():
    """Bot başlangıç fonksiyonu"""
    global bot_application
    
    # Token kontrolü
    if TELEGRAM_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("\n❌ HATA: TELEGRAM_TOKEN ayarlanmamış!")
        print("monitor_bot.py dosyasını düzenleyin ve BotFather'dan aldığınız token'ı girin.\n")
        return
    
    if GROUP_CHAT_ID == "YOUR_GROUP_CHAT_ID":
        print("\n❌ HATA: GROUP_CHAT_ID ayarlanmamış!")
        print("monitor_bot.py dosyasını düzenleyin ve grubun Chat ID'sini girin.\n")
        return
    
    logging.info("🤖 Bot başlatılıyor...")
    
    try:
        app = Application.builder().token(TELEGRAM_TOKEN).build()
        bot_application = app  # Global değişkene ata
        
        # Komutları ekle
        app.add_handler(CommandHandler(["start", "baslat"], start_cmd))
        app.add_handler(CommandHandler("tara", scan_cmd))
        app.add_handler(CommandHandler("surekli_tarama", continuous_scan_cmd))
        app.add_handler(CommandHandler("bilgi", info_cmd))
        app.add_handler(CommandHandler("durdur", stop_cmd))
        app.add_handler(CommandHandler("istatistik", stats_cmd))
        app.add_handler(CommandHandler("gecmis", history_cmd))
        app.add_handler(CommandHandler(["yardim", "help"], help_cmd))
        
        # Buton işleyicisi
        app.add_handler(CallbackQueryHandler(button_handler))
        
        logging.info("✅ Bot hazır ve dinliyor...")
        print("\n" + "="*60)
        print("✅ BOT ÇALIŞIYOR!")
        print("="*60)
        print("\n📱 Telegram'dan botunuzu test edin:")
        print("   /start - Bot bilgileri")
        print("   /tara - Tek tarama başlat")
        print("   /surekli_tarama - Otomatik tarama ayarla")
        print("\n💡 Tespit edilen domain'ler ANINDA bildirilecek!")
        print("="*60 + "\n")
        
        # Bot'u çalıştır
        app.run_polling()
        
    except Exception as e:
        logging.error(f"❌ Bot başlatma hatası: {e}")
        print(f"\n❌ HATA: {e}\n")

if __name__ == "__main__":
    main()
