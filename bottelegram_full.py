import telebot
import requests
import os
import json
import threading
import time
from dotenv import load_dotenv
import datetime
import pytz
import socket
import subprocess
import dns.resolver

# Load environment variables from .env file
load_dotenv() # Aktifkan kembali untuk production

# Get bot token from environment variables
BOT_TOKEN = os.getenv('BOT_TOKEN', "7127611248:AAHhz8jmGWGoinOu2P-a1Tiw5UnsS3REEs8")

bot = telebot.TeleBot(BOT_TOKEN)

# --- Timezone and Logging Setup ---

# Define Indonesian timezone (Waktu Indonesia Barat)
WIB = pytz.timezone('Asia/Jakarta')

def log_message(message):
    """Prints a message with a timestamp in WIB."""
    timestamp = datetime.datetime.now(WIB).strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp} WIB] {message}")


# File to store domains and user chat IDs
DOMAINS_FILE = 'domains.json'
USERS_FILE = 'users.json'

# --- Utility Functions ---

def get_domain_ip(domain):
    """Resolves a domain to its IP address."""
    try:
        # Clean the domain name for IP lookup
        if '://' in domain:
            domain = domain.split('://')[1]
        if '/' in domain:
            domain = domain.split('/')[0]
            
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "IP tidak ditemukan"
    except Exception:
        return "Gagal mencari IP"

def load_data(filename):
    """Loads data from a JSON file."""
    if not os.path.exists(filename):
        return {}
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

def save_data(data, filename):
    """Saves data to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def is_accessible(domain):
    """
    Checks if a domain is accessible.
    Returns a tuple (bool: accessible, str: status_message).
    """
    try:
        url = domain
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + domain

        # Cek DNS resolve dulu
        try:
            ip_address = get_domain_ip(domain)
            if ip_address in ["IP tidak ditemukan", "Gagal mencari IP"]:
                return False, "Domain tidak dapat diakses: gagal resolve DNS (IP tidak ditemukan). Kemungkinan domain tidak aktif, domain sudah expired, atau diblokir oleh pemerintah/ISP."
        except Exception:
            return False, "Domain tidak dapat diakses: gagal resolve DNS."

        response = requests.get(url, timeout=10, allow_redirects=True)
        status_code = response.status_code
        content = response.text.lower()
        final_url = response.url.lower()

        # Status code umum blokir/banned
        if status_code in [403]:
            return False, "Domain diblokir oleh server atau akses dibatasi (HTTP 403 Forbidden). Penyebab: Bisa karena firewall, blacklist, atau permintaan ISP/pemerintah."
        if status_code in [451]:
            return False, "Domain diblokir karena alasan hukum (HTTP 451 Unavailable For Legal Reasons). Penyebab: Permintaan pemerintah atau pelanggaran hukum."
        if status_code in [503]:
            return False, "Domain tidak dapat diakses (HTTP 503 Service Unavailable). Penyebab: Server sedang down, maintenance, atau diblokir sementara."
        if status_code in [429]:
            return False, "Akses ke domain dibatasi sementara (HTTP 429 Too Many Requests). Penyebab: Terlalu banyak request dalam waktu singkat."

        # Kata kunci blokir ISP Indonesia dan penyebabnya
        block_patterns = [
            ("internetpositif", "Diblokir oleh Kominfo/ISP karena terindikasi konten negatif atau melanggar regulasi pemerintah."),
            ("konten negatif", "Diblokir oleh Kominfo/ISP karena mengandung konten negatif."),
            ("diblokir kominfo", "Diblokir oleh Kominfo sesuai regulasi pemerintah."),
            ("internet sehat", "Diblokir oleh program Internet Sehat (Kominfo/ISP) karena konten tidak sesuai kebijakan."),
            ("akses dibatasi", "Akses ke domain dibatasi oleh ISP atau firewall."),
            ("site blocked", "Situs diblokir oleh ISP atau firewall."),
            ("diblokir oleh pemerintah", "Diblokir oleh pemerintah Indonesia."),
            ("akses internet anda dibatasi", "Akses internet dibatasi oleh ISP atau jaringan lokal."),
            ("akses ke situs ini diblokir", "Akses ke situs ini diblokir oleh ISP atau pemerintah."),
            ("this site is blocked", "Situs diblokir oleh ISP atau firewall."),
            ("blokir kominfo", "Diblokir oleh Kominfo."),
            ("diblokir oleh isp", "Diblokir oleh ISP (penyedia layanan internet)."),
            ("internetbaik", "Diblokir oleh program Internet Baik (Kominfo/ISP)."),
            ("safe browsing", "Diblokir oleh Google Safe Browsing karena terindikasi phishing/malware."),
            ("phishing", "Diblokir karena terindikasi phishing."),
            ("malware", "Diblokir karena terindikasi malware."),
            ("copyright", "Diblokir karena pelanggaran hak cipta."),
            ("situs ini telah diblokir oleh pemerintah", "Diblokir oleh pemerintah Indonesia."),
            ("situs ini tidak dapat diakses", "Situs tidak dapat diakses, kemungkinan diblokir oleh ISP/pemerintah."),
            ("blocked by government", "Diblokir oleh pemerintah."),
            ("blocked for legal reasons", "Diblokir karena alasan hukum."),
            ("your access to this site has been restricted", "Akses ke situs ini dibatasi oleh ISP atau firewall."),
            ("forbidden", "Akses ke situs ini dilarang (forbidden)."),
            ("dns_probe_finished_nxdomain", "Domain tidak ditemukan di DNS. Kemungkinan domain sudah tidak aktif atau diblokir.")
        ]
        for keyword, reason in block_patterns:
            if keyword in content or keyword in final_url:
                return False, f"Domain diblokir. Penyebab: {reason}"

        # Deteksi redirect ke halaman blokir
        if final_url != url.lower():
            for keyword, reason in block_patterns:
                if keyword in final_url:
                    return False, f"Domain dialihkan ke halaman blokir ISP. Penyebab: {reason}"

        if 200 <= status_code < 300:
            return True, "Domain dapat diakses."
        else:
            return False, f"Status code: {status_code}"

    except requests.ConnectionError:
        return False, "Gagal menyambung (Connection Error). Kemungkinan domain tidak aktif, jaringan bermasalah, atau diblokir."
    except requests.Timeout:
        return False, "Request timeout. Kemungkinan domain lambat, tidak responsif, atau diblokir oleh firewall."
    except requests.RequestException as e:
        return False, f"Error: {e}"

# --- User Management ---

def add_user(chat_id):
    """Adds a user's chat_id for notifications."""
    users = load_data(USERS_FILE)
    if 'chat_ids' not in users:
        users['chat_ids'] = []
    if chat_id not in users['chat_ids']:
        users['chat_ids'].append(chat_id)
        save_data(users, USERS_FILE)
        log_message(f"User baru ditambahkan: {chat_id}")

# --- Bot Command Handlers ---

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    add_user(message.chat.id)
    welcome_text = (
        "🤖 Selamat datang di Nawala Domain Monitor Bot!\n\n"
        "🗂️ Perintah yang tersedia:\n\n"
        "1️⃣ Menambah domain:\n  /add domain1.com domain2.com ...\n"
        "2️⃣ Mengganti domain:\n  /replace old.com new.com\n"
        "3️⃣ Menghapus domain:\n  /delete domain1.com domain2.com ...\n"
        "4️⃣ Melihat daftar domain:\n  /info\n"
        "5️⃣ Cek domain langsung:\n  /check domain1.com domain2.com ...\n\n"
        "❓ Butuh bantuan?\nKetik /help untuk panduan lengkap\n\n"
        "📌 Contoh penggunaan:\n"
        "• /add site1.com site2.com site3.com\n"
        "• /replace old.com new.com\n"
        "• /delete blocked1.com blocked2.com\n"
        "• /check domain1.com domain2.com"
    )
    bot.reply_to(message, welcome_text)

@bot.message_handler(commands=['add'])
def add_domains(message):
    add_user(message.chat.id)
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "Gunakan format: /add <domain1> [domain2] ...")
        return
    domains_to_add = parts[1:]
    all_domains = load_data(DOMAINS_FILE)
    chat_id = str(message.chat.id)
    if chat_id not in all_domains:
        all_domains[chat_id] = {}
    stored_domains = all_domains[chat_id]
    added_domains = []
    for domain in domains_to_add:
        domain = domain.strip().lower()
        if domain not in stored_domains:
            accessible, status = is_accessible(domain)
            stored_domains[domain] = {'accessible': accessible, 'last_status': status}
            added_domains.append(domain)
    if added_domains:
        all_domains[chat_id] = stored_domains
        save_data(all_domains, DOMAINS_FILE)
        bot.reply_to(message, f"Berhasil menambahkan domain baru:\n- " + "\n- ".join(added_domains))
    else:
        bot.reply_to(message, "Semua domain yang Anda masukkan sudah ada dalam daftar pantauan.")

@bot.message_handler(commands=['replace'])
def replace_domain(message):
    add_user(message.chat.id)
    parts = message.text.split()
    if len(parts) != 3:
        bot.reply_to(message, "Gunakan format: /replace <domain_lama> <domain_baru>")
        return
    old_domain = parts[1].strip().lower()
    new_domain = parts[2].strip().lower()
    all_domains = load_data(DOMAINS_FILE)
    chat_id = str(message.chat.id)
    if chat_id not in all_domains:
        bot.reply_to(message, "Belum ada domain yang dipantau.")
        return
    stored_domains = all_domains[chat_id]
    if old_domain not in stored_domains:
        bot.reply_to(message, f"Domain '{old_domain}' tidak ditemukan dalam daftar.")
        return
    if new_domain in stored_domains:
        bot.reply_to(message, f"Domain '{new_domain}' sudah ada dalam daftar.")
        return
    stored_domains[new_domain] = stored_domains.pop(old_domain)
    all_domains[chat_id] = stored_domains
    save_data(all_domains, DOMAINS_FILE)
    bot.reply_to(message, f"Domain '{old_domain}' berhasil diganti menjadi '{new_domain}'.")

@bot.message_handler(commands=['delete'])
def delete_domains(message):
    add_user(message.chat.id)
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "Gunakan format: /delete <domain1> [domain2] ...")
        return
    domains_to_delete = [d.strip().lower() for d in parts[1:]]
    all_domains = load_data(DOMAINS_FILE)
    chat_id = str(message.chat.id)
    if chat_id not in all_domains:
        bot.reply_to(message, "Belum ada domain yang dipantau.")
        return
    stored_domains = all_domains[chat_id]
    deleted = []
    not_found = []
    for domain in domains_to_delete:
        if domain in stored_domains:
            del stored_domains[domain]
            deleted.append(domain)
        else:
            not_found.append(domain)
    all_domains[chat_id] = stored_domains
    save_data(all_domains, DOMAINS_FILE)
    msg = ""
    if deleted:
        msg += "Berhasil menghapus:\n- " + "\n- ".join(deleted) + "\n"
    if not_found:
        msg += "Tidak ditemukan:\n- " + "\n- ".join(not_found)
    bot.reply_to(message, msg.strip())

@bot.message_handler(commands=['info'])
def info_domains(message):
    add_user(message.chat.id)
    all_domains = load_data(DOMAINS_FILE)
    chat_id = str(message.chat.id)
    if chat_id not in all_domains or not all_domains[chat_id]:
        bot.reply_to(message, "Tidak ada domain yang sedang dipantau.")
        return
    stored_domains = all_domains[chat_id]
    msg = "Daftar domain yang dipantau:\n"
    for i, (domain, data) in enumerate(stored_domains.items(), 1):
        status = data.get('accessible', False)
        status_text = "✅ Dapat diakses" if status else "❌ Tidak dapat diakses"
        msg += f"{i}. {domain} - {status_text}\n"
    bot.reply_to(message, msg)

def get_ping_time(domain):
    """Mengembalikan waktu ping (ms) ke domain, atau None jika gagal."""
    try:
        # Ping 1x, timeout 2 detik
        result = subprocess.run(["ping", "-n", "1", "-w", "2000", domain], capture_output=True, text=True)
        output = result.stdout
        if "Average =" in output:
            avg = output.split("Average =")[-1].split("ms")[0].strip()
            return avg + " ms"
        elif "Average =".lower() in output.lower():
            avg = output.lower().split("average =")[-1].split("ms")[0].strip()
            return avg + " ms"
        else:
            return None
    except Exception:
        return None

def check_blacklist(domain):
    """Cek apakah domain/IP masuk blacklist DNSBL Spamhaus (sederhana)."""
    try:
        ip = get_domain_ip(domain)
        if ip in ["IP tidak ditemukan", "Gagal mencari IP"]:
            return "Tidak dapat dicek (IP tidak ditemukan)"
        reversed_ip = ".".join(ip.split(".")[::-1])
        query = f"{reversed_ip}.zen.spamhaus.org"
        try:
            dns.resolver.resolve(query, 'A')
            return "⚠️ Terdaftar di blacklist Spamhaus"
        except dns.resolver.NXDOMAIN:
            return "✅ Tidak terdaftar di blacklist Spamhaus"
        except Exception:
            return "Tidak dapat dicek (error DNS)"
    except Exception:
        return "Tidak dapat dicek (error)"

@bot.message_handler(commands=['check'])
def check_domains(message):
    add_user(message.chat.id)
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "Gunakan format: /check <domain1> [domain2] ...")
        return
    domains_to_check = [d.strip().lower() for d in parts[1:]]
    results = []
    for domain in domains_to_check:
        accessible, status = is_accessible(domain)
        ip_address = get_domain_ip(domain)
        ping = get_ping_time(domain)
        blacklist = check_blacklist(domain)
        ping_text = f"Ping: {ping}" if ping else "Ping: -"
        blacklist_text = f"Blacklist: {blacklist}"
        if accessible:
            results.append(f"✅ {domain} dapat diakses.\nIP: {ip_address}\n{ping_text}\n{blacklist_text}\nStatus: {status}")
        else:
            results.append(f"❌ {domain} tidak dapat diakses.\nIP: {ip_address}\n{ping_text}\n{blacklist_text}\nStatus: {status}")
    bot.reply_to(message, "\n\n".join(results))

@bot.message_handler(func=lambda message: not message.text.startswith('/'))
def check_single_domain(message):
    add_user(message.chat.id)
    domain = message.text.strip()
    if ' ' in domain or '.' not in domain:
        bot.reply_to(message, "Masukkan nama domain yang valid (contoh: google.com).")
        return
    accessible, status = is_accessible(domain)
    ip_address = get_domain_ip(domain)
    ping = get_ping_time(domain)
    blacklist = check_blacklist(domain)
    ping_text = f"Ping: {ping}" if ping else "Ping: -"
    blacklist_text = f"Blacklist: {blacklist}"
    all_domains = load_data(DOMAINS_FILE)
    chat_id = str(message.chat.id)
    if chat_id not in all_domains:
        all_domains[chat_id] = {}
    stored_domains = all_domains[chat_id]
    stored_domains[domain] = stored_domains.get(domain, {})
    stored_domains[domain]['last_ip'] = ip_address
    all_domains[chat_id] = stored_domains
    save_data(all_domains, DOMAINS_FILE)
    if accessible:
        msg = (
            f"✅ Domain {domain} dapat diakses.\n"
            f"IP: {ip_address}\n"
            f"{ping_text}\n"
            f"{blacklist_text}\n"
            f"Status: {status}\n"
            f"Last IP: {ip_address}"
        )
    else:
        msg = (
            f"❌ Domain {domain} tidak dapat diakses.\n"
            f"IP: {ip_address}\n"
            f"{ping_text}\n"
            f"{blacklist_text}\n"
            f"Status: {status}\n"
            f"Last IP: {ip_address}"
        )
    bot.send_message(message.chat.id, msg)

# --- Background Checker ---

def background_checker():
    """Periodically checks all domains and notifies if a domain becomes inaccessible."""
    log_message("Background checker dimulai...")
    while True:
        try:
            all_domains = load_data(DOMAINS_FILE)
            users = load_data(USERS_FILE)
            chat_ids = users.get('chat_ids', [])
            
            if not all_domains or not chat_ids:
                time.sleep(60) # Tunggu jika tidak ada domain atau user
                continue

            something_changed = False
            for chat_id in chat_ids:
                chat_id_str = str(chat_id)
                if chat_id_str not in all_domains:
                    continue
                stored_domains = all_domains[chat_id_str]
                for domain, data in list(stored_domains.items()):
                    was_accessible = data.get('accessible', False)
                    is_now_accessible, current_status = is_accessible(domain)

                    # Kirim notifikasi jika domain yang tadinya bisa diakses menjadi tidak bisa
                    if was_accessible and not is_now_accessible:
                        ip_address = get_domain_ip(domain)
                        notification_text = f"🚨 PERINGATAN 🚨\nDomain {domain} ({ip_address}) tidak dapat diakses!\nStatus: {current_status}"
                        try:
                            bot.send_message(chat_id, notification_text)
                        except Exception as e:
                            log_message(f"Gagal mengirim notifikasi ke {chat_id}: {e}")
                    # Kirim notifikasi jika domain yang tadinya tidak bisa diakses, kini sudah bisa diakses
                    elif not was_accessible and is_now_accessible:
                        ip_address = get_domain_ip(domain)
                        notification_text = f"✅ PEMBERITAHUAN ✅\nDomain {domain} ({ip_address}) sudah dapat diakses kembali!\nStatus: {current_status}"
                        try:
                            bot.send_message(chat_id, notification_text)
                        except Exception as e:
                            log_message(f"Gagal mengirim notifikasi ke {chat_id}: {e}")
                    # Update status di file jika ada perubahan
                    if data.get('accessible') != is_now_accessible or data.get('last_status') != current_status:
                        stored_domains[domain]['accessible'] = is_now_accessible
                        stored_domains[domain]['last_status'] = current_status
                        something_changed = True
                all_domains[chat_id_str] = stored_domains

            if something_changed:
                save_data(all_domains, DOMAINS_FILE)

        except Exception as e:
            log_message(f"Error di background checker: {e}")
        
        # Cek setiap 5 menit
        time.sleep(300)

# --- Main ---

if __name__ == "__main__":
    # Inisialisasi file jika tidak ada
    if not os.path.exists(DOMAINS_FILE):
        save_data({}, DOMAINS_FILE)
    if not os.path.exists(USERS_FILE):
        save_data({'chat_ids': []}, USERS_FILE)
        
    # Jalankan background checker di thread terpisah
    checker_thread = threading.Thread(target=background_checker, daemon=True)
    checker_thread.start()

    log_message("Bot sedang berjalan...")
    bot.infinity_polling() 