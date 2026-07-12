#!/usr/bin/env python3
import sys
import json
import os
import time
import requests
import fcntl
import re
import hashlib
from datetime import datetime, timezone, timedelta

def format_wib(ts_str):
    try:
        import re
        ts_clean = re.sub(r'\+0000$', '+00:00', str(ts_str))
        dt = datetime.fromisoformat(ts_clean)
        wib = timezone(timedelta(hours=7))
        return dt.astimezone(wib).strftime('%Y-%m-%d %H:%M:%S WIB')
    except Exception:
        return str(ts_str)


COOLDOWN_DIR = "/var/ossec/logs/telegram_cooldown_v2"
DDOS_BASE_COOLDOWN  = 1800   # 30 menit
DDOS_MAX_COOLDOWN   = 7200   # 2 jam
BASE_COOLDOWN  = 600    # 10 menit
MAX_COOLDOWN   = 3600   # 1 jam
SEPARATOR = chr(9473) * 30
WEB_SERVER_URL = "http://127.0.0.1:5000"


def resolve_tenant_info(agent_name, default_chat_id):
    try:
        url = "%s/api/telegram-lookup-agent/%s" % (WEB_SERVER_URL, agent_name)
        resp = requests.get(url, timeout=3, headers={'X-Integration-Secret': 'ISI SECRET'})
        if resp.status_code == 200:
            data = resp.json()
            if data.get("chat_id"):
                return {
                    "chat_id": data["chat_id"],
                    "rule_prefs": data.get("rule_prefs", {}),
                }
    except Exception:
        pass
    return {"chat_id": default_chat_id, "rule_prefs": {}}


def resolve_chat_id(agent_name, bot_token, default_chat_id):
    return resolve_tenant_info(agent_name, default_chat_id)["chat_id"]


def get_cooldown_file(fingerprint):
    os.makedirs(COOLDOWN_DIR, exist_ok=True)
    safe = hashlib.md5(fingerprint.encode()).hexdigest()[:16]
    return os.path.join(COOLDOWN_DIR, safe)


def check_and_update_cooldown(fingerprint, src_ip="", base_cd=BASE_COOLDOWN, max_cd=MAX_COOLDOWN):
    filepath = get_cooldown_file(fingerprint)
    try:
        with open(filepath, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            content = f.read().strip()
            if content:
                parts   = content.split("|")
                first_t = float(parts[0])
                count   = int(parts[1]) if len(parts) > 1 else 1
                sends   = int(parts[2]) if len(parts) > 2 else 0
                ips_raw = parts[3]       if len(parts) > 3 else ""
                ips     = set(filter(None, ips_raw.split(";")))
                if src_ip:
                    ips.add(src_ip)

                cooldown = min(base_cd * (2 ** sends), max_cd)
                elapsed  = time.time() - first_t

                if elapsed < cooldown:
                    count += 1
                    f.seek(0); f.truncate()
                    f.write("%s|%d|%d|%s" % (first_t, count, sends, ";".join(ips)))
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False, count, sends, ips
                else:
                    summary_count = count
                    summary_ips   = ips
                    new_sends     = sends + 1
                    new_ips       = {src_ip} if src_ip else set()
                    f.seek(0); f.truncate()
                    f.write("%s|1|%d|%s" % (time.time(), new_sends, ";".join(new_ips)))
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return True, summary_count, new_sends, summary_ips
            else:
                ips = {src_ip} if src_ip else set()
                f.seek(0); f.truncate()
                f.write("%s|1|0|%s" % (time.time(), ";".join(ips)))
                fcntl.flock(f, fcntl.LOCK_UN)
                return True, 1, 0, ips
    except Exception:
        return True, 1, 0, ({src_ip} if src_ip else set())


def send_telegram(bot_token, chat_id, text):
    try:
        requests.post(
            "https://api.telegram.org/bot%s/sendMessage" % bot_token,
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True},
            timeout=15
        )
    except Exception:
        pass


def escape_html(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# Mapping rule_id custom kita SENDIRI ke kategori — PALING presisi & immune dari
# kontaminasi grup. Wazuh kadang meng-union rule.groups dari rule LAIN yg turut
# fire dalam window korelasi frequency-based (mis. rule 100030 DDoS bisa
# kebawa grup "otx"/"threat_intel" dari rule tak terkait yg fire bersamaan
# dalam periode 10 detik yg sama) — cek group SAJA jadi tak bisa diandalkan
# utk rule korelasi. rule_id sendiri tidak pernah berubah, jadi paling akurat.
CATEGORY_RULE_IDS = {
    "MALWARE": {"100003", "100005", "100009", "100053"},
    "DEFACEMENT": {"100010", "100011"},
    "DDoS / BRUTE FORCE": {"100020", "100021", "100022", "100023", "100024",
                            "100025", "100026", "100027", "100030", "100031"},
    "WEB ATTACK": {"100040", "100041", "100042", "100043", "100044", "100045"},
    "THREAT INTEL": {"100060", "100100", "100101", "100103", "100104", "100106"},
}
CATEGORY_EMOJI = {
    "THREAT INTEL": chr(0x1f50d),
    "MALWARE": chr(0x1f9a0),
    "DEFACEMENT": chr(0x1f310),
    "WEB ATTACK": chr(0x1f6e1),
    "DDoS / BRUTE FORCE": chr(0x26a1),
}


def categorize(rule_id, groups, description, full_log):
    # 1) PALING presisi: rule_id custom kita sendiri
    if rule_id in CATEGORY_RULE_IDS.get("MALWARE", ()):
        return "MALWARE", CATEGORY_EMOJI["MALWARE"]
    if rule_id in CATEGORY_RULE_IDS.get("DEFACEMENT", ()):
        return "DEFACEMENT", CATEGORY_EMOJI["DEFACEMENT"]
    if rule_id in CATEGORY_RULE_IDS.get("DDoS / BRUTE FORCE", ()):
        return "DDoS / BRUTE FORCE", CATEGORY_EMOJI["DDoS / BRUTE FORCE"]
    if rule_id in CATEGORY_RULE_IDS.get("WEB ATTACK", ()):
        return "WEB ATTACK", CATEGORY_EMOJI["WEB ATTACK"]
    if rule_id in CATEGORY_RULE_IDS.get("THREAT INTEL", ()):
        return "THREAT INTEL", CATEGORY_EMOJI["THREAT INTEL"]

    text = " ".join([description.lower(), " ".join(g.lower() for g in groups), full_log.lower()])

    # 2) Grup rule (presisi utk rule non-custom / built-in Wazuh)
    group_set = set(g.strip().lower() for g in groups if g.strip())
    if group_set & {"otx", "ioc", "malicious_hash", "malicious_ip", "malicious_domain"}:
        return "THREAT INTEL", chr(0x1f50d)
    if "malware" in group_set:
        return "MALWARE", chr(0x1f9a0)
    if "defacement" in group_set:
        return "DEFACEMENT", chr(0x1f310)
    if "web_attack" in group_set:
        return "WEB ATTACK", chr(0x1f6e1)
    if "ddos" in group_set:
        return "DDoS / BRUTE FORCE", chr(0x26a1)

    # 3) Fallback keyword teks — hanya utk alert yg tak punya grup custom di atas
    if any(k in text for k in ["otx", "ioc", "threat intel", "virustotal", "malicious ip", "malicious hash", "malicious domain"]):
        return "THREAT INTEL", chr(0x1f50d)
    if any(k in text for k in ["malware", "trojan", "virus", "ransomware", "rootkit", "backdoor", "hidden script",
                                 "adware", "spyware", "cryptominer", "impacket", "log.*cleared", "log.*reduced",
                                 "persistence", "outbreak", "clamav", "kernel level"]):
        return "MALWARE", chr(0x1f9a0)
    if any(k in text for k in ["defacement", "web page modified", "webshell", "php file added"]):
        return "DEFACEMENT", chr(0x1f310)
    if any(k in text for k in ["sql injection", "xss", "cross site", "web attack", "buffer overflow",
                                 "shell command", "scanning", "400 error"]):
        return "WEB ATTACK", chr(0x1f6e1)
    if any(k in text for k in ["brute force", "ddos", "authentication failure", "multiple.*login",
                                 "denied user", "network scan", "max.*auth"]):
        return "DDoS / BRUTE FORCE", chr(0x26a1)
    return "SECURITY EVENT", chr(0x1f514)


def severity_label(level):
    if level >= 15:
        return "CRITICAL", chr(0x1f6a8)
    if level >= 12:
        return "HIGH", chr(0x1f536)
    if level >= 8:
        return "WARNING", chr(0x26a0) + chr(0xfe0f)
    return "INFO", chr(0x2139) + chr(0xfe0f)


SEVERITY_MAP = {
    "critical": ("CRITICAL", chr(0x1f534)),
    "high":     ("HIGH",     chr(0x1f7e0)),
    "medium":   ("MEDIUM",   chr(0x1f7e1)),
    "low":      ("LOW",      chr(0x1f7e2)),
}

def apply_rule_prefs(rule_id, rule_prefs, current_sev_label, current_sev_emoji, base_cooldown, max_cooldown):
    pref = rule_prefs.get(str(rule_id), {})
    if pref.get("enabled") is False:
        return True, current_sev_label, current_sev_emoji, base_cooldown, max_cooldown
    sev_override = pref.get("severity", "default").lower()
    if sev_override and sev_override != "default" and sev_override in SEVERITY_MAP:
        sev_label, sev_emoji = SEVERITY_MAP[sev_override]
    else:
        sev_label, sev_emoji = current_sev_label, current_sev_emoji
    custom_cd = pref.get("cooldown")
    if custom_cd and isinstance(custom_cd, (int, float)) and custom_cd > 0:
        base_cooldown = int(custom_cd) * 60
        max_cooldown  = max(base_cooldown, max_cooldown)
    return False, sev_label, sev_emoji, base_cooldown, max_cooldown

def build_title(category, description):
    desc = description.lower()

    if category == "DDoS / BRUTE FORCE":
        if any(k in desc for k in ["high volume", "high-volume", "sustained", "flood", "connection attempts"]):
            return "Serangan DDoS Terdeteksi"
        if any(k in desc for k in ["brute force", "multiple authentication", "failed login"]):
            return "Percobaan Login Berulang Terdeteksi"
        if "network scan" in desc:
            return "Aktivitas Scanning Jaringan Terdeteksi"
        return "Serangan Brute Force Terdeteksi"

    if category == "MALWARE":
        if "rootkit" in desc:
            return "Potensi Rootkit Terdeteksi"
        if "backdoor" in desc or "hidden" in desc:
            return "Backdoor atau Script Tersembunyi Ditemukan"
        if "persistence" in desc or "cron" in desc:
            return "Modifikasi Mekanisme Persistensi"
        if "log" in desc and ("cleared" in desc or "reduced" in desc):
            return "Indikasi Penghapusan Jejak (Anti-Forensics)"
        if "clamav" in desc or "virustotal" in desc:
            return "File Malicious Terdeteksi oleh Antivirus"
        return "Indikator Malware Ditemukan"

    if category == "DEFACEMENT":
        if "php" in desc or "webshell" in desc:
            return "Potensi Webshell Terdeteksi"
        return "Modifikasi Halaman Web Terdeteksi"

    if category == "WEB ATTACK":
        if "sql injection" in desc:
            return "Percobaan SQL Injection Terdeteksi"
        if "xss" in desc:
            return "Percobaan XSS Terdeteksi"
        if "buffer overflow" in desc or "url" in desc:
            return "Percobaan Buffer Overflow via URL"
        if "shell" in desc:
            return "Eksekusi Command via Web Terdeteksi"
        return "Serangan Web Terdeteksi"

    if category == "THREAT INTEL":
        if "ip malicious" in desc:
            return "Koneksi dari/ke IP Berbahaya"
        if "hash" in desc:
            return "File dengan Hash Malicious Ditemukan"
        if "domain" in desc:
            return "Akses ke Domain Berbahaya"
        if "cve" in desc:
            return "Eksploitasi CVE Terdeteksi"
        return "Kecocokan Threat Intelligence"

    return description[:60]


def build_analysis(category, agent_name, src_ip, description):
    host = escape_html(agent_name)
    ip   = escape_html(src_ip) if src_ip and src_ip != "-" else "tidak diketahui"

    if category == "DDoS / BRUTE FORCE":
        desc_lower = description.lower()
        if any(k in desc_lower for k in ["high volume", "high-volume", "sustained", "flood", "connection attempts"]):
            summary = (
                "Sistem mendeteksi volume koneksi yang sangat tinggi menuju host <b>%s</b> dalam "
                "waktu singkat, mengindikasikan serangan DDoS (Distributed Denial of Service) yang "
                "berpotensi membebani atau melumpuhkan layanan." % host
            )
        else:
            summary = (
                "Sistem mendeteksi aktivitas login berulang yang gagal pada host <b>%s</b>. "
                "Ini adalah pola umum dari internet scanner atau bot otomatis yang mencoba "
                "kombinasi username/password secara massal." % host
            )
    elif category == "MALWARE":
        summary = "Host <b>%s</b> menunjukkan indikasi file atau aktivitas yang cocok dengan pola malware." % host
    elif category == "DEFACEMENT":
        summary = "Terdeteksi perubahan pada file web di host <b>%s</b> yang mengindikasikan defacement atau webshell." % host
    elif category == "WEB ATTACK":
        summary = "Terdeteksi percobaan serangan web terhadap host <b>%s</b> dari IP <code>%s</code>." % (host, ip)
    elif category == "THREAT INTEL":
        summary = "Alert pada host <b>%s</b> cocok dengan indikator ancaman yang dipantau (IP/domain/hash berbahaya)." % host
    else:
        summary = "Wazuh mendeteksi event keamanan pada host <b>%s</b>." % host

    return summary, "", ""


def build_fingerprint(category, rule_id, agent_name, src_ip, extra=""):
    if category == "DDoS / BRUTE FORCE":
        # Pisah per rule_id: brute force (100020-100027) dan DDoS volumetrik (100030/100031)
        # dulu berbagi 1 fingerprint sehingga notif DDoS ikut ketahan cooldown brute force.
        return "DDOS|%s|%s" % (rule_id, agent_name)
    if category == "WEB ATTACK":
        return "WEBATK|%s|%s" % (rule_id, agent_name)  # per rule_id: tiap jenis serangan notif terpisah
    if category == "DEFACEMENT":
        # Kelompokkan per rule per agent — tapi beri cooldown agar tidak flood
        return "DEFACE|%s|%s" % (rule_id, agent_name)
    if category == "THREAT INTEL":
        # Kelompokkan per rule per agent
        return "THREATINTEL|%s|%s" % (rule_id, agent_name)
    if category == "MALWARE":
        return "MALWARE|%s|%s" % (agent_name, extra or rule_id)
    return "%s|%s|%s|%s" % (category, rule_id, agent_name, src_ip)


def main():
    alert_file = sys.argv[1]
    hook_url   = sys.argv[3]

    with open(alert_file) as f:
        alert = json.load(f)

    rule      = alert.get("rule", {})
    agent     = alert.get("agent", {})
    data      = alert.get("data", {})
    syscheck  = alert.get("syscheck", {})

    groups      = rule.get("groups", [])
    description = rule.get("description", "N/A")
    rule_id     = rule.get("id", "N/A")
    level       = int(rule.get("level", 0))
    agent_name  = agent.get("name", "N/A")
    agent_ip    = agent.get("ip", "N/A")
    timestamp   = alert.get("timestamp", "N/A")
    full_log    = alert.get("full_log", "")
    location    = alert.get("location", "-")

    srcip    = data.get("srcip", "") or alert.get("srcip", "") or ""
    dstip    = data.get("dstip", "") or ""
    username = data.get("dstuser", "") or data.get("srcuser", "") or ""

    category, cat_emoji  = categorize(rule_id, groups, description, full_log)
    sev_label, sev_emoji = severity_label(level)
    title                = build_title(category, description)
    summary, _, _        = build_analysis(category, agent_name, srcip, description)

    parts = hook_url.split("|")
    if len(parts) != 2:
        return
    bot_token, default_chat_id = parts

    tenant      = resolve_tenant_info(agent_name, default_chat_id)
    chat_id     = tenant['chat_id']
    rule_prefs  = tenant['rule_prefs']

    muted, sev_label, sev_emoji, BASE_COOLDOWN_RULE, MAX_COOLDOWN_RULE = apply_rule_prefs(
        rule_id, rule_prefs, sev_label, sev_emoji, BASE_COOLDOWN, MAX_COOLDOWN)
    if muted:
        return

    fim_path    = syscheck.get("path", "") if syscheck else ""
    fingerprint = build_fingerprint(category, rule_id, agent_name, srcip, extra=fim_path)

    # ---- Throttle DDoS / Brute Force ----
    if category == "DDoS / BRUTE FORCE":
        should_send, count, sends, unique_ips = check_and_update_cooldown(
            fingerprint, srcip, DDOS_BASE_COOLDOWN, DDOS_MAX_COOLDOWN
        )
        if not should_send:
            return

        next_cd_min = min(DDOS_BASE_COOLDOWN * (2 ** sends), DDOS_MAX_COOLDOWN) // 60

        if sends == 0:
            extra_lines = []
            if srcip:
                extra_lines.append("<b>Source IP:</b> <code>%s</code>" % escape_html(srcip))
            if username:
                extra_lines.append("<b>User:</b> <code>%s</code>" % escape_html(username))
            if location and location != "-":
                extra_lines.append("<b>Log:</b> <code>%s</code>" % escape_html(location))
            extra_block = ("\n" + "\n".join(extra_lines) + "\n") if extra_lines else ""

            text = (
                "%s <b>%s</b> | %s <b>%s</b>\n"
                "%s\n\n"
                "<b>%s</b>\n\n"
                "<b>Host:</b> %s (%s)\n"
                "<b>Waktu:</b> %s"
                "%s\n"
                "<b>Ringkasan:</b>\n%s\n\n"
                "%s%s <i>Alert serupa dari host ini akan dikelompokkan. "
                "Summary berikutnya dalam <b>%d menit</b>.</i>\n\n"
                "<b>Metadata:</b>\nRule: %s | Level: %d | %s"
            ) % (
                sev_emoji, escape_html(sev_label), cat_emoji, escape_html(category),
                SEPARATOR,
                escape_html(title),
                escape_html(agent_name), escape_html(agent_ip),
                escape_html(format_wib(timestamp)),
                extra_block,
                summary,
                chr(0x1f6e1), chr(0xfe0f), next_cd_min,
                escape_html(rule_id), level, escape_html(description)
            )
            send_telegram(bot_token, chat_id, text)
            return
        else:
            ip_list  = sorted(unique_ips)
            ip_count = len(ip_list)
            if ip_count <= 5:
                ip_display = ", ".join("<code>%s</code>" % escape_html(ip) for ip in ip_list)
            else:
                shown = ip_list[:5]
                ip_display = (
                    ", ".join("<code>%s</code>" % escape_html(ip) for ip in shown)
                    + " <i>dan %d IP lainnya</i>" % (ip_count - 5)
                )

            text = (
                "%s <b>SUMMARY</b> | %s <b>%s</b>\n"
                "%s\n\n"
                "<b>%s</b>\n\n"
                "<b>Host:</b> %s (%s)\n"
                "<b>Periode:</b> %d menit terakhir\n\n"
                "%s <b>%d percobaan</b> dari <b>%d IP berbeda</b> terdeteksi.\n"
                "<b>IP Penyerang:</b> %s\n\n"
                "%s%s <i>Kemungkinan internet scanner otomatis. "
                "Summary berikutnya dalam <b>%d menit</b>.</i>\n\n"
                "<b>Metadata:</b>\nRule: %s | Level: %d | %s"
            ) % (
                chr(0x1f4ca), cat_emoji, escape_html(category),
                SEPARATOR,
                escape_html(title),
                escape_html(agent_name), escape_html(agent_ip),
                next_cd_min // 2,
                chr(0x26a1), count, ip_count,
                ip_display,
                chr(0x1f6e1), chr(0xfe0f), next_cd_min,
                escape_html(rule_id), level, escape_html(description)
            )
            send_telegram(bot_token, chat_id, text)
            return

    # ---- Throttle Web Attack ----
    elif category == "WEB ATTACK":
        should_send, count, sends, unique_ips = check_and_update_cooldown(
            fingerprint, srcip, DDOS_BASE_COOLDOWN, DDOS_MAX_COOLDOWN
        )
        if not should_send:
            return

        next_cd_min = min(DDOS_BASE_COOLDOWN * (2 ** sends), DDOS_MAX_COOLDOWN) // 60

        if sends == 0:
            extra_lines = []
            if srcip:
                extra_lines.append("<b>Source IP:</b> <code>%s</code>" % escape_html(srcip))
            if location and location != "-":
                extra_lines.append("<b>Log:</b> <code>%s</code>" % escape_html(location))
            extra_block = ("\n" + "\n".join(extra_lines) + "\n") if extra_lines else ""

            text = (
                "%s <b>%s</b> | %s <b>%s</b>\n"
                "%s\n\n"
                "<b>%s</b>\n\n"
                "<b>Host:</b> %s (%s)\n"
                "<b>Waktu:</b> %s"
                "%s\n"
                "<b>Ringkasan:</b>\n%s\n\n"
                "%s%s <i>Alert serupa dari host ini akan dikelompokkan. "
                "Summary berikutnya dalam <b>%d menit</b>.</i>\n\n"
                "<b>Metadata:</b>\nRule: %s | Level: %d | %s"
            ) % (
                sev_emoji, escape_html(sev_label), cat_emoji, escape_html(category),
                SEPARATOR,
                escape_html(title),
                escape_html(agent_name), escape_html(agent_ip),
                escape_html(format_wib(timestamp)),
                extra_block,
                summary,
                chr(0x1f6e1), chr(0xfe0f), next_cd_min,
                escape_html(rule_id), level, escape_html(description)
            )
            send_telegram(bot_token, chat_id, text)
            return
        else:
            ip_list  = sorted(unique_ips)
            ip_count = len(ip_list)
            if ip_count <= 5:
                ip_display = ", ".join("<code>%s</code>" % escape_html(ip) for ip in ip_list)
            else:
                shown = ip_list[:5]
                ip_display = (
                    ", ".join("<code>%s</code>" % escape_html(ip) for ip in shown)
                    + " <i>dan %d IP lainnya</i>" % (ip_count - 5)
                )

            text = (
                "%s <b>SUMMARY</b> | %s <b>%s</b>\n"
                "%s\n\n"
                "<b>%s</b>\n\n"
                "<b>Host:</b> %s (%s)\n"
                "<b>Periode:</b> %d menit terakhir\n\n"
                "%s <b>%d serangan</b> dari <b>%d IP berbeda</b> terdeteksi.\n"
                "<b>IP Penyerang:</b> %s\n\n"
                "%s%s <i>Kemungkinan internet scanner otomatis. "
                "Summary berikutnya dalam <b>%d menit</b>.</i>\n\n"
                "<b>Metadata:</b>\nRule: %s | Level: %d | %s"
            ) % (
                chr(0x1f4ca), cat_emoji, escape_html(category),
                SEPARATOR,
                escape_html(title),
                escape_html(agent_name), escape_html(agent_ip),
                next_cd_min // 2,
                chr(0x1f6e1), count, ip_count,
                ip_display,
                chr(0x1f6e1), chr(0xfe0f), next_cd_min,
                escape_html(rule_id), level, escape_html(description)
            )
            send_telegram(bot_token, chat_id, text)
            return

    # ---- Throttle DEFACEMENT (FIX: tambahkan cooldown 10 menit per rule per agent) ----
    elif category == "DEFACEMENT":
        should_send, count, sends, unique_ips = check_and_update_cooldown(
            fingerprint, srcip, BASE_COOLDOWN, MAX_COOLDOWN
        )
        if not should_send:
            return

        next_cd_min = min(BASE_COOLDOWN * (2 ** sends), MAX_COOLDOWN) // 60

        extra_lines = []
        if syscheck:
            fp     = syscheck.get("path", "")
            md5    = syscheck.get("md5_after", "")
            sha256 = syscheck.get("sha256_after", "")
            if fp:
                extra_lines.append("<b>File:</b> <code>%s</code>" % escape_html(fp))
            if md5:
                extra_lines.append("<b>MD5:</b> <code>%s</code>" % escape_html(md5))
            if sha256:
                extra_lines.append("<b>SHA256:</b> <code>%s...</code>" % escape_html(sha256[:32]))
        if srcip:
            extra_lines.append("<b>Source IP:</b> <code>%s</code>" % escape_html(srcip))
        if location and location != "-":
            extra_lines.append("<b>Log:</b> <code>%s</code>" % escape_html(location))
        extra_block = ("\n" + "\n".join(extra_lines) + "\n") if extra_lines else ""

        if sends == 0:
            text = (
                "%s <b>%s</b> | %s <b>%s</b>\n"
                "%s\n\n"
                "<b>%s</b>\n\n"
                "<b>Host:</b> %s (%s)\n"
                "<b>Waktu:</b> %s"
                "%s\n"
                "<b>Ringkasan:</b>\n%s\n\n"
                "%s%s <i>Alert serupa akan dikelompokkan selama <b>%d menit</b> ke depan.</i>\n\n"
                "<b>Metadata:</b>\nRule: %s | Level: %d | %s"
            ) % (
                sev_emoji, escape_html(sev_label), cat_emoji, escape_html(category),
                SEPARATOR,
                escape_html(title),
                escape_html(agent_name), escape_html(agent_ip),
                escape_html(format_wib(timestamp)),
                extra_block,
                summary,
                chr(0x1f6e1), chr(0xfe0f), next_cd_min,
                escape_html(rule_id), level, escape_html(description)
            )
        else:
            text = (
                "%s <b>SUMMARY</b> | %s <b>%s</b>\n"
                "%s\n\n"
                "<b>%s</b>\n\n"
                "<b>Host:</b> %s (%s)\n"
                "<b>Periode:</b> %d menit terakhir\n\n"
                "%s <b>%d event</b> terdeteksi sejak alert terakhir.\n"
                "%s%s <i>Summary berikutnya dalam <b>%d menit</b>.</i>\n\n"
                "<b>Metadata:</b>\nRule: %s | Level: %d | %s"
            ) % (
                chr(0x1f4ca), cat_emoji, escape_html(category),
                SEPARATOR,
                escape_html(title),
                escape_html(agent_name), escape_html(agent_ip),
                next_cd_min // 2,
                chr(0x1f310), count,
                chr(0x1f6e1), chr(0xfe0f), next_cd_min,
                escape_html(rule_id), level, escape_html(description)
            )
        send_telegram(bot_token, chat_id, text)
        return

    # ---- Throttle THREAT INTEL (FIX: tambahkan cooldown 10 menit per rule per agent) ----
    elif category == "THREAT INTEL":
        should_send, count, sends, _ = check_and_update_cooldown(
            fingerprint, srcip, BASE_COOLDOWN, MAX_COOLDOWN
        )
        if not should_send:
            return

    # ---- Throttle MALWARE (per file path) ----
    elif category == "MALWARE":
        should_send, count, sends, _ = check_and_update_cooldown(
            fingerprint, "", 300, 1800
        )
        if not should_send:
            return

    # ---- Format pesan lengkap (THREAT INTEL, MALWARE, SECURITY EVENT) ----
    extra_lines = []
    if srcip:
        extra_lines.append("<b>Source IP:</b> <code>%s</code>" % escape_html(srcip))
    if dstip:
        extra_lines.append("<b>Dest IP:</b> <code>%s</code>" % escape_html(dstip))
    if username:
        extra_lines.append("<b>User:</b> <code>%s</code>" % escape_html(username))
    if syscheck:
        fp     = syscheck.get("path", "")
        md5    = syscheck.get("md5_after", "")
        sha256 = syscheck.get("sha256_after", "")
        if fp:
            extra_lines.append("<b>File:</b> <code>%s</code>" % escape_html(fp))
        if md5:
            extra_lines.append("<b>MD5:</b> <code>%s</code>" % escape_html(md5))
        if sha256:
            extra_lines.append("<b>SHA256:</b> <code>%s...</code>" % escape_html(sha256[:32]))
    if location and location != "-":
        extra_lines.append("<b>Log:</b> <code>%s</code>" % escape_html(location))

    extra_block = "\n".join(extra_lines) if extra_lines else ""

    text = (
        "%s <b>%s</b> | %s <b>%s</b>\n"
        "%s\n\n"
        "<b>%s</b>\n\n"
        "<b>Host:</b> %s (%s)\n"
        "<b>Waktu:</b> %s\n"
    ) % (
        sev_emoji, escape_html(sev_label), cat_emoji, escape_html(category),
        SEPARATOR,
        escape_html(title),
        escape_html(agent_name), escape_html(agent_ip),
        escape_html(format_wib(timestamp))
    )

    if extra_block:
        text += "\n%s\n" % extra_block

    text += (
        "\n<b>Ringkasan:</b>\n%s\n"
        "\n<b>Metadata:</b>\n"
        "Rule: %s | Level: %d | %s"
    ) % (summary, escape_html(rule_id), level, escape_html(description))

    send_telegram(bot_token, chat_id, text)


if __name__ == "__main__":
    main()
