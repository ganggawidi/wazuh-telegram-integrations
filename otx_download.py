import requests
import json
import os
import sys
import time
import hashlib
from datetime import datetime, timedelta

# ==================== KONFIGURASI ====================
OTX_API_KEY = "KODE API"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
CDB_DIR = "/var/ossec/etc/lists"
CACHE_DIR = "/var/ossec/integrations/otx_cache"
CACHE_FILE = os.path.join(CACHE_DIR, "otx_cache.json")
STATS_FILE = os.path.join(CACHE_DIR, "otx_stats.json")

HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}

# Rate limiting: max requests per menit
RATE_LIMIT_MAX_REQUESTS = 20
RATE_LIMIT_WINDOW = 60  # detik

# Cache TTL: berapa lama cache valid (dalam jam)
CACHE_TTL_HOURS = 6

# Pulse count threshold: IoC harus muncul di minimal N pulse
# untuk dikonfirmasi sebagai ancaman (mengurangi false positive)
PULSE_COUNT_THRESHOLD = 2

# Maksimum halaman yang di-fetch
MAX_PAGES = 20

# ==================== RATE LIMITER ====================
class RateLimiter:
    """Mencegah pengiriman request berlebihan ke OTX API."""

    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests_made = []

    def wait_if_needed(self):
        now = time.time()
        # Hapus request yang sudah di luar window
        self.requests_made = [t for t in self.requests_made if now - t < self.window]

        if len(self.requests_made) >= self.max_requests:
            wait_time = self.window - (now - self.requests_made[0])
            if wait_time > 0:
                print(f"  [Rate Limit] Menunggu {wait_time:.1f}s sebelum request berikutnya...")
                time.sleep(wait_time)

        self.requests_made.append(time.time())

    def get_stats(self):
        return {
            "total_requests": len(self.requests_made),
            "max_per_window": self.max_requests,
            "window_seconds": self.window
        }

# ==================== CACHE MANAGER ====================
class CacheManager:
    """Menyimpan hasil enrichment sementara untuk menghindari query berulang."""

    def __init__(self, cache_file, ttl_hours):
        self.cache_file = cache_file
        self.ttl_hours = ttl_hours
        self.cache = self._load_cache()

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    cache = json.load(f)
                # Cek apakah cache masih valid
                cached_time = datetime.fromisoformat(cache.get('timestamp', '2000-01-01'))
                if datetime.utcnow() - cached_time < timedelta(hours=self.ttl_hours):
                    print(f"  [Cache] Cache valid (dibuat: {cached_time.isoformat()})")
                    return cache
                else:
                    print(f"  [Cache] Cache expired (dibuat: {cached_time.isoformat()})")
            except (json.JSONDecodeError, ValueError):
                pass
        return None

    def is_valid(self):
        return self.cache is not None

    def get_indicators(self):
        if self.cache:
            return self.cache.get('indicators', {})
        return None

    def save(self, indicators, raw_pulse_data):
        os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
        cache_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'ttl_hours': self.ttl_hours,
            'indicators': {k: list(v) for k, v in indicators.items()},
            'pulse_count': len(raw_pulse_data),
            'total_ioc': sum(len(v) for v in indicators.values())
        }
        with open(self.cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)
        print(f"  [Cache] Cache disimpan ({cache_data['total_ioc']} IoC)")

# ==================== FALLBACK MANAGER ====================
class FallbackManager:
    """Jika OTX unreachable, gunakan CDB lists yang sudah ada."""

    @staticmethod
    def has_existing_lists():
        """Cek apakah ada CDB lists yang masih bisa dipakai."""
        required_files = [
            'otx_malicious_ip',
            'otx_malicious_domains_all',
            'otx_malicious_hash_md5'
        ]
        existing = []
        for f in required_files:
            filepath = os.path.join(CDB_DIR, f)
            if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                existing.append(f)
        return existing

    @staticmethod
    def get_list_age():
        """Cek umur CDB lists yang ada."""
        ages = {}
        for f in os.listdir(CDB_DIR):
            if f.startswith('otx_'):
                filepath = os.path.join(CDB_DIR, f)
                mtime = os.path.getmtime(filepath)
                age_hours = (time.time() - mtime) / 3600
                ages[f] = round(age_hours, 1)
        return ages

# ==================== PULSE COUNTER ====================
class PulseCountFilter:
    """
    Filter IoC berdasarkan jumlah pulse OTX.
    IoC yang muncul di banyak pulse lebih terpercaya.
    Mengurangi false positive dari laporan yang belum terverifikasi.
    """

    def __init__(self, threshold):
        self.threshold = threshold
        self.ioc_pulse_count = {}  # {ioc_value: count_of_pulses}
        self.filtered_count = 0
        self.passed_count = 0

    def add_from_pulse(self, indicator_value, pulse_id):
        key = indicator_value.strip().lower()
        if key not in self.ioc_pulse_count:
            self.ioc_pulse_count[key] = set()
        self.ioc_pulse_count[key].add(pulse_id)

    def passes_threshold(self, indicator_value):
        key = indicator_value.strip().lower()
        count = len(self.ioc_pulse_count.get(key, set()))
        if count >= self.threshold:
            self.passed_count += 1
            return True
        self.filtered_count += 1
        return False

    def get_stats(self):
        return {
            "threshold": self.threshold,
            "total_unique_ioc": len(self.ioc_pulse_count),
            "passed_threshold": self.passed_count,
            "filtered_out": self.filtered_count,
            "filter_rate": f"{(self.filtered_count / max(len(self.ioc_pulse_count), 1) * 100):.1f}%"
        }

# ==================== MAIN DOWNLOADER ====================
def fetch_pulses(rate_limiter, days=30):
    """Fetch pulses dari OTX dengan rate limiting."""
    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    url = f"{OTX_BASE_URL}/pulses/subscribed?modified_since={since}&limit=50"

    all_pulses = []
    page = 1

    while url and page <= MAX_PAGES:
        rate_limiter.wait_if_needed()

        print(f"  [Fetch] Halaman {page}...")
        try:
            resp = requests.get(url, headers=HEADERS, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.ConnectionError:
            print(f"  [Error] Tidak dapat terhubung ke OTX API")
            return None  # Signal untuk fallback
        except requests.exceptions.Timeout:
            print(f"  [Error] Request timeout ke OTX API")
            return None
        except requests.exceptions.HTTPError as e:
            if resp.status_code == 429:
                print(f"  [Rate Limit] OTX API rate limit hit, menunggu 60s...")
                time.sleep(60)
                continue
            print(f"  [Error] HTTP Error: {e}")
            return None
        except Exception as e:
            print(f"  [Error] Unexpected: {e}")
            return None

        pulses = data.get('results', [])
        all_pulses.extend(pulses)
        print(f"  [Fetch] Dapat {len(pulses)} pulses (total: {len(all_pulses)})")

        url = data.get('next', None)
        page += 1

    return all_pulses

def process_pulses(pulses, pulse_filter):
    """Process pulses dan filter dengan pulse count threshold."""

    # Phase 1: Hitung kemunculan setiap IoC di berbagai pulse
    print("\n[Phase 1] Menghitung pulse count per IoC...")
    for pulse in pulses:
        pulse_id = pulse.get('id', '')
        for indicator in pulse.get('indicators', []):
            ioc_value = indicator.get('indicator', '').strip()
            if ioc_value:
                pulse_filter.add_from_pulse(ioc_value, pulse_id)

    print(f"  Total unique IoC sebelum filter: {len(pulse_filter.ioc_pulse_count)}")

    # Phase 2: Filter dan kategorikan IoC
    print(f"\n[Phase 2] Memfilter IoC (threshold: >= {pulse_filter.threshold} pulses)...")
    indicators = {
        'ip': set(),
        'domain': set(),
        'hostname': set(),
        'hash_md5': set(),
        'hash_sha256': set(),
        'cve': set()
    }

    for pulse in pulses:
        for indicator in pulse.get('indicators', []):
            ioc_type = indicator.get('type', '')
            ioc_value = indicator.get('indicator', '').strip()

            if not ioc_value:
                continue

            # Cek pulse count threshold
            if not pulse_filter.passes_threshold(ioc_value):
                continue

            if ioc_type == 'IPv4':
                indicators['ip'].add(ioc_value)
            elif ioc_type == 'domain':
                indicators['domain'].add(ioc_value)
            elif ioc_type == 'hostname':
                indicators['hostname'].add(ioc_value)
            elif ioc_type == 'FileHash-MD5':
                indicators['hash_md5'].add(ioc_value.lower())
            elif ioc_type == 'FileHash-SHA256':
                indicators['hash_sha256'].add(ioc_value.lower())
            elif ioc_type == 'CVE':
                indicators['cve'].add(ioc_value.upper())

    return indicators

def write_cdb_list(filename, indicators, description):
    """Write indicators ke format Wazuh CDB list."""
    filepath = os.path.join(CDB_DIR, filename)
    count = 0
    with open(filepath, 'w') as f:
        for indicator in sorted(indicators):
            clean = indicator.replace(':', '_')
            f.write(f"{clean}:\n")
            count += 1
    print(f"  {description}: {count} IoC -> {filename}")
    return count

def save_stats(stats):
    """Simpan statistik download untuk monitoring."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    stats['timestamp'] = datetime.utcnow().isoformat()
    with open(STATS_FILE, 'w') as f:
        json.dump(stats, f, indent=2)

def main():
    print("=" * 60)
    print(f"OTX AlienVault IoC Downloader")
    print(f"Waktu: {datetime.utcnow().isoformat()}")
    print(f"Pulse threshold: {PULSE_COUNT_THRESHOLD}")
    print(f"Cache TTL: {CACHE_TTL_HOURS} jam")
    print(f"Rate limit: {RATE_LIMIT_MAX_REQUESTS} req/{RATE_LIMIT_WINDOW}s")
    print("=" * 60)

    os.makedirs(CDB_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)

    # Inisialisasi komponen
    rate_limiter = RateLimiter(RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW)
    cache_mgr = CacheManager(CACHE_FILE, CACHE_TTL_HOURS)
    fallback_mgr = FallbackManager()
    pulse_filter = PulseCountFilter(PULSE_COUNT_THRESHOLD)

    stats = {
        'status': 'unknown',
        'source': 'unknown'
    }

    # ---- Cek Cache ----
    if cache_mgr.is_valid():
        print("\n[Cache] Menggunakan cached data (masih valid)")
        cached = cache_mgr.get_indicators()
        indicators = {k: set(v) for k, v in cached.items()}
        stats['source'] = 'cache'
        stats['status'] = 'success'
    else:
        # ---- Fetch dari OTX ----
        print("\n[Fetch] Mengunduh pulses dari OTX AlienVault...")
        pulses = fetch_pulses(rate_limiter, days=30)

        if pulses is None:
            # ---- Fallback ----
            print("\n[Fallback] OTX tidak dapat dijangkau!")
            existing = fallback_mgr.has_existing_lists()
            if existing:
                ages = fallback_mgr.get_list_age()
                print(f"  Menggunakan CDB lists yang sudah ada:")
                for f in existing:
                    print(f"    - {f} (umur: {ages.get(f, '?')} jam)")
                stats['source'] = 'fallback'
                stats['status'] = 'fallback_used'
                stats['existing_lists'] = existing
                stats['list_ages'] = ages
                stats['rate_limiter'] = rate_limiter.get_stats()
                save_stats(stats)
                print("\n[Done] Deteksi tetap berjalan dengan data sebelumnya.")
                return
            else:
                print("  PERINGATAN: Tidak ada CDB lists backup!")
                stats['source'] = 'none'
                stats['status'] = 'failed_no_fallback'
                save_stats(stats)
                return

        if len(pulses) == 0:
            print("\n[Info] Tidak ada pulse baru ditemukan")
            stats['status'] = 'no_new_pulses'
            stats['source'] = 'otx_api'
            save_stats(stats)
            return

        print(f"\n[OK] Total {len(pulses)} pulses diunduh")

        # ---- Process dengan Pulse Count Threshold ----
        indicators = process_pulses(pulses, pulse_filter)

        # ---- Simpan ke cache ----
        cache_mgr.save(indicators, pulses)

        stats['source'] = 'otx_api'
        stats['status'] = 'success'
        stats['pulses_fetched'] = len(pulses)
        stats['pulse_filter'] = pulse_filter.get_stats()
        stats['rate_limiter'] = rate_limiter.get_stats()

    # ---- Merge seed IoC permanen (demo/lokus) ----
    indicators.setdefault('ip', set()).update(SEED_IP)
    indicators.setdefault('domain', set()).update(SEED_DOMAIN)
    indicators.setdefault('hash_md5', set()).update(SEED_MD5)
    indicators.setdefault('hash_sha256', set()).update(SEED_SHA256)

    # ---- Write CDB Lists ----
    print("\n[Write] Menyimpan ke Wazuh CDB lists...")
    ioc_stats = {}
    ioc_stats['ip'] = write_cdb_list('otx_malicious_ip', indicators.get('ip', set()), 'Malicious IPs')
    ioc_stats['domain'] = write_cdb_list('otx_malicious_domain', indicators.get('domain', set()), 'Malicious Domains')
    ioc_stats['hostname'] = write_cdb_list('otx_malicious_hostname', indicators.get('hostname', set()), 'Malicious Hostnames')
    ioc_stats['hash_md5'] = write_cdb_list('otx_malicious_hash_md5', indicators.get('hash_md5', set()), 'Malicious MD5')
    ioc_stats['hash_sha256'] = write_cdb_list('otx_malicious_hash_sha256', indicators.get('hash_sha256', set()), 'Malicious SHA256')
    ioc_stats['cve'] = write_cdb_list('otx_cve', indicators.get('cve', set()), 'CVEs')

    # Gabungan domain + hostname
    all_domains = indicators.get('domain', set()) | indicators.get('hostname', set())
    write_cdb_list('otx_malicious_domains_all', all_domains, 'All Domains/Hostnames')

    total = sum(ioc_stats.values())
    stats['ioc_counts'] = ioc_stats
    stats['total_ioc'] = total
    save_stats(stats)

    # ---- Summary ----
    print(f"\n{'=' * 60}")
    print(f"SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Source       : {stats['source']}")
    print(f"  Status       : {stats['status']}")
    print(f"  Total IoC    : {total}")
    for k, v in ioc_stats.items():
        print(f"    - {k:15s}: {v}")
    if 'pulse_filter' in stats:
        pf = stats['pulse_filter']
        print(f"  Pulse Filter : threshold={pf['threshold']}, "
              f"passed={pf['passed_threshold']}, "
              f"filtered={pf['filtered_out']} ({pf['filter_rate']})")
    print(f"{'=' * 60}")

    # Restart Wazuh untuk reload CDB lists
    print("\n[Restart] Restarting Wazuh Manager...")
    os.system("systemctl restart wazuh-manager")
    print("[Done] Integrasi OTX selesai.")

if __name__ == '__main__':
