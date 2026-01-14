#!/usr/bin/env bash
# ==============================================================================
# FLAWK AD RUNNER - DEBUG INSTALLER (v0.1.1)
#
# CHANGES:
# - LOGGING: Python now logs the exact 'mpv' command line.
# - LOGGING: Python captures and logs MPV startup errors (stderr).
# - MPV: Enabled verbose video driver logging to /tmp/mpv_debug.log.
# - SYSTEM: 'supervisor.sh' now greps the process list to find the real XAuth.
# ==============================================================================

# Strict Mode
set -eu

# ==============================================================================
# [1] INSTALLER LOGGING
# ==============================================================================
LOG_DIR="/var/log/ad-runner"
if [ ! -d "$LOG_DIR" ]; then mkdir -p "$LOG_DIR"; chmod 777 "$LOG_DIR"; fi
INSTALL_LOG="$LOG_DIR/install.log"
exec > >(tee -a "$INSTALL_LOG") 2>&1

echo "=== [$(date)] Starting v0.1.1 Debug Installation ==="

# ==============================================================================
# [2] CONSTANTS
# ==============================================================================
BASE_DIR="/opt/flawk"
DATA_DIR="$BASE_DIR/data"
VERSIONS_DIR="$BASE_DIR/versions"
CURRENT_VER="v0.1.1"
INSTALL_DIR="$VERSIONS_DIR/$CURRENT_VER"
LEGACY_APP_DIR="/opt/ad-runner"
API_URL="https://cms.flawkai.com/api/dooh/golocal_screens/ads"
HEARTBEAT_URL="https://cms.flawkai.com/api/dooh/heartbeat"
MANIFEST_URL="https://cms.flawkai.com/api/updates/manifest.json"
DEFAULT_API_KEY="LIVE-XujYRzCR2OOZRgTj9u0nsBASoNmO7g5b"

# ==============================================================================
# [3] HELPERS
# ==============================================================================
die(){ echo "FATAL ERROR: $*" >&2; exit 1; }
detect_run_user() {
  if [ "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then echo "$SUDO_USER"; return; fi
  if u=$(logname 2>/dev/null) && [ -n "$u" ] && [ "$u" != "root" ]; then echo "$u"; return; fi
  if u=$(who | awk 'NR==1{print $1}'); then [ -n "$u" ] && [ "$u" != "root" ] && echo "$u" && return; fi
  echo "pi" # Fallback
}
ensure_user_bus() {
  local u="$1"; local uid; uid=$(id -u "$u")
  loginctl enable-linger "$u" >/dev/null 2>&1 || true
  if ! systemctl is-active "user@${uid}.service" >/dev/null 2>&1; then
    systemctl start "user@${uid}.service" || true
    sleep 1
  fi
}

# ==============================================================================
# [4] PRE-FLIGHT
# ==============================================================================
RUN_USER="$(detect_run_user)"
RUN_GROUP="$(id -gn "$RUN_USER")"
RUN_UID=$(id -u "$RUN_USER")
echo "== Target User: $RUN_USER (UID: $RUN_UID) =="

# ==============================================================================
# [5] CLEANUP
# ==============================================================================
echo "== Phase 1: Cleaning System =="
BACKUP_CONF="/tmp/flawk_config.bak"
if [ -f "$DATA_DIR/config.json" ]; then cp "$DATA_DIR/config.json" "$BACKUP_CONF"; fi

systemctl stop ad-runner.service 2>/dev/null || true
pkill -9 -f "ad_runner.py" 2>/dev/null || true
pkill -9 -f "mpv --fs" 2>/dev/null || true
rm -rf "$LEGACY_APP_DIR" "$VERSIONS_DIR" "$BASE_DIR/current"

# ==============================================================================
# [6] DEPENDENCIES
# ==============================================================================
echo "== Phase 2: Dependencies =="
apt-get install -y mpv python3 python3-venv python3-pip curl ca-certificates jq pulseaudio-utils || true

# ==============================================================================
# [7] SETUP
# ==============================================================================
echo "== Phase 3: Setup =="
mkdir -p "$DATA_DIR/cache" "$DATA_DIR/logs" "$INSTALL_DIR"
if [ -f "$BACKUP_CONF" ]; then mv "$BACKUP_CONF" "$DATA_DIR/config.json"; fi
chown -R "$RUN_USER:$RUN_GROUP" "$BASE_DIR" "$LOG_DIR"

# ==============================================================================
# [8] CONFIG
# ==============================================================================
CONF_FILE="$DATA_DIR/config.json"
if [ ! -f "$CONF_FILE" ]; then
    if [ -t 0 ]; then read -rp "Device ID: " DEVICE_ID; else DEVICE_ID="DebugDevice"; fi
    sudo -u "$RUN_USER" tee "$CONF_FILE" >/dev/null <<JSON
{
  "device_id": "$DEVICE_ID",
  "api_url": "$API_URL",
  "api_key": "$DEFAULT_API_KEY",
  "heartbeat_url": "$HEARTBEAT_URL",
  "manifest_url": "$MANIFEST_URL",
  "width": 1920, "height": 1080, "poll_interval_secs": 10, "fill_window_secs": 30,
  "queue_max": 5, "per_ad_cooldown_secs": 30, "initial_start_delay_secs": 5,
  "cache_dir": "$DATA_DIR/cache", "log_file": "$DATA_DIR/logs/ad_runner.log",
  "play_sound": true, "duck_other_audio": true, "force_ipv4": true
}
JSON
fi

# ==============================================================================
# [9] PYTHON
# ==============================================================================
echo "== Phase 5: Python Setup =="
sudo -u "$RUN_USER" python3 -m venv "$INSTALL_DIR/.venv"
sudo -u "$RUN_USER" "$INSTALL_DIR/.venv/bin/pip" install --upgrade pip requests urllib3

# ==============================================================================
# [10] APPLICATION CODE (DEBUG VERSION)
# ==============================================================================
echo "== Phase 6: Installing Debug Logic =="

sudo -u "$RUN_USER" tee "$INSTALL_DIR/ad_runner.py" >/dev/null <<'PY'
#!/usr/bin/env python3
import os, sys, time, json, random, hashlib, threading, subprocess, logging, logging.handlers, fcntl, re, socket
import concurrent.futures
import urllib.parse as up
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import connection, Retry
from xml.etree import ElementTree as ET

LOCK_PATH = "/opt/ad-runner/ad_runner.lock"
# API HEADERS (Keep separate from download headers)
API_HEADERS = {"User-Agent":"FlawkAdRunner/0.1.1","Accept":"application/xml,text/xml,*/*"}
MPV_TIMEOUT_BUFFER = 40 

def clean_vast_str(s): return str(s).strip() if s else ""

def remove_xml_namespaces(xml_string):
    try:
        if isinstance(xml_string, bytes): xml_string = xml_string.decode('utf-8', errors='ignore')
        return re.sub(r' xmlns:?[^=]*=["\'][^"\']*["\']', '', xml_string)
    except: return xml_string

def make_session(force_ipv4):
    if force_ipv4:
        fam = socket.AF_INET; orig = connection.allowed_gai_family
        connection.allowed_gai_family = lambda: fam
    s = requests.Session()
    retries = Retry(total=3, connect=3, read=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("http://", adapter); s.mount("https://", adapter)
    return s

def acquire_singleton_lock(lock_path):
    Path(os.path.dirname(lock_path)).mkdir(parents=True, exist_ok=True)
    fp = open(lock_path, "a+")
    try: fcntl.flock(fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: sys.exit(1)
    return fp

def ensure_dir(p): Path(p).mkdir(parents=True, exist_ok=True)
def sha256_hex(s): return hashlib.sha256(s.encode("utf-8")).hexdigest()

def parse_duration(t:str)->int:
    if not t: return 0
    s=str(t).strip()
    try:
        if ':' not in s: return int(float(s))
        if '.' in s: s=s.split('.')[0]
        parts = s.split(':')
        if len(parts)==3: return int(parts[0])*3600 + int(parts[1])*60 + int(parts[2])
        if len(parts)==2: return int(parts[0])*60 + int(parts[1])
    except: pass
    return 15

def replace_macros(url, duration, playhead):
    ts=int(time.time()); cb=str(random.randint(10000000,99999999))
    return (url.replace("[TIMESTAMP]",str(ts)).replace("[CACHEBUSTING]",cb))

def parse_vast_recursive(xml_content, session, depth=0, max_depth=5):
    if depth > max_depth: return None
    result = {"media_url": None, "duration": 15, "impressions": [], "trackers": {"start":[],"firstQuartile":[],"midpoint":[],"thirdQuartile":[],"complete":[]}}
    clean_xml = remove_xml_namespaces(xml_content)
    try: root = ET.fromstring(clean_xml)
    except: return None

    ad_node = root.find(".//Ad"); 
    if ad_node is None: ad_node = root 
    wrapper = ad_node.find(".//Wrapper"); inline = ad_node.find(".//InLine")
    if inline is None: inline = ad_node.find(".//Inline")
    active_node = wrapper if wrapper is not None else inline
    if active_node is None: return None

    imps = set() 
    for imp in active_node.findall(".//Impression"):
        val = clean_vast_str(imp.text)
        if val: imps.add(val)
    result["impressions"] = list(imps)

    for trk in active_node.findall(".//Tracking"):
        evt = trk.get("event")
        url = clean_vast_str(trk.text)
        if evt in result["trackers"] and url: result["trackers"][evt].append(url)

    if wrapper is not None:
        tag_uri = wrapper.find(".//VASTAdTagURI")
        if tag_uri is not None and tag_uri.text:
            try:
                r = session.get(clean_vast_str(tag_uri.text), headers=API_HEADERS, timeout=5)
                if r.ok:
                    child = parse_vast_recursive(r.content, session, depth+1, max_depth)
                    if child:
                        result["media_url"] = child["media_url"]
                        result["duration"] = child["duration"]
                        result["impressions"] = list(set(result["impressions"] + child["impressions"]))
                        for k in result["trackers"]: result["trackers"][k] = list(set(result["trackers"][k] + child["trackers"][k]))
            except: pass
    elif inline is not None:
        candidates = []
        for mf in inline.findall(".//MediaFile"):
            u = clean_vast_str(mf.text)
            if not u: continue
            u = u.replace('\n', '').replace('\r', '').replace('\t', '').strip()
            typ = mf.get("type", "").lower()
            if "mp4" not in typ and not u.endswith(".mp4"): continue
            w_str, h_str = mf.get("width"), mf.get("height")
            try: w = int(w_str) if w_str else 0; h = int(h_str) if h_str else 0
            except: w, h = 0, 0
            candidates.append({"url": u, "w": w, "h": h})
        if candidates:
            candidates.sort(key=lambda c: min(abs(c["h"] - 1080), abs(c["h"] - 720)))
            result["media_url"] = candidates[0]["url"]
        else:
            m = re.search(r'MediaFile.*?><!\[CDATA\[(.*?)\]\]>', clean_xml, re.S)
            if m: result["media_url"] = clean_vast_str(m.group(1))
        dn = inline.find(".//Duration")
        if dn is not None and dn.text: result["duration"] = parse_duration(dn.text)
    return result

def parse_legacy_fallback(txt):
    media = re.search(r'MediaFile.*?><!\[CDATA\[(.*?)\]\]>', txt, re.S)
    if not media: media = re.search(r'MediaFile.*?>\s*(http.*?)\s*<', txt, re.S)
    if not media: return None
    dur_m = re.search(r'<Duration>(.*?)</Duration>', txt)
    dur = parse_duration(dur_m.group(1)) if dur_m else 15
    return {"media_url": clean_vast_str(media.group(1)), "duration": dur, "impressions": [], "trackers": {}}

class Log:
    def __init__(self, logfile):
        self.l = logging.getLogger("ad-runner")
        self.l.setLevel(logging.INFO)
        self.l.propagate = False
        if self.l.handlers: return
        fmt=logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        if logfile:
            fh=logging.handlers.RotatingFileHandler(logfile, maxBytes=10*1024*1024, backupCount=5)
            fh.setFormatter(fmt); self.l.addHandler(fh)
        sh=logging.StreamHandler(sys.stdout); sh.setFormatter(fmt); self.l.addHandler(sh)
    def info(self,*a): self.l.info(" ".join(map(str,a)))
    def warn(self,*a): self.l.warning(" ".join(map(str,a)))
    def err (self,*a): self.l.error(" ".join(map(str,a)))

def enforce_cache_budget(cache_dir, max_mb=1500, log=None):
    try:
        p = Path(cache_dir)
        if not p.exists(): return
        files = [f for f in p.glob("*") if f.is_file()]
        now = time.time()
        for f in files:
            if (now - f.stat().st_mtime) > (30 * 86400): f.unlink(missing_ok=True)
    except: pass

def download_if_needed(url, cache_dir, session, logger=None):
    enforce_cache_budget(cache_dir)
    ensure_dir(cache_dir)
    url = clean_vast_str(url).replace('\n','').replace('\r','').replace(' ','')
    if not url: return None
    ext = os.path.splitext(up.urlparse(url).path)[1] or ".mp4"
    filename = sha256_hex(url) + ext
    path = os.path.join(cache_dir, filename)
    if os.path.exists(path):
        if os.path.getsize(path) > 1024: return path
        try: os.unlink(path)
        except: pass
    dl_headers = {"User-Agent": "FlawkAdRunner/0.1.1", "Accept": "*/*"}
    try:
        r = session.get(url, headers=dl_headers, timeout=60, stream=True)
        if not r.ok:
            if logger: logger.warn(f"Download Fail [HTTP {r.status_code}]")
            return url
        temp_path = path + ".tmp"
        with open(temp_path, "wb") as f:
            for chunk in r.iter_content(8192):
                if chunk: f.write(chunk)
        if os.path.getsize(temp_path) > 1024:
            os.rename(temp_path, path)
            if logger: logger.info(f"Cached: {filename}")
            return path
        else:
            os.unlink(temp_path)
            return url
    except Exception as e:
        if logger: logger.err(f"DL Error: {e}")
        return url

class Runner:
    def __init__(self, cfg_path):
        with open(cfg_path) as f: self.cfg = json.load(f)
        self.device = self.cfg.get("device_id","")
        self.api = self.cfg.get("api_url","")
        self.api_key = self.cfg.get("api_key","")
        self.hb_url = self.cfg.get("heartbeat_url","")
        self.cache = self.cfg.get("cache_dir")
        self.log = Log(self.cfg.get("log_file"))
        self.http = make_session(self.cfg.get("force_ipv4", True))
        ensure_dir(self.cache)
        self.queue = []
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=6)
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()

    def get_stats(self): return {}

    def heartbeat_loop(self):
        while True:
            try:
                payload = {"device_id": self.device, "status": "PLAYING" if self.queue else "IDLE", "stats": self.get_stats(), "queue": len(self.queue)}
                if self.hb_url: self.http.post(self.hb_url, json=payload, timeout=5)
            except: pass
            time.sleep(60)

    def fire_delayed(self, delay, urls, label):
        def t():
            for u in urls: 
                try: self.http.get(replace_macros(u,0,0), headers={"User-Agent":"Flawk"}, timeout=5)
                except: pass
        if delay<=0: t()
        else: threading.Timer(delay, t).start()

    def fill_once(self):
        try:
            url = f"{self.api}?device_id={self.device}&api_key={self.api_key}"
            r = self.http.get(url, headers=API_HEADERS, timeout=10)
            if r.status_code==204 or not r.content: return False
            vast_data = parse_vast_recursive(r.content, self.http)
            if not vast_data or not vast_data["media_url"]: vast_data = parse_legacy_fallback(r.text)
            if not vast_data or not vast_data["media_url"]: return False
            media_url = vast_data["media_url"]
            dur = vast_data["duration"]
            local = download_if_needed(media_url, self.cache, self.http, self.log)
            self.queue.append({"src": media_url, "path": local, "dur": dur, "imps": vast_data["impressions"], "trk": vast_data["trackers"]})
            self.log.info(f"Queued: {media_url[-20:]} (Dur: {dur}s)")
            return True
        except Exception as e: 
            self.log.err(f"Fill Error: {e}")
            return False

    def play_queue(self):
        if not self.queue: return 0
        items = list(self.queue); self.queue.clear()
        paths = []
        total_sec = 0
        for ad in items:
            total_sec += ad['dur']
            if os.path.exists(ad['path']):
                Path(ad['path']).touch()
                paths.append(ad['path'])
            else:
                paths.append(ad['src'])
        
        offset = 0
        for ad in items:
            if ad['imps']: self.fire_delayed(offset, ad['imps'], "imp")
            offset += ad['dur']

        subprocess.run(["pkill", "-9", "-f", "mpv --fs"], stdout=subprocess.DEVNULL)
        
        # [MPV FIX] Verbose Logging to TMP + Force Window
        # Note: --msg-level=vo=debug will write video driver logs
        cmd = ["mpv", "--fs", "--no-border", "--really-quiet", 
               "--ontop", "--force-window=immediate", "--keep-open=no",
               "--geometry=100%x100%", "--autofit=100%",
               "--input-default-bindings=no", "--input-vo-keyboard=no", 
               "--cursor-autohide=always", "--osc=no",
               "--msg-level=all=warn,vo=debug",
               f"--log-file=/tmp/mpv_debug.log"]

        # Only ONE definition of VO
        if os.environ.get("DISPLAY"):
             cmd.extend(["--vo=gpu", "--gpu-context=x11"])
        else:
             cmd.extend(["--vo=gpu", "--gpu-context=drm"])
        
        if not self.cfg.get("play_sound", True): cmd.append("--mute=yes")
        cmd = cmd + paths
        
        env = os.environ.copy()
        if os.environ.get("DISPLAY"): env["DISPLAY"] = os.environ.get("DISPLAY")
        
        self.log.info(f"Playing CMD: {' '.join(cmd)}") # [LOGGING] Log exact command

        try:
            # [LOGGING] Capture Stderr to see crash reason
            result = subprocess.run(cmd, env=env, check=False, timeout=total_sec + MPV_TIMEOUT_BUFFER, stderr=subprocess.PIPE, text=True)
            
            if result.returncode != 0:
                self.log.err(f"MPV Exited with {result.returncode}")
                if result.stderr: self.log.err(f"MPV STDERR: {result.stderr[:200]}") # Log first 200 chars of error
                
        except subprocess.TimeoutExpired:
            self.log.err(f"MPV Freeze detected.")
            subprocess.run(["pkill", "-9", "-f", "mpv --fs"], stdout=subprocess.DEVNULL)
        return len(items)

    def run(self):
        self.log.info(f"Runner Start v0.1.1. ID={self.device}")
        time.sleep(5)
        while True:
            while len(self.queue) < self.cfg.get("queue_max",5):
                if not self.fill_once(): break
                time.sleep(1)
            if self.queue:
                played = self.play_queue()
                time.sleep(self.cfg.get("per_ad_cooldown_secs", 30) * played)
            else:
                time.sleep(self.cfg.get("poll_interval_secs", 10))

if __name__=="__main__":
    _lock = acquire_singleton_lock(LOCK_PATH)
    Runner("/opt/ad-runner/config.json").run()
PY

# ==============================================================================
# [11] SUPERVISOR (ROBUST XAUTH)
# ==============================================================================
echo "== Phase 7: Installing Supervisor =="
sudo -u "$RUN_USER" tee "$INSTALL_DIR/supervisor.sh" >/dev/null <<'BASH'
#!/bin/bash
APP_DIR="/opt/ad-runner"
VENV="$APP_DIR/.venv"

# [FIX] ADVANCED XAUTH DETECTION
export DISPLAY=:0
# 1. Try process list for running Xorg/Xwayland auth file
XAUTH=$(ps aux | grep -o '\-auth [^ ]*' | head -n 1 | cut -d' ' -f2)
if [ -n "$XAUTH" ] && [ -r "$XAUTH" ]; then
    export XAUTHORITY="$XAUTH"
elif [ -f "/home/$(whoami)/.Xauthority" ]; then
    export XAUTHORITY="/home/$(whoami)/.Xauthority"
fi

pkill -9 -u "$(whoami)" -f "mpv --fs" || true
chmod -R 755 "$APP_DIR/cache" 2>/dev/null || true
exec "$VENV/bin/python3" "$APP_DIR/ad_runner.py"
BASH
sudo chmod +x "$INSTALL_DIR/supervisor.sh"

# ==============================================================================
# [12] FINAL LINKING & SYSTEMD
# ==============================================================================
echo "== Phase 8: Finalizing =="
ln -sf "$DATA_DIR/config.json" "$INSTALL_DIR/config.json"
ln -sf "$DATA_DIR/cache" "$INSTALL_DIR/cache"
ln -sf "$DATA_DIR/logs" "$INSTALL_DIR/logs"
echo "$CURRENT_VER" > "$INSTALL_DIR/version.txt"

ln -sfn "$INSTALL_DIR" "$BASE_DIR/current"
ln -sfn "$BASE_DIR/current" "$LEGACY_APP_DIR"

tee /etc/systemd/system/ad-runner.service >/dev/null <<UNIT
[Unit]
Description=Flawk Ad Runner (Production v0.1.1)
After=network-online.target sound.target graphical-session.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_GROUP
WorkingDirectory=$LEGACY_APP_DIR
ExecStart=/bin/bash supervisor.sh
Restart=always
RestartSec=5
StartLimitBurst=10
Environment=DISPLAY=:0
Environment=XDG_RUNTIME_DIR=/run/user/$RUN_UID
StandardOutput=append:$LOG_DIR/service.log
StandardError=inherit

[Install]
WantedBy=multi-user.target
UNIT

ensure_user_bus "$RUN_USER"
systemctl daemon-reload
systemctl enable --now ad-runner.service

echo
echo "=========================================="
echo "    FLAWK AD RUNNER
