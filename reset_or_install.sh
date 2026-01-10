#!/usr/bin/env bash
# ==============================================================================
# FLAWK AD RUNNER - MASTER PRODUCTION INSTALLER (v0.0.14)
#
# RELEASE NOTES:
# - PERFORMANCE: "Lean MPV". Removed heavy flags (prefetch, huge buffers,
#   forced geometry) that were causing stutter on Pi 3/4.
# - OPTIMIZATION: Added '--x11-bypass-compositor=yes' to disable GUI effects
#   during playback.
# - INCLUDES: RAM Playback, Priority Boost, Safe Mode, Updater.
# ==============================================================================

# Strict Mode
set -eu

# ==============================================================================
# [1] INSTALLER LOGGING
# ==============================================================================
LOG_DIR="/var/log/ad-runner"
if [ ! -d "$LOG_DIR" ]; then mkdir -p "$LOG_DIR"; chmod 777 "$LOG_DIR"; fi

INSTALL_LOG="$LOG_DIR/install.log"
touch "$INSTALL_LOG" >/dev/null 2>&1 || true
chmod 0666 "$INSTALL_LOG" >/dev/null 2>&1 || true
exec > >(tee -a "$INSTALL_LOG") 2>&1

echo "=== [$(date)] Starting v0.0.14 (Lean MPV) Installation ==="

if [ ! -t 0 ] && [ -r /dev/tty ]; then exec </dev/tty; fi

# ==============================================================================
# [2] CONSTANTS
# ==============================================================================
BASE_DIR="/opt/flawk"
DATA_DIR="$BASE_DIR/data"
VERSIONS_DIR="$BASE_DIR/versions"
CURRENT_VER="v0.0.14"
INSTALL_DIR="$VERSIONS_DIR/$CURRENT_VER"
LEGACY_APP_DIR="/opt/ad-runner"

# API Config
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
  read -rp "Enter desktop username (e.g., pi): " u
  [ -z "$u" ] && die "Username required."
  echo "$u"
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
# [5] THE "NUKE" PHASE
# ==============================================================================
echo "== Phase 1: Cleaning System =="

BACKUP_CONF="/tmp/flawk_config.bak"
if [ -f "$DATA_DIR/config.json" ]; then cp "$DATA_DIR/config.json" "$BACKUP_CONF"
elif [ -f "$LEGACY_APP_DIR/config.json" ]; then cp "$LEGACY_APP_DIR/config.json" "$BACKUP_CONF"; fi

systemctl stop ad-runner.service 2>/dev/null || true
systemctl disable ad-runner.service 2>/dev/null || true
rm -f /etc/systemd/system/ad-runner.service

if sudo -u "$RUN_USER" XDG_RUNTIME_DIR="/run/user/$RUN_UID" systemctl --user is-active ad-runner.service >/dev/null 2>&1; then
    sudo -u "$RUN_USER" XDG_RUNTIME_DIR="/run/user/$RUN_UID" systemctl --user stop ad-runner.service
    sudo -u "$RUN_USER" XDG_RUNTIME_DIR="/run/user/$RUN_UID" systemctl --user disable ad-runner.service
fi
rm -f "/home/$RUN_USER/.config/systemd/user/ad-runner.service"

systemctl daemon-reload

pkill -9 -f "ad_runner.py" 2>/dev/null || true
pkill -9 -f "mpv --fs" 2>/dev/null || true

rm -rf "$LEGACY_APP_DIR"
rm -rf "$VERSIONS_DIR"
rm -f "$BASE_DIR/current"

# ==============================================================================
# [6] DEPENDENCIES (Safe Mode)
# ==============================================================================
echo "== Phase 2: Dependencies (Safe Mode) =="
apt-get install -y mpv python3 python3-venv python3-pip curl ca-certificates jq pulseaudio-utils logrotate coreutils || true

# ==============================================================================
# [7] ARCHITECTURE SETUP
# ==============================================================================
echo "== Phase 3: Creating Architecture =="
mkdir -p "$DATA_DIR/cache" "$DATA_DIR/logs" "$INSTALL_DIR"

if [ -f "$BACKUP_CONF" ]; then
    mv "$BACKUP_CONF" "$DATA_DIR/config.json"
    echo "   Config restored."
fi

chown -R "$RUN_USER:$RUN_GROUP" "$BASE_DIR" "$LOG_DIR"
chmod -R 755 "$BASE_DIR" "$LOG_DIR"

# ==============================================================================
# [8] CONFIGURATION
# ==============================================================================
CONF_FILE="$DATA_DIR/config.json"

if [ -f "$CONF_FILE" ]; then
    echo "== Phase 4: Existing Config Found =="
    DEVICE_ID=$(jq -r .device_id "$CONF_FILE" 2>/dev/null || echo "Unknown")
else
    echo "== Phase 4: New Configuration Required =="
    if [ -t 0 ]; then read -rp "Device ID (required): " DEVICE_ID; else read -rp "Device ID (required): " DEVICE_ID < /dev/tty; fi
    [ -z "$DEVICE_ID" ] && die "Device ID is required."

    PLAY_SOUND=true
    while :; do
      if [ -t 0 ]; then read -rp "Play ads with sound? [Y/n]: " SOUND_ANS; else read -rp "Play ads with sound? [Y/n]: " SOUND_ANS < /dev/tty; fi
      SOUND_ANS="${SOUND_ANS:-Y}"
      case "$SOUND_ANS" in y|Y) PLAY_SOUND=true; break ;; n|N) PLAY_SOUND=false; break ;; *) echo "Please answer Y or N." ;; esac
    done

    sudo -u "$RUN_USER" tee "$CONF_FILE" >/dev/null <<JSON
{
  "device_id": "$DEVICE_ID",
  "api_url": "$API_URL",
  "api_key": "$DEFAULT_API_KEY",
  "heartbeat_url": "$HEARTBEAT_URL",
  "manifest_url": "$MANIFEST_URL",
  "width": 1920,
  "height": 1080,
  "poll_interval_secs": 10,
  "fill_window_secs": 30,
  "queue_max": 5,
  "per_ad_cooldown_secs": 30,
  "initial_start_delay_secs": 30,
  "cache_dir": "$DATA_DIR/cache",
  "log_file": "$DATA_DIR/logs/ad_runner.log",
  "play_sound": $PLAY_SOUND,
  "duck_other_audio": true,
  "force_ipv4": true
}
JSON
fi

# ==============================================================================
# [9] PYTHON ENVIRONMENT
# ==============================================================================
echo "== Phase 5: Python Setup =="
sudo -u "$RUN_USER" python3 -m venv "$INSTALL_DIR/.venv"
sudo -u "$RUN_USER" "$INSTALL_DIR/.venv/bin/pip" install --upgrade pip requests urllib3

# ==============================================================================
# [10] APPLICATION CODE
# ==============================================================================
echo "== Phase 6: Installing App Logic (v0.0.14) =="

sudo -u "$RUN_USER" tee "$INSTALL_DIR/ad_runner.py" >/dev/null <<'PY'
#!/usr/bin/env python3
import os, sys, time, json, random, hashlib, threading, subprocess, logging, logging.handlers, fcntl, re, socket, shutil
import concurrent.futures
import urllib.parse as up
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import connection, Retry
from xml.etree import ElementTree as ET

LOCK_PATH = "/opt/ad-runner/ad_runner.lock"
HEADERS = {"User-Agent":"FlawkAdRunner/0.0.14 (Linux; Production)","Accept":"application/xml,text/xml,*/*"}
MPV_TIMEOUT_BUFFER = 60
RAM_DISK_PATH = "/dev/shm" 

class IPv4HTTPAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        fam = socket.AF_INET; orig = connection.allowed_gai_family
        connection.allowed_gai_family = lambda: fam
        try: super().init_poolmanager(*args, **kwargs)
        finally: connection.allowed_gai_family = orig

def make_session(force_ipv4):
    s = requests.Session()
    retries = Retry(total=3, connect=3, read=3, backoff_factor=0.5, status_forcelist=[429,500,502,503,504])
    adapter = IPv4HTTPAdapter(max_retries=retries) if force_ipv4 else HTTPAdapter(max_retries=retries)
    s.mount("http://", adapter); s.mount("https://", adapter)
    s.headers.update(HEADERS)
    return s

def acquire_singleton_lock(lock_path):
    Path(os.path.dirname(lock_path)).mkdir(parents=True, exist_ok=True)
    fp = open(lock_path, "a+")
    try: fcntl.flock(fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: 
        print("Ad Runner is already running (Locked). Exiting with code 1.")
        sys.exit(1)
    return fp

def ensure_dir(p): Path(p).mkdir(parents=True, exist_ok=True)
def sha256_hex(s): return hashlib.sha256(s.encode("utf-8")).hexdigest()

def parse_duration(t:str)->int:
    if not t: return 0
    s=str(t).strip()
    if ":" not in s:
        try: return int(float(s))
        except: return 0
    try:
        colons = s.count(':')
        if colons == 3: parts = s.rsplit(':', 1); s = f"{parts[0]}.{parts[1]}"
        elif ',' in s: s = s.replace(',', '.')
        if '.' in s:
            main, ms = s.split('.'); hh, mm, ss = main.split(':')
            return int(hh)*3600 + int(mm)*60 + int(ss)
        else:
            hh, mm, ss = s.split(':')
            return int(hh)*3600 + int(mm)*60 + int(ss)
    except Exception:
        try:
            parts = s.replace(':', ' ').split()
            if len(parts) >= 3:
                return int(parts[0])*3600 + int(parts[1])*60 + int(parts[2])
        except: pass
        return 15

def replace_macros(url, duration, playhead):
    ts=int(time.time()); cb=str(random.randint(10000000,99999999))
    hh=playhead//3600; mm=(playhead%3600)//60; ss=playhead%60
    ph=f"{hh:02d}:{mm:02d}:{ss:02d}.000"
    return (url.replace("[TIMESTAMP]",str(ts)).replace("[CACHEBUSTING]",cb).replace("[CONTENTPLAYHEAD]",ph))

def _strip_ns(tag):
    if '}' in tag: return tag.split('}', 1)[1]
    return tag

def parse_vast_recursive(xml_content, session, depth=0, max_depth=5):
    if depth > max_depth: return None
    result = {"media_url": None, "duration": 15, "impressions": [], "trackers": {"start":[],"firstQuartile":[],"midpoint":[],"thirdQuartile":[],"complete":[]}}
    try: root = ET.fromstring(xml_content)
    except: return None

    ad_node = None
    if _strip_ns(root.tag).upper() == "VAST":
        ad_node = root.find(".//{*}Ad")
        if ad_node is None: ad_node = root.find("Ad")
    else: ad_node = root
    if ad_node is None: return None

    wrapper = ad_node.find(".//{*}Wrapper"); inline = ad_node.find(".//{*}Inline")
    if wrapper is None: wrapper = ad_node.find("Wrapper")
    if inline is None: inline = ad_node.find("Inline")
    active_node = wrapper if wrapper is not None else inline
    if active_node is None: return None

    imps = set() 
    for imp in active_node.findall(".//{*}Impression"):
        if imp.text and imp.text.strip(): imps.add(imp.text.strip())
    for imp in active_node.findall("Impression"):
        if imp.text and imp.text.strip(): imps.add(imp.text.strip())
    result["impressions"] = list(imps)

    for trk in active_node.findall(".//{*}Tracking"):
        evt = trk.get("event")
        url = trk.text.strip() if trk.text else ""
        if evt in result["trackers"] and url and url not in result["trackers"][evt]: 
            result["trackers"][evt].append(url)

    if wrapper is not None:
        tag_uri = wrapper.find(".//{*}VASTAdTagURI")
        if tag_uri is None: tag_uri = wrapper.find("VASTAdTagURI")
        if tag_uri is not None and tag_uri.text:
            try:
                r = session.get(tag_uri.text.strip(), timeout=5)
                if r.ok:
                    child = parse_vast_recursive(r.content, session, depth+1, max_depth)
                    if child:
                        result["media_url"] = child["media_url"]
                        result["duration"] = child["duration"]
                        result["impressions"] = list(set(result["impressions"] + child["impressions"]))
                        for k in result["trackers"]: 
                            result["trackers"][k] = list(set(result["trackers"][k] + child["trackers"][k]))
            except: pass
    elif inline is not None:
        candidates = []
        for mf in inline.findall(".//{*}MediaFile"):
            u = mf.text.strip() if mf.text else ""
            if not u: continue
            typ = mf.get("type", "").lower()
            if "mp4" not in typ and not u.endswith(".mp4"): continue
            w_str, h_str = mf.get("width"), mf.get("height")
            try: w = int(w_str) if w_str else 0; h = int(h_str) if h_str else 0
            except: w, h = 0, 0
            candidates.append({"url": u, "w": w, "h": h})

        if not candidates:
            m = re.search(r'MediaFile.*?><!\[CDATA\[(.*?)\]\]>', xml_content.decode('utf-8', 'ignore'), re.S)
            if m: result["media_url"] = m.group(1).strip()
        elif len(candidates) == 1:
            result["media_url"] = candidates[0]["url"]
        else:
            def score_fn(c):
                h = c["h"]
                if h <= 0: return 999999
                # Priority: 720p or 480p (Safe for CPU)
                return min(abs(h - 720), abs(h - 480))
            candidates.sort(key=score_fn)
            result["media_url"] = candidates[0]["url"]

        dn = inline.find(".//{*}Duration")
        if dn is not None and dn.text: result["duration"] = parse_duration(dn.text)
    return result

def parse_legacy_fallback(txt):
    media = re.search(r'MediaFile.*?><!\[CDATA\[(.*?)\]\]>', txt, re.S)
    if not media: media = re.search(r'MediaFile.*?>(http.*?)<', txt, re.S)
    if not media: return None
    dur_m = re.search(r'<Duration>(.*?)</Duration>', txt)
    dur = parse_duration(dur_m.group(1)) if dur_m else 15
    return {
        "media_url": media.group(1).strip(),
        "duration": dur,
        "impressions": list(set(re.findall(r'<Impression.*?><!\[CDATA\[(.*?)\]\]>', txt, re.S))),
        "trackers": {}
    }

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

def enforce_cache_budget(cache_dir, max_mb=1500, max_age_days=30, log=None):
    try:
        p = Path(cache_dir)
        if not p.exists(): return
        files = [f for f in p.glob("*") if f.is_file()]
        now = time.time()
        if max_age_days > 0:
            for f in files:
                if (now - f.stat().st_mtime) > (max_age_days * 86400): f.unlink(missing_ok=True)
        files = [f for f in p.glob("*") if f.is_file()]
        total = sum((f.stat().st_size for f in files), 0)
        limit = max_mb * 1024 * 1024
        if total > limit:
            files.sort(key=lambda f: f.stat().st_mtime)
            for f in files:
                total -= f.stat().st_size; f.unlink(missing_ok=True)
                if total <= limit: break
    except: pass

def duck_others(mute=True, snapshot=None):
    try: subprocess.run(["which", "pactl"], check=True, stdout=subprocess.DEVNULL)
    except: return [] if mute else None
    try:
        if mute:
            out = subprocess.check_output(["pactl", "list", "sink-inputs", "short"], text=True, timeout=0.5)
            ids = [l.split()[0] for l in out.splitlines() if l.strip() and l.split()[0].isdigit()]
            for sid in ids:
                subprocess.run(["pactl", "set-sink-input-mute", sid, "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.2)
            return ids
        elif snapshot:
            for sid in snapshot:
                subprocess.run(["pactl", "set-sink-input-mute", sid, "0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.2)
    except: pass

def download_if_needed(url, cache_dir, session):
    enforce_cache_budget(cache_dir)
    ensure_dir(cache_dir)
    ext = os.path.splitext(up.urlparse(url).path)[1] or ".mp4"
    path = os.path.join(cache_dir, sha256_hex(url)+ext)
    if os.path.exists(path) and os.path.getsize(path)>0: return path
    try:
        r = session.get(url, timeout=60, stream=True)
        if not r.ok: return url
        with open(path,"wb") as f:
            for chunk in r.iter_content(8192):
                if chunk: f.write(chunk)
        return path
    except: return url

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
        enforce_cache_budget(self.cache, log=self.log)
        
        self.queue = []
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=6)
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()

    def get_stats(self):
        s = {"uptime":0,"cpu":0,"disk":0}
        try:
            with open('/proc/uptime','r') as f: s["uptime"]=int(float(f.read().split()[0]))
            with open('/proc/loadavg','r') as f: s["cpu"]=float(f.read().split()[0])
            st = os.statvfs(self.cache)
            s["disk"] = int((st.f_bavail * st.f_frsize)/1024/1024)
        except: pass
        return s

    def heartbeat_loop(self):
        while True:
            try:
                payload = {"device_id": self.device, "status": "PLAYING" if self.queue else "IDLE", "stats": self.get_stats(), "queue": len(self.queue)}
                if self.hb_url:
                    r = self.http.post(self.hb_url, json=payload, timeout=5)
                    if r.ok:
                        cmd = r.json().get("command")
                        if cmd == "REBOOT": subprocess.run(["sudo", "reboot"])
                        if cmd == "UPDATE": subprocess.Popen(["/bin/bash", "/opt/flawk/updater.sh", "--force"])
            except: pass
            time.sleep(60)

    def req_url(self):
        return f"{self.api}?device_id={self.device}&api_key={self.api_key}"

    def _net_task(self, url, label):
        try:
            r = self.http.get(url, timeout=5)
            if 200<=r.status_code<400: self.log.info(f"Trk {label} -> {r.status_code}")
        except: pass

    def fire_delayed(self, delay, urls, label):
        def t():
            for u in urls: self.executor.submit(self._net_task, replace_macros(u,0,0), label)
        if delay<=0: t()
        else: threading.Timer(delay, t).start()

    def fill_once(self):
        try:
            r = self.http.get(self.req_url(), timeout=10)
            if r.status_code==204 or not r.content: return False
            
            vast_data = parse_vast_recursive(r.content, self.http)
            
            if not vast_data or not vast_data["media_url"]:
                self.log.warn("Smart Parse failed. Trying Legacy...")
                vast_data = parse_legacy_fallback(r.text)
                
            if not vast_data or not vast_data["media_url"]:
                self.log.warn("VAST Parse failed (No Media Found).")
                return False
            
            media_url = vast_data["media_url"]
            local = download_if_needed(media_url, self.cache, self.http)
            dur = vast_data["duration"]
            
            self.queue.append({
                "src": media_url, 
                "path": local, 
                "dur": dur, 
                "imps": vast_data["impressions"], 
                "trk": vast_data["trackers"]
            })
            self.log.info(f"Queued: {media_url[-20:]} (Dur: {dur}s)")
            return True
        except Exception as e: 
            self.log.err(f"Fill Error: {e}")
            return False

    def play_queue(self):
        if not self.queue: return 0
        items = list(self.queue); self.queue.clear()
        paths = []
        ram_files = [] 
        
        total_sec = 0
        
        # --- RAM PLAYBACK: Copy to /dev/shm ---
        for ad in items:
            total_sec += ad['dur']
            src_path = ad['path'] if os.path.exists(ad['path']) else None
            if src_path:
                Path(src_path).touch()
                base = os.path.basename(src_path)
                ram_path = os.path.join(RAM_DISK_PATH, f"flawk_{base}")
                try:
                    shutil.copyfile(src_path, ram_path)
                    paths.append(ram_path)
                    ram_files.append(ram_path)
                except:
                    paths.append(src_path)
            else:
                paths.append(ad['src'])
        
        offset = 0
        for ad in items:
            if ad['imps']: self.fire_delayed(offset, ad['imps'], "imp")
            if 'trk' in ad and ad['trk']:
                evs=[("start",0),("firstQuartile",ad['dur']//4),("midpoint",ad['dur']//2),
                     ("thirdQuartile",(ad['dur']*3)//4),("complete",max(0,ad['dur']-1))]
                for name, tsec in evs:
                    if name in ad['trk']: self.fire_delayed(offset+tsec, ad['trk'][name], name)
            offset += ad['dur']

        is_muted = not self.cfg.get("play_sound", True)
        snap = duck_others(True) if (not is_muted and self.cfg.get("duck_other_audio")) else None
        
        subprocess.run(["pkill", "-9", "-f", "mpv --fs"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # --- LEAN MPV COMMAND (NO FLUFF) ---
        cmd = ["mpv", "--fs", "--no-border", "--really-quiet", 
               "--ontop", "--keep-open=no",
               "--input-default-bindings=no", "--input-vo-keyboard=no", 
               "--cursor-autohide=always", "--osc=no", 
               "--x11-bypass-compositor=yes",
               # FAST DECODING FOR CPU
               "--vd-lavc-skiploopfilter=all",
               "--vd-lavc-fast",
               "--framedrop=vo",
               f"--log-file=/var/log/ad-runner/mpv_player.log"]
        
        if is_muted: cmd.append("--mute=yes")
        cmd = cmd + paths
        
        env = os.environ.copy(); env["DISPLAY"] = env.get("DISPLAY", ":0")
        
        TIMEOUT_VAL = total_sec + MPV_TIMEOUT_BUFFER
        self.log.info(f"Playing Batch (RAM + Lean). Total: {total_sec}s.")

        try:
            subprocess.run(cmd, env=env, check=False, timeout=TIMEOUT_VAL)
        except subprocess.TimeoutExpired:
            self.log.err(f"MPV Freeze detected. Killing.")
            subprocess.run(["pkill", "-9", "-f", "mpv --fs"], stdout=subprocess.DEVNULL)
        
        if snap: duck_others(False, snap)
        
        for rf in ram_files:
            try: os.remove(rf)
            except: pass
            
        return len(items)

    def run(self):
        self.log.info(f"Runner Start v0.0.14. ID={self.device}")
        time.sleep(self.cfg.get("initial_start_delay_secs", 10))
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
# [11] SUPERVISOR
# ==============================================================================
echo "== Phase 7: Installing Supervisor =="
sudo -u "$RUN_USER" tee "$INSTALL_DIR/supervisor.sh" >/dev/null <<'BASH'
#!/bin/bash
APP_DIR="/opt/ad-runner"
VENV="$APP_DIR/.venv"
# NO LOCK REMOVAL
pkill -9 -u "$(whoami)" -f "mpv --fs" || true
usage=$(df "$APP_DIR" | awk 'NR==2 {print $5}' | tr -d '%')
if [ "$usage" -gt 90 ]; then rm -rf "$APP_DIR/cache/"*; fi
exec "$VENV/bin/python3" "$APP_DIR/ad_runner.py"
BASH
sudo chmod +x "$INSTALL_DIR/supervisor.sh"

# ==============================================================================
# [12] UPDATER ENGINE
# ==============================================================================
echo "== Phase 8: Installing Updater =="

sudo -u "$RUN_USER" tee "$BASE_DIR/updater.sh" >/dev/null <<'BASH'
#!/bin/bash
set -u

BASE_DIR="/opt/flawk"
DATA_DIR="$BASE_DIR/data"
VERSIONS_DIR="$BASE_DIR/versions"
CURRENT_LINK="$BASE_DIR/current"
LOG_FILE="$DATA_DIR/logs/updater.log"
CONFIG_FILE="$DATA_DIR/config.json"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [UPDATER] $1" >> "$LOG_FILE"; }

if [ ! -f "$CONFIG_FILE" ]; then exit 1; fi
DEVICE_ID=$(jq -r .device_id "$CONFIG_FILE")
MANIFEST_URL=$(jq -r .manifest_url "$CONFIG_FILE")
if [ -z "$DEVICE_ID" ] || [ "$DEVICE_ID" == "null" ]; then exit 1; fi

if [ "${1:-}" != "--force" ]; then
    SLEEP_SEC=$((RANDOM % 1800))
    sleep $SLEEP_SEC
fi

HTTP_CODE=$(curl -s -w "%{http_code}" -o /tmp/manifest_temp.json --max-time 15 "$MANIFEST_URL")
if [ "$HTTP_CODE" != "200" ]; then exit 0; fi
if ! jq -e . /tmp/manifest_temp.json >/dev/null 2>&1; then exit 0; fi
JSON=$(cat /tmp/manifest_temp.json)

TARGET_VER=$(echo "$JSON" | jq -r .stable.version)
URL=$(echo "$JSON" | jq -r .stable.url)
SUM=$(echo "$JSON" | jq -r .stable.shasum)
ROLLOUT=$(echo "$JSON" | jq -r .stable.rollout_percent)

IS_BETA=$(echo "$JSON" | jq -r --arg id "$DEVICE_ID" '.beta.devices[] | select(. == $id)')
if [ -n "$IS_BETA" ]; then
    TARGET_VER=$(echo "$JSON" | jq -r .beta.version)
    URL=$(echo "$JSON" | jq -r .beta.url)
    SUM=$(echo "$JSON" | jq -r .beta.shasum)
    ROLLOUT=100
fi

HASH_NUM=$(echo -n "$DEVICE_ID" | cksum | awk '{print $1 % 100}')
if [ "$ROLLOUT" != "100" ] && [ "$HASH_NUM" -ge "$ROLLOUT" ]; then exit 0; fi

CURRENT_VER="unknown"
if [ -f "$CURRENT_LINK/version.txt" ]; then CURRENT_VER=$(cat "$CURRENT_LINK/version.txt"); fi
if [ "$CURRENT_VER" == "$TARGET_VER" ]; then exit 0; fi

log "Update: $CURRENT_VER -> $TARGET_VER"

NEW_DIR="$VERSIONS_DIR/$TARGET_VER"
if [ -d "$NEW_DIR" ]; then rm -rf "$NEW_DIR"; fi
mkdir -p "$NEW_DIR"

TMP_FILE="/tmp/update_$TARGET_VER.tar.gz"
if ! curl -L -s -o "$TMP_FILE" "$URL"; then log "Download failed."; exit 1; fi

CALC_SUM=$(sha256sum "$TMP_FILE" | awk '{print $1}')
if [ "$CALC_SUM" != "$SUM" ]; then log "Checksum mismatch!"; rm -f "$TMP_FILE"; exit 1; fi

tar -xzf "$TMP_FILE" -C "$NEW_DIR"
rm -f "$TMP_FILE"
echo "$TARGET_VER" > "$NEW_DIR/version.txt"

ln -sf "$DATA_DIR/config.json" "$NEW_DIR/config.json"
ln -sf "$DATA_DIR/cache" "$NEW_DIR/cache"
ln -sf "$DATA_DIR/logs" "$NEW_DIR/logs"

python3 -m venv "$NEW_DIR/.venv"
if [ -f "$NEW_DIR/requirements.txt" ]; then
    "$NEW_DIR/.venv/bin/pip" install -r "$NEW_DIR/requirements.txt" --quiet
fi

OWNER=$(stat -c '%U' "$CONFIG_FILE")
chown -R "$OWNER:$OWNER" "$NEW_DIR"

ln -sfn "$NEW_DIR" "$BASE_DIR/next"
mv -Tf "$BASE_DIR/next" "$CURRENT_LINK"

log "Restarting service..."
systemctl restart ad-runner.service
sleep 20

if systemctl is-active --quiet ad-runner.service; then
    log "Update SUCCESS."
else
    log "CRITICAL: Service crashed. Rolling back."
    PREV_DIR=$(ls -dt "$VERSIONS_DIR"/*/ | head -n 2 | tail -n 1)
    if [ -n "$PREV_DIR" ]; then
        ln -sfn "$PREV_DIR" "$BASE_DIR/rollback_link"
        mv -Tf "$BASE_DIR/rollback_link" "$CURRENT_LINK"
        systemctl restart ad-runner.service
        log "Rollback done."
    fi
    exit 1
fi

ls -dt "$VERSIONS_DIR"/*/ | tail -n +3 | xargs rm -rf 2>/dev/null || true
BASH
sudo chmod +x "$BASE_DIR/updater.sh"

(crontab -l 2>/dev/null; echo "0 3 * * * /bin/bash /opt/flawk/updater.sh") | crontab -

# ==============================================================================
# [13] FINAL LINKING & SYSTEMD
# ==============================================================================
echo "== Phase 9: Linking & Services =="
ln -sf "$DATA_DIR/config.json" "$INSTALL_DIR/config.json"
ln -sf "$DATA_DIR/cache" "$INSTALL_DIR/cache"
ln -sf "$DATA_DIR/logs" "$INSTALL_DIR/logs"
echo "$CURRENT_VER" > "$INSTALL_DIR/version.txt"

ln -sfn "$INSTALL_DIR" "$BASE_DIR/current"
ln -sfn "$BASE_DIR/current" "$LEGACY_APP_DIR"

tee /etc/systemd/system/ad-runner.service >/dev/null <<UNIT
[Unit]
Description=Flawk Ad Runner (Production v0.0.14)
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
StartLimitIntervalSec=60
MemoryMax=768M
CPUWeight=50
# PRIORITY
Nice=-15
IOSchedulingClass=realtime
IOSchedulingPriority=2
Environment=DISPLAY=:0
Environment=XDG_RUNTIME_DIR=/run/user/$RUN_UID
StandardOutput=append:$LOG_DIR/service.log
StandardError=inherit

[Install]
WantedBy=multi-user.target
UNIT

tee /etc/logrotate.d/flawk-ad-runner >/dev/null <<ROT
$LOG_DIR/*.log $DATA_DIR/logs/*.log {
    size 10M
    rotate 5
    compress
    missingok
    notifempty
    create 0644 $RUN_USER $RUN_GROUP
}
ROT

# ==============================================================================
# [14] FINALIZE
# ==============================================================================
echo "== Phase 10: Launching =="
ensure_user_bus "$RUN_USER"
systemctl daemon-reload
systemctl enable --now ad-runner.service

echo
echo "=========================================="
echo "   FLAWK AD RUNNER INSTALLED (v0.0.14)"
echo "   - Lean MPV: ACTIVE (No bloat flags)"
echo "   - Compositor Bypass: ON"
echo "=========================================="
echo " Device ID: $DEVICE_ID"
echo " Status:    systemctl status ad-runner"
echo " Logs:      tail -f $DATA_DIR/logs/ad_runner.log"
echo "=========================================="
