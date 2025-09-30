#!/usr/bin/env bash
set -euo pipefail

# ===== Install log (capture all output and errors) =====
INSTALL_LOG="/var/log/ad_runner_install.log"
sudo touch "$INSTALL_LOG" >/dev/null 2>&1 || true
sudo chmod 0666 "$INSTALL_LOG" >/dev/null 2>&1 || true
# Redirect all stdout+stderr to the install log (and to the terminal)
exec > >(tee -a "$INSTALL_LOG") 2>&1

# Ensure prompts work even when piped (curl | bash)
if [ ! -t 0 ] && [ -r /dev/tty ]; then
  exec </dev/tty
fi

# ===== Static paths =====
APP_DIR="/opt/ad-runner"
CACHE_DIR="$APP_DIR/cache"
LOCK_FILE="$APP_DIR/ad_runner.lock"
LOG_FILE="/var/log/ad_runner.log"
MPV_LOG_FILE="/var/log/mpv_player.log"
CONF_JSON="$APP_DIR/config.json"

# ===== Defaults =====
ORG_DEFAULT="golocal"
WIDTH_DEFAULT=1920
HEIGHT_DEFAULT=1080
POLL_INTERVAL=3           # <10s as requested
FILL_WINDOW=30
QUEUE_MAX=3
PER_AD_COOLDOWN_DEFAULT=60
INITIAL_DELAY_DEFAULT=60

# ---------- Detect the real desktop/user ----------
detect_run_user() {
  if [ "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then echo "$SUDO_USER"; return; fi
  if u=$(logname 2>/dev/null) && [ -n "$u" ] && [ "$u" != "root" ]; then echo "$u"; return; fi
  if u=$(who | awk 'NR==1{print $1}'); then if [ -n "$u" ] && [ "$u" != "root" ]; then echo "$u"; return; fi; fi
  if u=$(id -un 2>/dev/null) && [ "$u" != "root" ]; then echo "$u"; return; fi
  read -rp "Enter the desktop username that should run Ad Runner: " u
  [ -z "$u" ] && { echo "A username is required." >&2; exit 1; }
  echo "$u"
}
RUN_USER="$(detect_run_user)"
getent passwd "$RUN_USER" >/dev/null || { echo "User '$RUN_USER' not found." >&2; exit 1; }
USER_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
echo "== Using desktop user: $RUN_USER (home: $USER_HOME) =="

as_user() { sudo -u "$RUN_USER" -H bash -lc "$*"; }

# ---------- Validation helpers ----------
is_float() { [[ "$1" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; }
valid_lat() { is_float "$1" && awk -v v="$1" 'BEGIN{exit (v<-90 || v>90)}'; }
valid_lon() { is_float "$1" && awk -v v="$1" 'BEGIN{exit (v<-180 || v>180)}'; }
valid_int_pos() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ]; }
valid_taxonomy() { [[ "$1" =~ ^[a-z]+([._-][a-z0-9]+)+$ ]]; }  # e.g., retail.malls
trim() { awk '{$1=$1; print}' <<<"$1"; }

# ---------- Make user bus available (prevents 'No Medium found') ----------
ensure_user_bus() {
  local user="$1"
  local uid; uid=$(id -u "$user")
  sudo loginctl enable-linger "$user" >/dev/null 2>&1 || true
  if ! systemctl is-active "user@${uid}.service" >/dev/null 2>&1; then
    sudo systemctl start "user@${uid}.service"
    sleep 1
  fi
  export XDG_RUNTIME_DIR="/run/user/${uid}"
}

# ---------- Clean out old install ----------
echo "== Clean out old install =="
as_user 'systemctl --user stop ad-runner.service 2>/dev/null || true'
as_user 'systemctl --user disable ad-runner.service 2>/dev/null || true'
sudo systemctl stop ad-runner.service 2>/dev/null || true
sudo systemctl disable ad-runner.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/ad-runner.service
sudo systemctl daemon-reload || true

rm -f "$USER_HOME/.config/systemd/user/ad-runner.service" 2>/dev/null || true
rm -f "$USER_HOME/.config/autostart/flawk-ad-runner.desktop" 2>/dev/null || true

pkill -f "$APP_DIR/ad_runner.py" 2>/dev/null || true
pkill -f mpv 2>/dev/null || true

sudo rm -rf "$APP_DIR" /etc/ad_runner.env
sudo rm -f "$LOG_FILE" "$MPV_LOG_FILE" 2>/dev/null || true

# ---------- Dependencies ----------
echo "== Install prerequisites =="
sudo apt-get update -y
sudo apt-get install -y mpv python3 python3-venv python3-pip curl pulseaudio-utils

# ---------- App structure ----------
echo "== Create app structure =="
sudo mkdir -p "$APP_DIR" "$CACHE_DIR"
sudo touch "$LOG_FILE" "$MPV_LOG_FILE"
sudo chown -R "$RUN_USER:$RUN_USER" "$APP_DIR" "$LOG_FILE" "$MPV_LOG_FILE"
sudo chmod -R 0777 "$APP_DIR"
sudo chmod 0666 "$LOG_FILE" "$MPV_LOG_FILE"

# ---------- Prompts ----------
echo "== Prompt for configuration =="

read -rp "Device ID (free-form, required): " DEVICE_ID
[ -z "$DEVICE_ID" ] && { echo "Device ID is required"; exit 1; }

VENUE_NAME=""
while :; do
  read -rp "Venue name (e.g., Mall of Example): " VENUE_NAME
  VENUE_NAME="$(trim "$VENUE_NAME")"
  [ -n "$VENUE_NAME" ] && break || echo "Venue name cannot be empty."
done

echo "Select DOOH venue type:"
VENUE_CHOICES=(
  "retail.malls"
  "retail.grocery"
  "retail.convenience"
  "dining.restaurants"
  "dining.bars"
  "fitness.gyms"
  "travel.airports"
  "travel.transit"
  "hospitality.hotels"
  "education.universities"
  "other (enter manually)"
)
i=1; for v in "${VENUE_CHOICES[@]}"; do printf "  %2d) %s\n" "$i" "$v"; i=$((i+1)); done
VENUE_TYPE=""
while :; do
  read -rp "Choice [1-${#VENUE_CHOICES[@]}, default 4]: " VENUE_CHOICE
  VENUE_CHOICE="${VENUE_CHOICE:-4}"
  if [[ "$VENUE_CHOICE" =~ ^[0-9]+$ ]] && [ "$VENUE_CHOICE" -ge 1 ] && [ "$VENUE_CHOICE" -le ${#VENUE_CHOICES[@]} ]; then
    if [ "$VENUE_CHOICE" -eq ${#VENUE_CHOICES[@]} ]; then
      read -rp "Enter venue type (e.g., retail.malls): " VENUE_TYPE
      VENUE_TYPE="$(trim "$VENUE_TYPE")"
      valid_taxonomy "$VENUE_TYPE" && break || echo "Invalid taxonomy. Use alpha segments with dots, e.g., retail.malls"
    else
      VENUE_TYPE="${VENUE_CHOICES[$((VENUE_CHOICE-1))]}"; break
    fi
  else
    VENUE_TYPE="dining.restaurants"; break
  fi
done

while :; do
  read -rp "Latitude (-90..90): " LAT
  valid_lat "$LAT" && break || echo "Invalid latitude. Must be numeric in range -90..90."
done
while :; do
  read -rp "Longitude (-180..180): " LON
  valid_lon "$LON" && break || echo "Invalid longitude. Must be numeric in range -180..180."
done

PLAY_SOUND=true
while :; do
  read -rp "Play ads with sound? [Y/n]: " SOUND_ANS
  SOUND_ANS="${SOUND_ANS:-Y}"
  case "$SOUND_ANS" in y|Y) PLAY_SOUND=true; break ;; n|N) PLAY_SOUND=false; break ;; *) echo "Please answer Y or N." ;; esac
done

DUCK_OTHERS=true
while :; do
  read -rp "Mute ALL other applications while ads play? [Y/n]: " DUCK_ANS
  DUCK_ANS="${DUCK_ANS:-Y}"
  case "$DUCK_ANS" in y|Y) DUCK_OTHERS=true; break ;; n|N) DUCK_OTHERS=false; break ;; *) echo "Please answer Y or N." ;; esac
done

while :; do
  read -rp "Cooldown per ad in seconds (default ${PER_AD_COOLDOWN_DEFAULT}): " COOLDOWN_PER_AD
  COOLDOWN_PER_AD="${COOLDOWN_PER_AD:-$PER_AD_COOLDOWN_DEFAULT}"
  valid_int_pos "$COOLDOWN_PER_AD" && break || echo "Enter a positive integer."
done

while :; do
  read -rp "Initial startup delay BEFORE first playback (seconds, default ${INITIAL_DELAY_DEFAULT}): " INIT_DELAY
  INIT_DELAY="${INIT_DELAY:-$INITIAL_DELAY_DEFAULT}"
  valid_int_pos "$INIT_DELAY" && break || echo "Enter a positive integer."
done

# ---------- Write config ----------
echo "== Write config.json =="
cat > "$CONF_JSON" <<JSON
{
  "device_id": "$DEVICE_ID",
  "venue_name": "$VENUE_NAME",
  "venue_type": "$VENUE_TYPE",
  "lat": "$(echo "$LAT" | tr -d '[:space:]')",
  "lon": "$(echo "$LON" | tr -d '[:space:]')",
  "organization": "$ORG_DEFAULT",
  "width": ${WIDTH_DEFAULT},
  "height": ${HEIGHT_DEFAULT},
  "poll_interval_secs": ${POLL_INTERVAL},
  "fill_window_secs": ${FILL_WINDOW},
  "queue_max": ${QUEUE_MAX},
  "per_ad_cooldown_secs": ${COOLDOWN_PER_AD},
  "initial_start_delay_secs": ${INIT_DELAY},
  "api_url_base": "https://cms.flawkai.com/api/ads",
  "cache_dir": "$CACHE_DIR",
  "log_file": "$LOG_FILE",
  "play_sound": $PLAY_SOUND,
  "duck_other_audio": $DUCK_OTHERS
}
JSON
sudo chmod 0666 "$CONF_JSON"

# ---------- Python venv ----------
echo "== Create Python venv and install deps =="
sudo -u "$RUN_USER" -H python3 -m venv "$APP_DIR/.venv"
sudo -u "$RUN_USER" -H "$APP_DIR/.venv/bin/pip" install --upgrade pip requests

# ---------- Runner code (with IPv6 support) ----------
echo "== Write ad_runner.py =="
sudo tee "$APP_DIR/ad_runner.py" >/dev/null <<'PY'
#!/usr/bin/env python3
import os, sys, time, json, random, hashlib, threading, subprocess, logging, logging.handlers, fcntl, re
import urllib.parse as up
from pathlib import Path
from xml.etree import ElementTree as ET
import requests

LOCK_PATH = "/opt/ad-runner/ad_runner.lock"

HEADERS = {
    "User-Agent": "FlawkAdRunner/1.0 (Raspberry Pi; Linux; mpv)",
    "Accept": "application/xml,text/xml;q=0.9,*/*;q=0.8",
}
TIMEOUT = 10

def acquire_singleton_lock(lock_path:str):
    Path(os.path.dirname(lock_path)).mkdir(parents=True, exist_ok=True)
    fp = open(lock_path, "a+")
    try: os.chmod(lock_path, 0o666)
    except PermissionError: pass
    try: fcntl.flock(fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("Another ad-runner instance is already running. Exiting.", file=sys.stderr); sys.exit(0)
    return fp

def load_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f: return json.load(f)
    except Exception: return default

def ensure_dir(p:str): Path(p).mkdir(parents=True, exist_ok=True)

def sha256_hex(s:str)->str: return hashlib.sha256(s.encode("utf-8")).hexdigest()

def parse_duration(t:str)->int:
    if t is None: return 0
    s=str(t).strip()
    if not s: return 0
    if ":" not in s:
        try: return int(float(s))
        except: return 0
    try:
        hh,mm,ss = s.split(":"); return int(hh)*3600 + int(mm)*60 + int(float(ss))
    except Exception: return 0

def ext_ip():
    for url in ("https://api.ipify.org","https://ifconfig.me/ip"):
        try:
            r = requests.get(url, timeout=3, headers={"User-Agent": HEADERS["User-Agent"]})
            if r.ok and r.text.strip(): return r.text.strip()
        except Exception: pass
    return None

def ext_ipv6():
    for url in ("https://api64.ipify.org","https://ifconfig.co/ip"):
        try:
            r = requests.get(url, timeout=3, headers={"User-Agent": HEADERS["User-Agent"]})
            if r.ok:
                ip = r.text.strip()
                if ":" in ip: return ip
        except Exception: pass
    return None

def replace_macros(url:str, duration:int, playhead:int)->str:
    ts=int(time.time()); cb=str(random.randint(10000000,99999999))
    hh=playhead//3600; mm=(playhead%3600)//60; ss=playhead%60
    ph=f"{hh:02d}:{mm:02d}:{ss:02d}.000"
    return (url.replace("[TIMESTAMP]",str(ts))
               .replace("[CACHEBUSTING]",cb)
               .replace("[CONTENTPLAYHEAD]",ph))

class Log:
    def __init__(self, logfile:str):
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

def _media_files_from_xml_bytes(xml_bytes):
    media=[]
    try:
        root = ET.fromstring(xml_bytes)
        for mf in root.findall(".//{*}MediaFile"):
            url = (mf.text or "").strip()
            typ = (mf.get("type") or "").strip()
            w = (mf.get("width") or "").strip()
            h = (mf.get("height") or "").strip()
            media.append({"url":url,"type":typ,"width":w,"height":h})
    except Exception:
        pass
    if media: return media
    try:
        txt = xml_bytes.decode("utf-8", errors="ignore")
        pat = re.compile(r"<\s*MediaFile\b([^>]*)>(.*?)</\s*MediaFile\s*>", re.IGNORECASE|re.DOTALL)
        for m in pat.finditer(txt):
            attrs, inner = m.group(1), m.group(2)
            def get_attr(name):
                r = re.search(rf'{name}\s*=\s*"([^"]*)"', attrs, re.IGNORECASE)
                return r.group(1) if r else ""
            url = re.sub(r"^\s*<!\[CDATA\[(.*?)\]\]>\s*$", r"\1", inner.strip(), flags=re.DOTALL)
            media.append({
                "url": url.strip(),
                "type": get_attr("type").strip(),
                "width": get_attr("width").strip(),
                "height": get_attr("height").strip(),
            })
    except Exception:
        pass
    return media

def follow_wrappers(xml_bytes, depth=0, max_depth=4):
    if depth>max_depth: return None
    root=None
    try: root = ET.fromstring(xml_bytes)
    except Exception: pass

    if root is not None:
        tag_uri = root.find(".//{*}VASTAdTagURI")
        if tag_uri is not None and (tag_uri.text or "").strip():
            next_url = (tag_uri.text or "").strip()
            try: child = requests.get(next_url, timeout=TIMEOUT, headers=HEADERS)
            except Exception: return None
            if not child.ok: return None
            inner = follow_wrappers(child.content, depth+1, max_depth)
            wrap_imps = [ (n.text or "").strip() for n in root.findall(".//{*}Impression") if (n.text or "").strip() ]
            if inner: inner["impressions"] = wrap_imps + inner.get("impressions",[])
            return inner

    impressions=[]; trackers={"start":[], "firstQuartile":[], "midpoint":[], "thirdQuartile":[], "complete":[]}; duration=0
    if root is not None:
        impressions = [ (n.text or "").strip() for n in root.findall(".//{*}Impression") if (n.text or "").strip() ]
        for tr in root.findall(".//{*}Tracking"):
            ev=tr.get("event") or ""; url=(tr.text or "").strip()
            if ev in trackers and url: trackers[ev].append(url)
        dur_node = root.find(".//{*}Duration")
        if dur_node is not None and dur_node.text: duration = parse_duration(dur_node.text)
    else:
        txt = xml_bytes.decode("utf-8", errors="ignore")
        for m in re.findall(r"<Impression[^>]*>(.*?)</Impression>", txt, re.IGNORECASE|re.DOTALL):
            impressions.append(re.sub(r"^\s*<!\[CDATA\[(.*?)\]\]>\s*$", r"\1", m.strip(), flags=re.DOTALL))
        md = re.search(r"<Duration[^>]*>(.*?)</Duration>", txt, re.IGNORECASE|re.DOTALL)
        if md: duration = parse_duration(md.group(1).strip())

    media_files = _media_files_from_xml_bytes(xml_bytes)
    return {"impressions":impressions, "trackers":trackers, "duration":duration, "media_files":media_files}

def choose_media(media_files, want_w, want_h):
    def is_playable(mf):
        typ = (mf.get("type") or "").lower()
        url = (mf.get("url") or "").strip().lower()
        if not url: return False
        if "mp4" in typ: return True
        if url.endswith(".mp4") or url.endswith(".m3u8") or url.endswith(".mpd"): return True
        return False
    candidates = [mf for mf in media_files if is_playable(mf)]
    if not candidates: return None
    best=None; best_delta=None
    for mf in candidates:
        try: w=int(mf.get("width") or 0); h=int(mf.get("height") or 0)
        except: w=h=0
        delta = (abs((w or want_w)-want_w)+abs((h or want_h)-want_h)) if (w or h) else 10_000_000
        if best is None or delta<best_delta: best,best_delta=mf,delta
    return best

def download_if_needed(url:str, cache_dir:str)->str:
    ensure_dir(cache_dir)
    ext = os.path.splitext(up.urlparse(url).path)[1] or ".mp4"
    path = os.path.join(cache_dir, sha256_hex(url)+ext)
    if os.path.exists(path) and os.path.getsize(path)>0: return path
    r = requests.get(url, timeout=60, stream=True, headers=HEADERS)
    if not r.ok: return url
    with open(path,"wb") as f:
        for chunk in r.iter_content(1<<20):
            if chunk: f.write(chunk)
    try: os.chmod(path,0o666)
    except PermissionError: pass
    return path

def _pactl_available()->bool:
    from shutil import which
    return which("pactl") is not None

def _pactl_list_sink_inputs():
    try:
        out = subprocess.check_output(["pactl", "list", "sink-inputs", "short"], text=True)
        ids=[]
        for line in out.strip().splitlines():
            if not line.strip(): continue
            sid=line.split()[0]
            if sid.isdigit(): ids.append(sid)
        return ids
    except Exception: return []

def duck_others(mute=True, snapshot=None):
    if not _pactl_available(): return [] if mute else None
    try:
        if mute:
            ids=_pactl_list_sink_inputs()
            for sid in ids: subprocess.run(["pactl","set-sink-input-mute",sid,"1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return ids
        else:
            if not snapshot: return
            for sid in snapshot: subprocess.run(["pactl","set-sink-input-mute",sid,"0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception: pass

class MPV:
    @staticmethod
    def play_list_blocking(paths, mute: bool)->bool:
        if not paths: return True
        base = [
            "mpv","--fs","--no-border","--osc=no","--cursor-autohide=always",
            "--no-terminal","--really-quiet","--msg-level=all=warn",
            f"--log-file=/var/log/mpv_player.log"
        ]
        if mute: base += ["--mute=yes"]
        attempts = [base + list(paths)]
        have_display = bool(os.environ.get("DISPLAY"))
        if have_display:
            attempts += [ base + ["--vo=gpu","--gpu-context=x11"] + list(paths),
                          base + ["--vo=gpu","--gpu-context=wayland"] + list(paths) ]
        else:
            attempts += [ base + ["--vo=gpu","--gpu-context=drm"] + list(paths) ]
        last_rc=None; last_err=""
        for args in attempts:
            proc = subprocess.run(args, capture_output=True, text=True)
            if proc.returncode==0: return True
            last_rc=proc.returncode; last_err=(proc.stderr or "").strip()[:200]
        logging.getLogger("ad-runner").error("mpv failed: %s %s", last_rc, last_err); return False

class Runner:
    def __init__(self, cfg_path:str):
        cfg = load_json(cfg_path, {})
        self.device = (cfg.get("device_id") or "").strip()
        self.venue_name = (cfg.get("venue_name") or "").strip()
        self.venue  = cfg.get("venue_type") or "dining.restaurants"
        self.lat    = (cfg.get("lat") or "").strip()
        self.lon    = (cfg.get("lon") or "").strip()
        if not self.device or not self.lat or not self.lon or not self.venue_name:
            print("Missing device/lat/lon/venue_name in config.json", file=sys.stderr); sys.exit(1)
        self.org    = cfg.get("organization") or "golocal"
        self.w      = int(cfg.get("width") or 1920)
        self.h      = int(cfg.get("height") or 1080)
        self.poll   = int(cfg.get("poll_interval_secs") or 3)
        self.fill   = int(cfg.get("fill_window_secs") or 30)
        self.qmax   = int(cfg.get("queue_max") or 3)
        self.cool_per_ad = int(cfg.get("per_ad_cooldown_secs") or 60)
        self.init_delay = int(cfg.get("initial_start_delay_secs") or 60)
        self.cache  = cfg.get("cache_dir") or "/opt/ad-runner/cache"
        self.api    = cfg.get("api_url_base") or "https://cms.flawkai.com/api/ads"
        self.play_sound = bool(cfg.get("play_sound", True))
        self.duck_other_audio = bool(cfg.get("duck_other_audio", True))
        self.log    = Log(cfg.get("log_file") or "/var/log/ad_runner.log")
        ensure_dir(self.cache)
        try: os.chmod(self.cache,0o777)
        except PermissionError: pass
        self.queue=[]
        self.first_play_done = False
        self.start_ts = time.time()

    def req_url(self):
        params = {
            "device_id": self.device,
            "organization": self.org,
            "width": str(self.w),
            "height": str(self.h),
            "venue_type": self.venue,
            "venue_name": self.venue_name,
            "lat": self.lat, "lon": self.lon,
        }
        ip4 = ext_ip()
        ip6 = ext_ipv6()
        if ip4: params["ip"] = ip4
        if ip6: params["ipv6"] = ip6   # send IPv6 if available
        return self.api + "?" + up.urlencode(params)

    def fire(self, urls, duration=0, playhead=0, label=""):
        if not urls: return
        def worker(v):
            for u in v:
                try: requests.get(replace_macros(u,duration,playhead), timeout=2, headers=HEADERS)
                except Exception: pass
        threading.Thread(target=worker, args=(list(urls),), daemon=True).start()
        if label: self.log.info("Fired %s x %d", label, len(urls))

    def fill_once(self):
        url = self.req_url()
        r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
        if r.status_code==204 or not r.content:
            time.sleep(self.poll); return False
        parsed = follow_wrappers(r.content)
        if not parsed:
            self.log.warn("VAST parse returned nothing"); time.sleep(self.poll); return False

        media_list = parsed.get("media_files", [])
        if media_list:
            try:
                summary=[]
                for mf in media_list[:10]:
                    t=(mf.get("type") or "").lower()
                    w=(mf.get("width") or "?"); h=(mf.get("height") or "?")
                    u=(mf.get("url") or "")
                    utail="…"+u[-60:] if len(u)>60 else u
                    summary.append(f"{t}|{w}x{h}|{utail}")
                self.log.info("VAST media candidates: %s", " , ".join(summary))
            except Exception: pass

        mf = choose_media(media_list, self.w, self.h)
        if not mf or not mf.get("url"):
            try:
                with open("/opt/ad-runner/last_vast.xml","wb") as f: f.write(r.content)
                os.chmod("/opt/ad-runner/last_vast.xml",0o666)
            except Exception: pass
            self.log.warn("No playable media file in VAST (saved to /opt/ad-runner/last_vast.xml)")
            time.sleep(self.poll); return False

        media_url = mf["url"]
        local     = download_if_needed(media_url, self.cache)
        ad = {
            "src": media_url,
            "path": local if os.path.exists(local) else media_url,
            "dur": max(1, int(parsed.get("duration") or 15)),
            "imps": parsed.get("impressions", []),
            "trk": parsed.get("trackers", {})
        }
        self.queue.append(ad)
        self.log.info("Queued ad %d/%d from %s", len(self.queue), self.qmax, media_url)
        time.sleep(self.poll); return True

    def fill_window(self):
        self.log.info("Filling queue for up to %ds or until %d ads queued…", self.fill, self.qmax)
        deadline = time.time() + self.fill
        while time.time() < deadline and len(self.queue) < self.qmax:
            self.fill_once()

    def _schedule_tracking_for_set(self, items, t0):
        offset = 0
        for ad in items:
            dur = max(1, ad["dur"])
            if ad["imps"]:
                threading.Thread(target=lambda u=ad["imps"], d=dur, off=offset:
                                 (time.sleep(max(0, t0+off - time.time())), self.fire(u, d, 0, "impressions")),
                                 daemon=True).start()
            evs=[("start",0),("firstQuartile",dur//4),("midpoint",dur//2),
                 ("thirdQuartile",(dur*3)//4),("complete",max(0,dur-1))]
            for name, tsec in evs:
                urls = ad["trk"].get(name, [])
                if not urls: continue
                threading.Thread(target=lambda u=urls, tt=tsec, dd=dur, off=offset, nm=name:
                                 (time.sleep(max(0, t0+off+tt - time.time())), self.fire(u, dd, tt, nm)),
                                 daemon=True).start()
            offset += dur

    def play_queue(self):
        if not self.queue:
            self.log.info("Nothing to play."); return 0
        items=list(self.queue); self.queue.clear()
        self.log.info("Playing %d queued ads in one player session…", len(items))
        paths=[ad["path"] for ad in items]
        t0 = time.time() + 0.5
        self._schedule_tracking_for_set(items, t0)

        snapshot = []
        if self.duck_other_audio:
            snapshot = duck_others(mute=True) or []
            self.log.info("Ducked %d other audio stream(s).", len(snapshot))

        ok = MPV.play_list_blocking(paths, mute=not self.play_sound)

        if self.duck_other_audio:
            duck_others(mute=False, snapshot=snapshot)
            self.log.info("Restored %d audio stream(s).", len(snapshot))

        if not ok:
            self.log.err("Batch playback failed.")
        return len(items)

    def background_cache(self, until_ts):
        while time.time() < until_ts:
            if len(self.queue) >= self.qmax: time.sleep(1); continue
            self.fill_once()

    def run(self):
        self.log.info("Ad Runner start. Device=%s Org=%s VenueType=%s VenueName=%s",
                      self.device, self.org, self.venue, self.venue_name)
        init_end = time.time() + max(0, self.init_delay)
        self.log.info("Initial startup delay: %ds (playback will not start before that; caching allowed).", self.init_delay)

        while True:
            self.fill_window()

            if not self.first_play_done:
                now = time.time()
                if now < init_end:
                    remaining = int(init_end - now)
                    self.log.info("Startup delay active: %ds remaining. Caching in background.", remaining)
                    self.background_cache(init_end)

            played = self.play_queue()
            if not self.first_play_done:
                self.first_play_done = True

            total_cool = self.cool_per_ad * max(0, played)
            if total_cool <= 0: total_cool = self.cool_per_ad
            self.log.info("Cooldown %ds (=%ds per ad × %d). Caching in background.", total_cool, self.cool_per_ad, played)
            end = time.time() + total_cool
            self.background_cache(end)

if __name__=="__main__":
    _lock = acquire_singleton_lock(LOCK_PATH)
    Runner("/opt/ad-runner/config.json").run()
PY

sudo chmod +x "$APP_DIR/ad_runner.py"
sudo chmod -R 0777 "$APP_DIR"

# ---------- systemd user service ----------
echo "== Create systemd user service =="
mkdir -p "$USER_HOME/.config/systemd/user"
cat > "$USER_HOME/.config/systemd/user/ad-runner.service" <<'UNIT'
[Unit]
Description=Flawk Ad Runner (VAST poller + fullscreen player)
After=graphical-session.target
Wants=graphical-session.target

[Service]
Type=simple
ExecStart=/opt/ad-runner/.venv/bin/python /opt/ad-runner/ad_runner.py
WorkingDirectory=/opt/ad-runner
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1
Environment=DISPLAY=:0
Environment=PULSE_SERVER=unix:/run/user/%U/pulse/native
# Route unexpected Python stderr (e.g., crashes before logger init) to our main log.
# Avoid duplicate info logs by discarding stdout here (Python already writes to the log_file).
StandardOutput=null
StandardError=append:/var/log/ad_runner.log

[Install]
WantedBy=default.target
UNIT
chown "$RUN_USER:$RUN_USER" "$USER_HOME/.config/systemd/user/ad-runner.service"

# ---------- ensure user bus is available, then enable & start ----------
echo "== Enable user lingering and start user manager =="
ensure_user_bus "$RUN_USER"

echo "== Reload systemd (user) and enable service =="
sudo -u "$RUN_USER" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" systemctl --user daemon-reload
sudo -u "$RUN_USER" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" systemctl --user enable --now ad-runner.service

echo
echo "== Install complete =="
echo "Status:"
sudo -u "$RUN_USER" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" systemctl --user status ad-runner.service --no-pager || true
echo
echo "Logs:"
echo "  Installer log: $INSTALL_LOG"
echo "  Runner log:    $LOG_FILE"
echo "  MPV log:       $MPV_LOG_FILE"
echo
echo "To tail live logs:"
echo "  tail -f $INSTALL_LOG $LOG_FILE $MPV_LOG_FILE"
