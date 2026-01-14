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
HEADERS = {"User-Agent":"FlawkAdRunner/0.0.8 (Linux; Production)","Accept":"application/xml,text/xml,*/*"}
MPV_TIMEOUT_BUFFER = 40 

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

# --- SMART PARSER (Media Selection + Recursion) ---
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
                return min(abs(h - 720), abs(h - 1080))
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
        total_sec = 0
        for ad in items:
            total_sec += ad['dur']
            if os.path.exists(ad['path']):
                Path(ad['path']).touch()
                paths.append(ad['path'])
            else: paths.append(ad['src'])
        
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
        
        cmd = ["mpv", "--fs", "--no-border", "--really-quiet", 
               "--ontop", "--force-window=immediate", "--keep-open=no",
               "--geometry=100%x100%", "--autofit=100%",
               "--input-default-bindings=no", "--input-vo-keyboard=no", 
               "--cursor-autohide=always", "--osc=no", #"--prefetch-playlist=yes",
               "--vo=gpu", "--gpu-context=x11" if os.environ.get("DISPLAY") else "--gpu-context=drm",
               f"--log-file=/var/log/ad-runner/mpv_player.log"]

        if os.environ.get("DISPLAY"):
             cmd.extend(["--vo=gpu", "--gpu-context=x11"])
        else:
             cmd.extend(["--vo=gpu", "--gpu-context=drm"])
        
        if is_muted: cmd.append("--mute=yes")
        cmd = cmd + paths
        
        env = os.environ.copy(); env["DISPLAY"] = env.get("DISPLAY", ":0")
        
        TIMEOUT_VAL = total_sec + MPV_TIMEOUT_BUFFER
        self.log.info(f"Playing Batch. Total: {total_sec}s. Watchdog: {TIMEOUT_VAL}s")

        try:
            subprocess.run(cmd, env=env, check=False, timeout=TIMEOUT_VAL)
        except subprocess.TimeoutExpired:
            self.log.err(f"MPV Freeze detected. Killing.")
            subprocess.run(["pkill", "-9", "-f", "mpv --fs"], stdout=subprocess.DEVNULL)
        
        if snap: duck_others(False, snap)
        return len(items)

    def run(self):
        self.log.info(f"Runner Start v0.0.8. ID={self.device}")
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
