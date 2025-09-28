import time, logging, os, json
log = logging.getLogger("ta")
def now_ms():
    return int(time.time()*1000)
def ensure_dir(p):
    os.makedirs(p, exist_ok=True)
def read_json(p):
    with open(p,'r',encoding='utf-8') as f:
        return json.load(f)
def write_json(p, obj):
    ensure_dir(os.path.dirname(p))
    with open(p,'w',encoding='utf-8') as f:
        json.dump(obj, f, indent=2)
