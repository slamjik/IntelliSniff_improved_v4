# traffic_analyzer/storage.py
import os, sqlite3, threading, time
from typing import Dict, Any, List

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, 'ta_storage.db')

class Storage:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                iface TEXT,
                src TEXT,
                dst TEXT,
                sport INTEGER,
                dport INTEGER,
                proto TEXT,
                packets INTEGER,
                bytes INTEGER,
                label TEXT,
                score REAL,
                summary TEXT
            )""")
            c.commit()

    def insert_flow(self, flow: Dict[str,Any]):
        with self._lock:
            with self._conn() as c:
                c.execute("""INSERT INTO flows (ts,iface,src,dst,sport,dport,proto,packets,bytes,label,score,summary)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    float(flow.get('ts') or time.time()),
                    flow.get('iface'),
                    flow.get('src'),
                    flow.get('dst'),
                    int(flow.get('sport') or 0),
                    int(flow.get('dport') or 0),
                    flow.get('proto') or '',
                    int(flow.get('packets') or 0),
                    int(flow.get('bytes') or 0),
                    flow.get('label') or 'unknown',
                    float(flow.get('score') or 0.0),
                    str(flow.get('summary') or '')
                ))
                c.commit()

    def recent(self, limit=100):
        with self._conn() as c:
            cur = c.execute('SELECT ts,iface,src,dst,sport,dport,proto,packets,bytes,label,score,summary FROM flows ORDER BY ts DESC LIMIT ?', (limit,))
            rows = cur.fetchall()
            cols = ['ts','iface','src','dst','sport','dport','proto','packets','bytes','label','score','summary']
            return [dict(zip(cols, r)) for r in rows]

storage = Storage()
