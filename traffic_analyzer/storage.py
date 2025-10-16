# traffic_analyzer/storage.py
import json
import os, sqlite3, threading, time
from typing import Dict, Any, Optional

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

    def _cleanup(self, conn: sqlite3.Connection, max_age_hours: Optional[float] = 24.0, max_rows: int = 5000):
        """Keep database compact by dropping very old or excessive rows."""
        if max_age_hours is not None:
            cutoff = time.time() - float(max_age_hours) * 3600.0
            conn.execute("DELETE FROM flows WHERE ts < ?", (cutoff,))
        if max_rows and max_rows > 0:
            # delete rows older than the newest max_rows entries
            cur = conn.execute("SELECT id FROM flows ORDER BY id DESC LIMIT 1 OFFSET ?", (max_rows - 1,))
            row = cur.fetchone()
            if row:
                conn.execute("DELETE FROM flows WHERE id < ?", (row[0],))

    @staticmethod
    def _as_text(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        if isinstance(value, (bytes, bytearray)):
            try:
                return value.decode('utf-8', errors='ignore')
            except Exception:
                return str(value)
        return str(value)

    @staticmethod
    def _as_int(value: Any, default: int = 0) -> int:
        if value is None:
            return default
        if callable(value):
            try:
                return Storage._as_int(value(), default)
            except Exception:
                return default
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            if value != value:  # NaN check without math import
                return default
            return int(value)
        if isinstance(value, (bytes, bytearray)):
            try:
                value = value.decode('utf-8', errors='ignore')
            except Exception:
                return default
        try:
            return int(str(value).strip())
        except Exception:
            try:
                return int(float(str(value).strip()))
            except Exception:
                return default

    @staticmethod
    def _as_float(value: Any, default: float = 0.0) -> float:
        if value is None:
            return default
        if callable(value):
            try:
                return Storage._as_float(value(), default)
            except Exception:
                return default
        if isinstance(value, bool):
            return float(value)
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, (bytes, bytearray)):
            try:
                value = value.decode('utf-8', errors='ignore')
            except Exception:
                return default
        try:
            return float(str(value).strip())
        except Exception:
            return default

    def insert_flow(self, flow: Dict[str,Any]):
        with self._lock:
            with self._conn() as c:
                summary = flow.get('summary')
                if isinstance(summary, (dict, list)):
                    summary_value = json.dumps(summary, ensure_ascii=False)
                else:
                    summary_value = self._as_text(summary) or ''
                iface = self._as_text(flow.get('iface'))
                c.execute("""INSERT INTO flows (ts,iface,src,dst,sport,dport,proto,packets,bytes,label,score,summary)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    self._as_float(flow.get('ts'), time.time()),
                    iface,
                    self._as_text(flow.get('src')),
                    self._as_text(flow.get('dst')),
                    self._as_int(flow.get('sport')),
                    self._as_int(flow.get('dport')),
                    self._as_text(flow.get('proto')) or '',
                    self._as_int(flow.get('packets')),
                    self._as_int(flow.get('bytes')),
                    self._as_text(flow.get('label')) or 'unknown',
                    self._as_float(flow.get('score')),
                    summary_value
                ))
                try:
                    self._cleanup(c)
                except Exception:
                    pass
                c.commit()

    def recent(self, limit=100):
        try:
            limit = int(limit)
        except Exception:
            limit = 100
        limit = max(1, min(limit, 1000))
        with self._conn() as c:
            cur = c.execute('SELECT ts,iface,src,dst,sport,dport,proto,packets,bytes,label,score,summary FROM flows ORDER BY ts DESC LIMIT ?', (limit,))
            rows = cur.fetchall()
            cols = ['ts','iface','src','dst','sport','dport','proto','packets','bytes','label','score','summary']
            return [dict(zip(cols, r)) for r in rows]

storage = Storage()
