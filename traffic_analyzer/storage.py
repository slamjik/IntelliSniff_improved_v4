import os, threading, sqlite3, time, logging
from typing import Dict, Any, List
log = logging.getLogger('ta.storage')
CLICKHOUSE_HOST = os.getenv('CLICKHOUSE_HOST')
try:
    from clickhouse_driver import Client as CHClient
except Exception:
    CHClient = None

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
DB_PATH = os.path.join(DATA_DIR, 'ta_storage.db')

class Storage:
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        self._lock = threading.Lock()
        self._use_ch = False
        self._ch = None
        if CLICKHOUSE_HOST and CHClient is not None:
            try:
                self._ch = CHClient(host=CLICKHOUSE_HOST)
                # initialize table
                self._ch.execute('CREATE TABLE IF NOT EXISTS ta_flows (ts DateTime, src String, dst String, sport UInt16, dport UInt16, proto String, packets UInt32, bytes UInt64, label String) ENGINE = MergeTree() ORDER BY ts')
                self._use_ch = True
                log.info('Using ClickHouse at %s', CLICKHOUSE_HOST)
            except Exception as e:
                log.exception('ClickHouse init failed: %s', e)
                self._use_ch = False
        # fallback to sqlite
        self._init_sqlite()

    def _init_sqlite(self):
        with self._conn() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS flows (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, src TEXT, dst TEXT, sport INTEGER, dport INTEGER, proto TEXT, packets INTEGER, bytes INTEGER, label TEXT)''')

    def _conn(self):
        return sqlite3.connect(DB_PATH, check_same_thread=False)

    def insert_flow(self, flow: Dict[str, Any]):
        if self._use_ch:
            try:
                self._ch.execute('INSERT INTO ta_flows (ts,src,dst,sport,dport,proto,packets,bytes,label) VALUES', [
                    (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(flow.get('ts')/1000)), flow.get('src'), flow.get('dst'),
                     int(flow.get('sport') or 0), int(flow.get('dport') or 0), str(flow.get('proto') or ''),
                     int(flow.get('packets') or 0), int(flow.get('bytes') or 0), str(flow.get('label') or ''))])
            except Exception:
                log.exception('CH insert failed, falling back to sqlite')
                self._use_ch = False
        if not self._use_ch:
            with self._lock, self._conn() as c:
                c.execute('''INSERT INTO flows (ts,src,dst,sport,dport,proto,packets,bytes,label) VALUES (?,?,?,?,?,?,?,?,?)''',
                          (int(time.time()*1000), flow.get('src'), flow.get('dst'), int(flow.get('sport') or 0),
                           int(flow.get('dport') or 0), flow.get('proto'), int(flow.get('packets') or 0),
                           int(flow.get('bytes') or 0), flow.get('label') or ''))
    def recent(self, limit=100):
        if self._use_ch:
            try:
                rows = self._ch.execute('SELECT ts,src,dst,proto,packets,bytes,label FROM ta_flows ORDER BY ts DESC LIMIT %s',[limit])
                return rows
            except Exception:
                self._use_ch = False
        with self._conn() as c:
            cur = c.execute('SELECT ts,src,dst,proto,packets,bytes,label FROM flows ORDER BY ts DESC LIMIT ?', (limit,))
            return cur.fetchall()

storage = Storage()
