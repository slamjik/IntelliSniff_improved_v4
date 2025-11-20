# traffic_analyzer/storage.py
import json
import os
import sqlite3
import threading
import time
from typing import Dict, Any, Optional

# === Путь к данным / БД ======================================================

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "ta_storage.db")

# Как часто запускать "уборку" (после скольких вставок)
_CLEANUP_EVERY_INSERTS = 500

# Ограничения по данным по умолчанию
_DEFAULT_MAX_AGE_HOURS: float = 24.0
_DEFAULT_MAX_ROWS: int = 5000


class Storage:
    """
    Простое, но более аккуратное хранилище сетевых потоков на SQLite.

    - Один постоянный connection на процесс.
    - Все операции проходят через глобальный lock (безопасно из нескольких потоков).
    - Включены оптимизационные PRAGMA (WAL, synchronous=NORMAL и т.п.).
    - Очистка старых/лишних строк выполняется периодически, а не при каждом INSERT.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = self._connect()
        self._inserts_since_cleanup = 0
        self._init_db()

    # === Внутренние методы ===================================================

    def _connect(self) -> sqlite3.Connection:
        """
        Создаёт и настраивает соединение с SQLite.
        Один раз на весь объект Storage.
        """
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        try:
            # Оптимизационные PRAGMA (если не поддерживается — просто игнорируем)
            conn.execute("PRAGMA journal_mode=WAL;")      # лучше параллелизм чтения/записи
            conn.execute("PRAGMA synchronous=NORMAL;")    # баланс надёжности и скорости
            conn.execute("PRAGMA temp_store=MEMORY;")     # временные таблицы в памяти
            conn.execute("PRAGMA cache_size=-16000;")     # ~16 МБ под кэш (16000 КБ)
        except Exception:
            # Ничего страшного, если на какой-то платформе часть PRAGMA не зайдёт
            pass
        return conn

    def _init_db(self) -> None:
        """
        Создаёт таблицу flows при первом запуске
        и гарантирует наличие нужных колонок и индексов.
        """
        with self._lock:
            c = self._conn
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS flows (
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
                    label_name TEXT,
                    score REAL,
                    summary TEXT
                )
                """
            )

            # ensure newer columns exist even on legacy databases
            cur = c.execute("PRAGMA table_info(flows)")
            existing_cols = {row[1] for row in cur.fetchall()}
            if "label_name" not in existing_cols:
                c.execute("ALTER TABLE flows ADD COLUMN label_name TEXT")

            # Минимально полезные индексы
            c.execute("CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_flows_id ON flows(id)")

            c.commit()

    def _cleanup(
        self,
        conn: sqlite3.Connection,
        max_age_hours: Optional[float] = _DEFAULT_MAX_AGE_HOURS,
        max_rows: int = _DEFAULT_MAX_ROWS,
    ) -> None:
        """
        Поддерживает БД компактной: удаляет очень старые и лишние строки.
        Вызывается не на каждый insert, а периодически.
        """
        try:
            if max_age_hours is not None:
                cutoff = time.time() - float(max_age_hours) * 3600.0
                conn.execute("DELETE FROM flows WHERE ts < ?", (cutoff,))

            if max_rows and max_rows > 0:
                # Удаляем строки старше "максимально свежих max_rows записей"
                cur = conn.execute(
                    "SELECT id FROM flows ORDER BY id DESC LIMIT 1 OFFSET ?",
                    (max_rows - 1,),
                )
                row = cur.fetchone()
                if row:
                    conn.execute("DELETE FROM flows WHERE id < ?", (row[0],))
        except Exception:
            # Очистка — вспомогательная, не должна ломать основной поток
            pass

    def _maybe_cleanup(self) -> None:
        """
        Запускает очистку БД раз в N вставок, чтобы не делать DELETE на каждый INSERT.
        """
        self._inserts_since_cleanup += 1
        if self._inserts_since_cleanup >= _CLEANUP_EVERY_INSERTS:
            self._cleanup(self._conn)
            self._inserts_since_cleanup = 0

    # === Хелперы приведения типов ===========================================

    @staticmethod
    def _as_text(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        if isinstance(value, (bytes, bytearray)):
            try:
                return value.decode("utf-8", errors="ignore")
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
            # NaN check без math
            if value != value:
                return default
            return int(value)
        if isinstance(value, (bytes, bytearray)):
            try:
                value = value.decode("utf-8", errors="ignore")
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
                value = value.decode("utf-8", errors="ignore")
            except Exception:
                return default
        try:
            return float(str(value).strip())
        except Exception:
            return default

    # === Публичные методы ====================================================

    def insert_flow(self, flow: Dict[str, Any]) -> None:
        """
        Вставляет одну запись о потоке в таблицу flows.

        Совместимо по входным данным с предыдущей версией:
        ожидает dict с ключами:
        ts, iface, src, dst, sport, dport, proto,
        packets, bytes, label, label_name, score, summary.
        """
        summary = flow.get("summary")
        if isinstance(summary, (dict, list)):
            summary_value = json.dumps(summary, ensure_ascii=False)
        else:
            summary_value = self._as_text(summary) or ""

        iface = self._as_text(flow.get("iface"))

        row = (
            self._as_float(flow.get("ts"), time.time()),
            iface,
            self._as_text(flow.get("src")),
            self._as_text(flow.get("dst")),
            self._as_int(flow.get("sport")),
            self._as_int(flow.get("dport")),
            self._as_text(flow.get("proto")) or "",
            self._as_int(flow.get("packets")),
            self._as_int(flow.get("bytes")),
            self._as_text(flow.get("label")) or "unknown",
            self._as_text(flow.get("label_name"))
            or self._as_text(flow.get("label"))
            or "unknown",
            self._as_float(flow.get("score")),
            summary_value,
        )

        with self._lock:
            c = self._conn
            c.execute(
                """
                INSERT INTO flows (
                    ts, iface, src, dst,
                    sport, dport, proto,
                    packets, bytes,
                    label, label_name,
                    score, summary
                )
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                row,
            )
            # Периодическая очистка
            self._maybe_cleanup()
            c.commit()

    def recent(self, limit: int = 100):
        """
        Возвращает список последних записей о потоках в виде dict’ов.
        Аналогично старой реализации, но использует постоянное соединение.
        """
        try:
            limit = int(limit)
        except Exception:
            limit = 100
        limit = max(1, min(limit, 1000))

        cols = [
            "ts",
            "iface",
            "src",
            "dst",
            "sport",
            "dport",
            "proto",
            "packets",
            "bytes",
            "label",
            "label_name",
            "score",
            "summary",
        ]

        with self._lock:
            cur = self._conn.execute(
                """
                SELECT ts, iface, src, dst,
                       sport, dport, proto,
                       packets, bytes,
                       label, label_name,
                       score, summary
                FROM flows
                ORDER BY ts DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cur.fetchall()

        return [dict(zip(cols, r)) for r in rows]


# === Глобальный экземпляр и удобная функция ================================

storage = Storage()


def recent(limit: int = 100):
    """
    Удобный прокси, полностью совместимый с предыдущей версией:
    from traffic_analyzer.storage import recent
    """
    return storage.recent(limit=limit)
