"""SQLite 存储层：连接管理、建表与种子数据。"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

DATA_DIR = Path(os.environ.get("SANDBOX_DATA", Path(__file__).resolve().parent.parent / "data"))
DB_PATH = DATA_DIR / "sandbox.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    action TEXT NOT NULL DEFAULT 'suppress',
    priority INTEGER NOT NULL DEFAULT 100,
    cooldown_seconds INTEGER NOT NULL DEFAULT 0,
    match_device TEXT DEFAULT '',
    match_batch TEXT DEFAULT '',
    match_level TEXT DEFAULT '',
    time_start TEXT DEFAULT '',
    time_end TEXT DEFAULT '',
    date_start TEXT DEFAULT '',
    date_end TEXT DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER NOT NULL UNIQUE,
    device_id TEXT DEFAULT '',
    batch_id TEXT DEFAULT '',
    level TEXT DEFAULT 'info',
    alert_type TEXT DEFAULT '',
    message TEXT DEFAULT '',
    ts TEXT NOT NULL,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS staged (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ord INTEGER NOT NULL DEFAULT 0,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL DEFAULT 'replay',   -- live=实时注入链; replay=回放对比
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    note TEXT DEFAULT '',
    rule_snapshot TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    decision TEXT NOT NULL,
    rule_id INTEGER,
    rule_name TEXT,
    reason TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    fired_at_epoch REAL,
    detail_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS receiver_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    status TEXT NOT NULL,           -- received / delivered / failed
    target TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    detail TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signature TEXT NOT NULL UNIQUE,          -- 内容签名（间隔+分组键+成员），用于重算对齐
    device_id TEXT NOT NULL DEFAULT '',
    alert_type TEXT NOT NULL DEFAULT '',
    gap_seconds INTEGER NOT NULL DEFAULT 900,
    first_ts TEXT NOT NULL,
    last_ts TEXT NOT NULL,
    alert_count INTEGER NOT NULL,
    max_level TEXT NOT NULL DEFAULT 'info',
    member_ids TEXT NOT NULL,                -- JSON: 按时间线排序的 alerts.id
    member_seqs TEXT NOT NULL,               -- JSON: 对应的注入序号
    acknowledged INTEGER NOT NULL DEFAULT 0,
    acked_at TEXT,
    note TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_times ON events(first_ts, last_ts);
CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id, alert_type);

-- 事件演进：不可变快照。保存后不再被任何操作改写（撤销告警、调整间隔、
-- 重算事件都只影响 events 表）；仅 /api/reset 恢复出厂时随业务数据一并清空。
CREATE TABLE IF NOT EXISTS event_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note TEXT DEFAULT '',
    gap_seconds INTEGER NOT NULL DEFAULT 900,   -- 生成快照时的聚合间隔
    event_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS event_snapshot_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL REFERENCES event_snapshots(id) ON DELETE CASCADE,
    ord INTEGER NOT NULL,                    -- 快照内稳定顺序（首时间, 设备, 类型, 事件 id）
    event_id INTEGER,                        -- 生成快照时的 events.id（血缘排序用）
    device_id TEXT NOT NULL DEFAULT '',
    alert_type TEXT NOT NULL DEFAULT '',
    first_ts TEXT NOT NULL,
    last_ts TEXT NOT NULL,
    alert_count INTEGER NOT NULL,
    max_level TEXT NOT NULL DEFAULT 'info',
    member_ids TEXT NOT NULL,                -- JSON: 按时间线排序的 alerts.id
    member_seqs TEXT NOT NULL,               -- JSON: 对应的注入序号
    acknowledged INTEGER NOT NULL DEFAULT 0,
    acked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_snapshot_items ON event_snapshot_items(snapshot_id, ord);
"""

_RULE_COLS = [
    "id", "name", "description", "action", "priority", "cooldown_seconds",
    "match_device", "match_batch", "match_level", "time_start", "time_end",
    "date_start", "date_end", "enabled",
]

DEFAULT_SETTINGS = {
    "forward_enabled": "false",
    "receiver_mode": "mock",      # mock=内置模拟接收端; external=自定义 webhook
    "external_url": "http://receiver:9000/mock-webhook",
    "correlation_gap_seconds": "900",  # 事件关联：相邻告警聚合间隔（秒）
}


def get_conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # isolation_level=None：autocommit 模式，避免隐式事务导致 DDL/批量 DELETE 不生效
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def rule_view(row: sqlite3.Row) -> dict:
    return {col: row[col] for col in _RULE_COLS}


def seed_rules() -> list[dict]:
    """内置冷链场景示例规则。"""
    return [
        {
            "name": "夜间冷藏车温度抖动抑制",
            "description": "冷藏车 TR-01 运输批次 B2026-09A 时，夜间 22:00-次日 06:00 的 warning 级温度告警直接抑制",
            "action": "suppress",
            "priority": 100,
            "cooldown_seconds": 0,
            "match_device": "TR-01",
            "match_batch": "B2026-09A",
            "match_level": "warning",
            "time_start": "22:00",
            "time_end": "06:00",
            "date_start": "",
            "date_end": "",
            "enabled": 1,
        },
        {
            "name": "critical 告警永远放行",
            "description": "显式高优先级规则（priority 更小），任何设备/批次的 critical 一律放行，覆盖夜间抑制规则",
            "action": "pass",
            "priority": 10,
            "cooldown_seconds": 0,
            "match_device": "",
            "match_batch": "",
            "match_level": "critical",
            "time_start": "",
            "time_end": "",
            "date_start": "",
            "date_end": "",
            "enabled": 1,
        },
        {
            "name": "TR-02 开门告警 5 分钟冷却",
            "description": "放行规则但带 300s 冷却窗：同一设备/批次/级别/类型的连续开门告警只放行首条",
            "action": "pass",
            "priority": 50,
            "cooldown_seconds": 300,
            "match_device": "TR-02",
            "match_batch": "",
            "match_level": "warning",
            "time_start": "",
            "time_end": "",
            "date_start": "",
            "date_end": "",
            "enabled": 1,
        },
        {
            "name": "夜间温度抑制（重复规则·审计示例）",
            "description": "与「夜间冷藏车温度抖动抑制」条件完全相同但优先级更低，会被规则审计标为完全遮蔽的死规则",
            "action": "suppress",
            "priority": 200,
            "cooldown_seconds": 0,
            "match_device": "TR-01",
            "match_batch": "B2026-09A",
            "match_level": "warning",
            "time_start": "22:00",
            "time_end": "06:00",
            "date_start": "",
            "date_end": "",
            "enabled": 1,
        },
        {
            "name": "TR-01 深夜放行覆盖（审计示例）",
            "description": "00:00-02:00 放行 TR-01/B2026-09A 全部级别（仅 2026-09 生效），与夜间抑制规则在凌晨时段存在动作冲突，但优先级更低、交集内被抑制规则压住",
            "action": "pass",
            "priority": 150,
            "cooldown_seconds": 0,
            "match_device": "TR-01",
            "match_batch": "B2026-09A",
            "match_level": "",
            "time_start": "00:00",
            "time_end": "02:00",
            "date_start": "2026-09-01",
            "date_end": "2026-09-30",
            "enabled": 1,
        },
    ]


def seed_staged_payloads() -> list[dict]:
    """内置 8 条示例冷链告警（覆盖抑制/优先覆盖/冷却/默认放行四种情形）。"""
    base = datetime(2026, 9, 21, 0, 0, 0)

    def at(minutes: int) -> str:
        return (base + timedelta(minutes=minutes)).isoformat()

    return [
        {"device_id": "TR-01", "batch_id": "B2026-09A", "level": "warning",
         "alert_type": "temp_high", "message": "厢内温度 -15.2℃，高于阈值 -18℃", "ts": at(5)},
        {"device_id": "TR-01", "batch_id": "B2026-09A", "level": "critical",
         "alert_type": "temp_high", "message": "厢内温度 -9.0℃，存在断链风险", "ts": at(15)},
        {"device_id": "TR-01", "batch_id": "B2026-09A", "level": "warning",
         "alert_type": "temp_high", "message": "厢内温度 -16.4℃，夜间抖动", "ts": at(30)},
        {"device_id": "TR-02", "batch_id": "B2026-09B", "level": "warning",
         "alert_type": "door_open", "message": "后门开启超过 2 分钟", "ts": at(45)},
        {"device_id": "TR-02", "batch_id": "B2026-09B", "level": "warning",
         "alert_type": "door_open", "message": "后门仍未关闭", "ts": at(47)},
        {"device_id": "TR-02", "batch_id": "B2026-09B", "level": "warning",
         "alert_type": "door_open", "message": "后门仍未关闭", "ts": at(52)},
        {"device_id": "WH-03", "batch_id": "B2026-09C", "level": "info",
         "alert_type": "sensor_offline", "message": "冷库传感器心跳超时", "ts": at(60)},
        {"device_id": "TR-01", "batch_id": "B2026-09A", "level": "warning",
         "alert_type": "temp_high", "message": "厢内温度 -16.0℃，白天仍偏高", "ts": at(60 * 9)},
    ]


def reset_all(conn) -> None:
    """在给定连接上原子清空业务数据并恢复内置示例。"""
    conn.execute("BEGIN")
    try:
        conn.executescript(
            "DELETE FROM decisions; DELETE FROM receiver_logs; DELETE FROM staged; "
            "DELETE FROM alerts; DELETE FROM rules; DELETE FROM runs; DELETE FROM events; "
            "DELETE FROM event_snapshot_items; DELETE FROM event_snapshots;"
        )
        inserted_ids = []
        for rule in seed_rules():
            cur = conn.execute(
                """INSERT INTO rules(name, description, action, priority, cooldown_seconds,
                   match_device, match_batch, match_level, time_start, time_end,
                   date_start, date_end, enabled)
                   VALUES (:name, :description, :action, :priority, :cooldown_seconds,
                   :match_device, :match_batch, :match_level, :time_start, :time_end,
                   :date_start, :date_end, :enabled)""",
                rule,
            )
            inserted_ids.append(cur.lastrowid)
        for idx, payload in enumerate(seed_staged_payloads()):
            conn.execute(
                "INSERT INTO staged(ord, payload) VALUES (?, ?)",
                (idx, json.dumps(payload, ensure_ascii=False)),
            )
        snap_rows = conn.execute(
            "SELECT * FROM rules WHERE id IN (%s) ORDER BY priority, id"
            % ",".join("?" * len(inserted_ids)), inserted_ids,
        ).fetchall()
        snapshot = json.dumps([rule_view(r) for r in snap_rows], ensure_ascii=False)
        conn.execute(
            "INSERT INTO runs(kind, note, rule_snapshot) VALUES ('live', ?, ?)",
            ("实时注入链（当前策略，逐条累积评估）", snapshot),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db(force_seed: bool = False) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = get_conn()
    try:
        conn.executescript(_SCHEMA)
        conn.execute("BEGIN")
        try:
            for key, value in DEFAULT_SETTINGS.items():
                conn.execute(
                    "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (key, value)
                )
            count = conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
            if force_seed or count == 0:
                if force_seed:
                    conn.executescript(
                        "DELETE FROM decisions; DELETE FROM receiver_logs; "
                        "DELETE FROM staged; DELETE FROM alerts; DELETE FROM rules; "
                        "DELETE FROM runs; DELETE FROM events; "
                        "DELETE FROM event_snapshot_items; DELETE FROM event_snapshots;"
                    )
                for rule in seed_rules():
                    conn.execute(
                        """INSERT INTO rules(name, description, action, priority, cooldown_seconds,
                           match_device, match_batch, match_level, time_start, time_end,
                           date_start, date_end, enabled)
                           VALUES (:name, :description, :action, :priority, :cooldown_seconds,
                           :match_device, :match_batch, :match_level, :time_start, :time_end,
                           :date_start, :date_end, :enabled)""",
                        rule,
                    )
            if conn.execute("SELECT COUNT(*) FROM staged").fetchone()[0] == 0:
                for idx, payload in enumerate(seed_staged_payloads()):
                    conn.execute(
                        "INSERT INTO staged(ord, payload) VALUES (?, ?)",
                        (idx, json.dumps(payload, ensure_ascii=False)),
                    )
            # 确保 live run 存在
            row = conn.execute("SELECT id FROM runs WHERE kind='live'").fetchone()
            if row is None:
                snapshot = json.dumps(
                    [rule_view(r) for r in conn.execute(
                        "SELECT * FROM rules WHERE enabled=1 ORDER BY priority, id"
                    )],
                    ensure_ascii=False,
                )
                conn.execute(
                    "INSERT INTO runs(kind, note, rule_snapshot) VALUES ('live', ?, ?)",
                    ("实时注入链（当前策略，逐条累积评估）", snapshot),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    finally:
        conn.close()
