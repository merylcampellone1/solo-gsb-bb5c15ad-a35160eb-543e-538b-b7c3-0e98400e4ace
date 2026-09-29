"""SQLite 连接、建表与初始化。"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DATABASE_PATH = Path(__file__).resolve().parent.parent / "data" / "rules.db"


def database_url() -> str:
    return os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DATABASE_PATH}")


def _sqlite_path(url: str) -> str | None:
    """将 DATABASE_URL 转成文件路径；sqlite:///:memory: 返回 :memory:。"""
    if url.startswith("sqlite:///"):
        target = url[len("sqlite:///") :]
        return target or ":memory:"
    if url == "sqlite://":
        return ":memory:"
    # 也允许直接传文件路径
    return url


SCHEMA = """
CREATE TABLE IF NOT EXISTS rulesets (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    default_conflict_policy TEXT NOT NULL DEFAULT 'collect_all',
    current_version INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ruleset_versions (
    id          TEXT PRIMARY KEY,
    ruleset_id  TEXT NOT NULL REFERENCES rulesets(id),
    version     INTEGER NOT NULL,
    snapshot    TEXT NOT NULL,            -- 完整规则集 JSON 快照（不可变）
    created_at  TEXT NOT NULL,
    UNIQUE(ruleset_id, version)
);
CREATE INDEX IF NOT EXISTS idx_versions_ruleset
    ON ruleset_versions(ruleset_id);

CREATE TABLE IF NOT EXISTS evaluations (
    id          TEXT PRIMARY KEY,
    ruleset_id  TEXT NOT NULL REFERENCES rulesets(id),
    version     INTEGER NOT NULL,         -- 计算所用版本
    document    TEXT NOT NULL,           -- 提交的文档
    result      TEXT NOT NULL,           -- 完整决策结果
    converged   INTEGER NOT NULL,
    iterations  INTEGER NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evaluations_ruleset
    ON evaluations(ruleset_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_evaluations_ruleset_version
    ON evaluations(ruleset_id, version);

-- 单文档决策的客户端幂等记录：键作用域为规则集。
-- version_mode/explicit_version 固定首次受理时的版本选择方式，
-- document_canonical 为按对象键排序规范化后的文档，
-- evaluation_id 关联 evaluations 中保存的完整决策结果。
CREATE TABLE IF NOT EXISTS idempotent_decisions (
    id                 TEXT PRIMARY KEY,
    ruleset_id         TEXT NOT NULL REFERENCES rulesets(id),
    idempotency_key    TEXT NOT NULL,
    version_mode       TEXT NOT NULL,         -- latest=使用受理时最新版；explicit=指定版本
    explicit_version   INTEGER,               -- version_mode=explicit 时的请求版本号
    actual_version     INTEGER NOT NULL,      -- 首次受理实际固定求值的版本
    document_canonical TEXT NOT NULL,         -- 规范化（sort_keys）后的文档 JSON
    evaluation_id      TEXT NOT NULL REFERENCES evaluations(id),
    created_at         TEXT NOT NULL,
    UNIQUE(ruleset_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def connect(database: str | None = None) -> sqlite3.Connection:
    url = database or database_url()
    path = _sqlite_path(url)
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


@contextmanager
def session(database: str | None = None) -> Iterator[sqlite3.Connection]:
    conn = connect(database)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
