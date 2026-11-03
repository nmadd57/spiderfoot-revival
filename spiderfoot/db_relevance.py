# -*- coding: utf-8 -*-
"""Database support for relevance scoring.

Mixed into :class:`spiderfoot.db.SpiderFootDb`. Like the identity tables, these are created idempotently
every time a database is opened, so existing databases are migrated in place and no data is touched.

Tables:

``tbl_event_relevance``      score (0..1), label, reasons (JSON list), method and time per scan event
``tbl_scan_context``         the user's context hints and the prune switch per scan
``tbl_relevance_override``   the user's "this is mine" / "not related" decisions (they win over any score)
``tbl_relevance_run``        status and counters of the last assessment of a scan
``tbl_embedding_cache``      embedding vectors keyed by (model, sha256 of the text), so reruns are free
"""

import array
import json
import sqlite3
import time
import typing

LABELS = ('confirmed', 'likely', 'unclear', 'unrelated')
VERDICTS = ('mine', 'not_related')


class RelevanceDbMixin:
    relevanceSchemaQueries = [
        "CREATE TABLE IF NOT EXISTS tbl_event_relevance ( \
            scan_id    TEXT NOT NULL, \
            event_hash TEXT NOT NULL, \
            score      REAL NOT NULL, \
            label      TEXT NOT NULL, \
            reasons    TEXT NOT NULL DEFAULT '[]', \
            method     TEXT NOT NULL DEFAULT 'heuristics', \
            updated    INTEGER NOT NULL DEFAULT 0, \
            PRIMARY KEY (scan_id, event_hash) \
        )",
        "CREATE INDEX IF NOT EXISTS idx_event_relevance_label ON tbl_event_relevance (scan_id, label)",
        "CREATE TABLE IF NOT EXISTS tbl_scan_context ( \
            scan_id TEXT PRIMARY KEY, \
            context TEXT NOT NULL DEFAULT '', \
            prune   INTEGER NOT NULL DEFAULT 1, \
            created INTEGER NOT NULL DEFAULT 0 \
        )",
        "CREATE TABLE IF NOT EXISTS tbl_relevance_override ( \
            scan_id    TEXT NOT NULL, \
            event_hash TEXT NOT NULL, \
            verdict    TEXT NOT NULL CHECK (verdict IN ('mine','not_related')), \
            user_id    INTEGER, \
            created    INTEGER NOT NULL DEFAULT 0, \
            PRIMARY KEY (scan_id, event_hash) \
        )",
        "CREATE TABLE IF NOT EXISTS tbl_relevance_run ( \
            scan_id   TEXT PRIMARY KEY, \
            status    TEXT NOT NULL DEFAULT 'idle', \
            phase     TEXT NOT NULL DEFAULT '', \
            progress  REAL NOT NULL DEFAULT 0, \
            method    TEXT NOT NULL DEFAULT '', \
            calls     INTEGER NOT NULL DEFAULT 0, \
            tokens    INTEGER NOT NULL DEFAULT 0, \
            embedded  INTEGER NOT NULL DEFAULT 0, \
            started   INTEGER NOT NULL DEFAULT 0, \
            ended     INTEGER NOT NULL DEFAULT 0, \
            message   TEXT NOT NULL DEFAULT '', \
            counts    TEXT NOT NULL DEFAULT '{}' \
        )",
        "CREATE TABLE IF NOT EXISTS tbl_embedding_cache ( \
            model     TEXT NOT NULL, \
            text_hash TEXT NOT NULL, \
            dim       INTEGER NOT NULL, \
            vec       BLOB NOT NULL, \
            created   INTEGER NOT NULL DEFAULT 0, \
            PRIMARY KEY (model, text_hash) \
        )",
    ]

    def _migrate_relevance(self) -> None:
        """Create the relevance tables when missing (idempotent)."""
        try:
            for query in self.relevanceSchemaQueries:
                self.dbh.execute(query)
            self.conn.commit()
        except sqlite3.Error as e:
            raise IOError("Failed to migrate the database for relevance scoring") from e

    # ------------------------------------------------------------------ context

    def scanContextSet(self, scanId: str, context: str, prune: bool = True) -> None:
        with self.dbhLock:
            try:
                self.dbh.execute(
                    "INSERT OR REPLACE INTO tbl_scan_context (scan_id, context, prune, created) VALUES (?, ?, ?, ?)",
                    [scanId, str(context or '')[:4000], 1 if prune else 0, int(time.time())])
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when saving the scan context") from e

    def scanContextGet(self, scanId: str) -> dict:
        """{'context': str, 'prune': bool, 'exists': bool}; empty hints and no pruning when the scan has none (older scans)."""
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT context, prune FROM tbl_scan_context WHERE scan_id = ?", [scanId])
                row = self.dbh.fetchone()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading the scan context") from e
        return {'context': row[0], 'prune': bool(row[1]), 'exists': True} if row else {'context': '', 'prune': False, 'exists': False}

    # ------------------------------------------------------------------ scores

    def relevanceStore(self, scanId: str, rows: typing.Iterable, replace: bool = True) -> int:
        """Store ``rows`` of (event_hash, score, label, reasons list, method). Returns the number written."""
        now = int(time.time())
        data = [(scanId, r[0], float(r[1]), r[2], json.dumps(list(r[3])[:8]), r[4], now) for r in rows]
        if not data:
            return 0
        verb = 'INSERT OR REPLACE' if replace else 'INSERT OR IGNORE'
        with self.dbhLock:
            try:
                self.dbh.executemany(
                    f"{verb} INTO tbl_event_relevance (scan_id, event_hash, score, label, reasons, method, updated) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)", data)
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when storing relevance scores") from e
        return len(data)

    def relevanceGet(self, scanId: str, labels: typing.Optional[typing.Iterable[str]] = None) -> dict:
        """{event_hash: (score, label, reasons list, method)} for a scan (optionally only some labels)."""
        qry = "SELECT event_hash, score, label, reasons, method FROM tbl_event_relevance WHERE scan_id = ?"
        args = [scanId]
        if labels:
            labels = list(labels)
            qry += " AND label IN (" + ','.join('?' for _ in labels) + ")"
            args += labels
        with self.dbhLock:
            try:
                self.dbh.execute(qry, args)
                rows = self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading relevance scores") from e
        out = {}
        for h, score, label, reasons, method in rows:
            try:
                rs = json.loads(reasons)
            except ValueError:
                rs = []
            out[h] = (score, label, rs, method)
        return out

    def relevanceCounts(self, scanId: str) -> dict:
        """{label: number of events}; every label is present."""
        counts = {k: 0 for k in LABELS}
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT label, COUNT(*) FROM tbl_event_relevance WHERE scan_id = ? GROUP BY label", [scanId])
                for label, n in self.dbh.fetchall():
                    counts[label] = n
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when counting relevance labels") from e
        return counts

    def relevanceCountsByType(self, scanId: str) -> dict:
        """{event type: {label: n}} for the per-tab counts."""
        out: dict = {}
        with self.dbhLock:
            try:
                self.dbh.execute(
                    "SELECT r.type, v.label, COUNT(*) FROM tbl_scan_results r JOIN tbl_event_relevance v "
                    "ON v.scan_id = r.scan_instance_id AND v.event_hash = r.hash WHERE r.scan_instance_id = ? "
                    "GROUP BY r.type, v.label", [scanId])
                for t, label, n in self.dbh.fetchall():
                    out.setdefault(t, {})[label] = n
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when counting relevance labels by type") from e
        return out

    def relevanceUnrelatedRows(self, scanId: str, types: typing.Optional[typing.Iterable[str]] = None, limit: int = 60000) -> list:
        """(hash, source hash, type, first 160 characters of the data) of the events labelled unrelated, without reading their whole data."""
        qry = ("SELECT r.hash, r.source_event_hash, r.type, substr(r.data, 1, 160) FROM tbl_scan_results r JOIN tbl_event_relevance v "
               "ON v.scan_id = r.scan_instance_id AND v.event_hash = r.hash WHERE r.scan_instance_id = ? AND v.label = 'unrelated'")
        args: list = [scanId]
        if types is not None:
            types = list(types)
            qry += " AND r.type IN (" + ','.join('?' for _ in types) + ")"
            args += types
        qry += " LIMIT ?"
        args.append(int(limit))
        with self.dbhLock:
            try:
                self.dbh.execute(qry, args)
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading unrelated events") from e

    def relevanceDelete(self, scanId: str) -> None:
        with self.dbhLock:
            try:
                self.dbh.execute("DELETE FROM tbl_event_relevance WHERE scan_id = ?", [scanId])
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when clearing relevance scores") from e

    def scanEventsForRelevance(self, scanId: str) -> list:
        """Every event of a scan as (hash, type, module, data, source_event_hash, generated, false_positive)."""
        with self.dbhLock:
            try:
                self.dbh.execute(
                    "SELECT hash, type, module, data, source_event_hash, generated, false_positive "
                    "FROM tbl_scan_results WHERE scan_instance_id = ?", [scanId])
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading the events for relevance scoring") from e

    def scanSeedInfo(self, scanId: str) -> typing.Optional[tuple]:
        """(seed target, target type or None) of a scan, None when it does not exist."""
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT seed_target FROM tbl_scan_instance WHERE guid = ?", [scanId])
                row = self.dbh.fetchone()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading the scan target") from e
        if not row:
            return None
        return row[0], self.scanTargetType(scanId)

    # ------------------------------------------------------------------ overrides

    def overrideSet(self, scanId: str, hashes: typing.Iterable[str], verdict: str, userId: typing.Optional[int] = None) -> int:
        if verdict not in VERDICTS:
            raise ValueError("verdict must be 'mine' or 'not_related'")
        now = int(time.time())
        data = [(scanId, h, verdict, userId, now) for h in hashes]
        with self.dbhLock:
            try:
                self.dbh.executemany(
                    "INSERT OR REPLACE INTO tbl_relevance_override (scan_id, event_hash, verdict, user_id, created) "
                    "VALUES (?, ?, ?, ?, ?)", data)
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when saving a relevance decision") from e
        return len(data)

    def overrideClear(self, scanId: str, hashes: typing.Iterable[str]) -> int:
        hashes = list(hashes)
        n = 0
        with self.dbhLock:
            try:
                for i in range(0, len(hashes), 500):
                    part = hashes[i:i + 500]
                    self.dbh.execute(
                        "DELETE FROM tbl_relevance_override WHERE scan_id = ? AND event_hash IN (" + ','.join('?' for _ in part) + ")",
                        [scanId] + part)
                    n += self.dbh.rowcount
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when clearing a relevance decision") from e
        return n

    def overrideGet(self, scanId: str) -> dict:
        """{event_hash: 'mine' | 'not_related'}."""
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT event_hash, verdict FROM tbl_relevance_override WHERE scan_id = ?", [scanId])
                return {h: v for h, v in self.dbh.fetchall()}
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading relevance decisions") from e

    # ------------------------------------------------------------------ run status

    RUN_FIELDS = ('status', 'phase', 'progress', 'method', 'calls', 'tokens', 'embedded', 'started', 'ended', 'message', 'counts')

    def relevanceRunGet(self, scanId: str) -> dict:
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT " + ', '.join(self.RUN_FIELDS) + " FROM tbl_relevance_run WHERE scan_id = ?", [scanId])
                row = self.dbh.fetchone()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading the relevance status") from e
        if not row:
            return {'status': 'none', 'phase': '', 'progress': 0.0, 'method': '', 'calls': 0, 'tokens': 0, 'embedded': 0,
                    'started': 0, 'ended': 0, 'message': '', 'counts': {}}
        out = dict(zip(self.RUN_FIELDS, row))
        try:
            out['counts'] = json.loads(out['counts'] or '{}')
        except ValueError:
            out['counts'] = {}
        return out

    def relevanceRunSet(self, scanId: str, **fields) -> None:
        fields = {k: v for k, v in fields.items() if k in self.RUN_FIELDS}
        if 'counts' in fields and not isinstance(fields['counts'], str):
            fields['counts'] = json.dumps(fields['counts'])
        if not fields:
            return
        with self.dbhLock:
            try:
                self.dbh.execute("INSERT OR IGNORE INTO tbl_relevance_run (scan_id) VALUES (?)", [scanId])
                sets = ', '.join(f"{k} = ?" for k in fields)
                self.dbh.execute(f"UPDATE tbl_relevance_run SET {sets} WHERE scan_id = ?", list(fields.values()) + [scanId])
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when saving the relevance status") from e

    def relevanceRunsReconcile(self) -> int:
        """Mark runs that were 'running' or 'queued' when the server stopped as failed (called once at start-up)."""
        with self.dbhLock:
            try:
                self.dbh.execute(
                    "UPDATE tbl_relevance_run SET status = 'failed', message = 'Interrupted by a restart; run it again.', ended = ? "
                    "WHERE status IN ('running', 'queued')", [int(time.time())])
                n = self.dbh.rowcount
                self.conn.commit()
                return n
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reconciling relevance runs") from e

    # ------------------------------------------------------------------ embedding cache

    def embeddingCacheGet(self, model: str, hashes: typing.Iterable[str]) -> dict:
        """{text_hash: vector (list of float)} for the cached ones."""
        hashes = list(hashes)
        out = {}
        with self.dbhLock:
            try:
                for i in range(0, len(hashes), 500):
                    part = hashes[i:i + 500]
                    self.dbh.execute(
                        "SELECT text_hash, vec FROM tbl_embedding_cache WHERE model = ? AND text_hash IN ("
                        + ','.join('?' for _ in part) + ")", [model] + part)
                    for h, blob in self.dbh.fetchall():
                        a = array.array('f')
                        a.frombytes(blob)
                        out[h] = list(a)
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading the embedding cache") from e
        return out

    def embeddingCachePut(self, model: str, items: typing.Dict[str, list]) -> None:
        now = int(time.time())
        data = [(model, h, len(v), array.array('f', v).tobytes(), now) for h, v in items.items() if v]
        if not data:
            return
        with self.dbhLock:
            try:
                self.dbh.executemany(
                    "INSERT OR REPLACE INTO tbl_embedding_cache (model, text_hash, dim, vec, created) VALUES (?, ?, ?, ?, ?)", data)
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when writing the embedding cache") from e

    def embeddingCachePrune(self, keep: int = 200000) -> None:
        """Keep the newest ``keep`` cached vectors."""
        with self.dbhLock:
            try:
                self.dbh.execute(
                    "DELETE FROM tbl_embedding_cache WHERE rowid IN (SELECT rowid FROM tbl_embedding_cache "
                    "ORDER BY created DESC LIMIT -1 OFFSET ?)", [keep])
                self.conn.commit()
            except sqlite3.Error:
                pass

    def relevanceDeleteScan(self, scanId: str) -> None:
        """Remove everything relevance related for a deleted scan (the embedding cache is shared and stays)."""
        with self.dbhLock:
            for table, col in (('tbl_event_relevance', 'scan_id'), ('tbl_scan_context', 'scan_id'),
                               ('tbl_relevance_override', 'scan_id'), ('tbl_relevance_run', 'scan_id')):
                try:
                    self.dbh.execute(f"DELETE FROM {table} WHERE {col} = ?", [scanId])
                except sqlite3.Error:
                    pass   # an older database that has not been migrated yet
