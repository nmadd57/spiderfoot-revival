# -*- coding: utf-8 -*-
"""Database support for written scan reports.

Mixed into :class:`spiderfoot.db.SpiderFootDb`. Like the identity and relevance tables, these are created
idempotently every time a database is opened, so existing databases are migrated in place.

Tables:

``tbl_scan_report``  one row per generated report version of a scan: status and progress while it is written,
                     then the markdown, the digests it was written from, the citation index, the model and the usage
``tbl_report_pref``  the per-scan choice made when the scan was started ("write a report when finished": yes / no)
"""

import json
import sqlite3
import time
import typing

STATUSES = ('queued', 'running', 'done', 'failed')
ACTIVE = ('queued', 'running')
TRIGGERS = ('auto', 'manual', 'mcp')

JSON_FIELDS = ('sections', 'digests', 'citations', 'warnings', 'options')
LIGHT_FIELDS = ('id', 'scan_id', 'version', 'status', 'mode', 'trigger', 'phase', 'progress', 'sections_done', 'sections_total',
                'model', 'model_used', 'calls', 'prompt_tokens', 'completion_tokens', 'tokens', 'message', 'scan_status',
                'scan_ended', 'requested_by', 'created', 'started', 'ended')
UPDATABLE = set(LIGHT_FIELDS) - {'id', 'scan_id', 'version', 'created'} | {'markdown'} | set(JSON_FIELDS)


class ReportDbMixin:
    reportSchemaQueries = [
        "CREATE TABLE IF NOT EXISTS tbl_scan_report ( \
            id                INTEGER PRIMARY KEY AUTOINCREMENT, \
            scan_id           TEXT NOT NULL, \
            version           INTEGER NOT NULL, \
            status            TEXT NOT NULL DEFAULT 'queued', \
            mode              TEXT NOT NULL DEFAULT 'ai', \
            trigger           TEXT NOT NULL DEFAULT 'manual', \
            phase             TEXT NOT NULL DEFAULT '', \
            progress          REAL NOT NULL DEFAULT 0, \
            sections_done     INTEGER NOT NULL DEFAULT 0, \
            sections_total    INTEGER NOT NULL DEFAULT 0, \
            model             TEXT NOT NULL DEFAULT '', \
            model_used        TEXT NOT NULL DEFAULT '', \
            calls             INTEGER NOT NULL DEFAULT 0, \
            prompt_tokens     INTEGER NOT NULL DEFAULT 0, \
            completion_tokens INTEGER NOT NULL DEFAULT 0, \
            tokens            INTEGER NOT NULL DEFAULT 0, \
            markdown          TEXT NOT NULL DEFAULT '', \
            sections          TEXT NOT NULL DEFAULT '{}', \
            digests           TEXT NOT NULL DEFAULT '{}', \
            citations         TEXT NOT NULL DEFAULT '{}', \
            warnings          TEXT NOT NULL DEFAULT '[]', \
            options           TEXT NOT NULL DEFAULT '{}', \
            message           TEXT NOT NULL DEFAULT '', \
            scan_status       TEXT NOT NULL DEFAULT '', \
            scan_ended        INTEGER NOT NULL DEFAULT 0, \
            requested_by      INTEGER, \
            created           INTEGER NOT NULL DEFAULT 0, \
            started           INTEGER NOT NULL DEFAULT 0, \
            ended             INTEGER NOT NULL DEFAULT 0, \
            UNIQUE (scan_id, version) \
        )",
        "CREATE INDEX IF NOT EXISTS idx_scan_report_scan ON tbl_scan_report (scan_id, version)",
        "CREATE INDEX IF NOT EXISTS idx_scan_report_status ON tbl_scan_report (status)",
        "CREATE TABLE IF NOT EXISTS tbl_report_pref ( \
            scan_id TEXT PRIMARY KEY, \
            want    INTEGER NOT NULL DEFAULT 1 \
        )",
    ]

    def _migrate_report(self) -> None:
        """Create the report tables when missing (idempotent)."""
        try:
            for query in self.reportSchemaQueries:
                self.dbh.execute(query)
            self.conn.commit()
        except sqlite3.Error as e:
            raise IOError("Failed to migrate the database for scan reports") from e

    # ------------------------------------------------------------------ helpers

    def _report_row(self, names: typing.Sequence[str], row) -> dict:
        out = dict(zip(names, row))
        for k in JSON_FIELDS:
            if k in out:
                try:
                    out[k] = json.loads(out[k] or ('[]' if k == 'warnings' else '{}'))
                except ValueError:
                    out[k] = [] if k == 'warnings' else {}
        return out

    # ------------------------------------------------------------------ preference

    def reportPrefSet(self, scanId: str, want: typing.Optional[bool]) -> None:
        """Record the per-scan choice (None clears it, so the global setting decides)."""
        with self.dbhLock:
            try:
                if want is None:
                    self.dbh.execute("DELETE FROM tbl_report_pref WHERE scan_id = ?", [scanId])
                else:
                    self.dbh.execute("INSERT OR REPLACE INTO tbl_report_pref (scan_id, want) VALUES (?, ?)", [scanId, 1 if want else 0])
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when saving the report preference") from e

    def reportPrefGet(self, scanId: str) -> typing.Optional[bool]:
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT want FROM tbl_report_pref WHERE scan_id = ?", [scanId])
                row = self.dbh.fetchone()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading the report preference") from e
        return None if row is None else bool(row[0])

    # ------------------------------------------------------------------ versions

    def reportCreate(self, scanId: str, trigger: str = 'manual', model: str = '', options: typing.Optional[dict] = None,
                     requestedBy: typing.Optional[int] = None, scanStatus: str = '', scanEnded: int = 0) -> typing.Tuple[dict, bool]:
        """Queue a new report version. Returns (light row, created): when a version of this scan is already queued
        or running nothing is added and that one is returned with created False (one report at a time per scan)."""
        if trigger not in TRIGGERS:
            raise ValueError("unknown trigger")
        cols = ', '.join(LIGHT_FIELDS)
        with self.dbhLock:
            try:
                self.dbh.execute(f"SELECT {cols} FROM tbl_scan_report WHERE scan_id = ? AND status IN ('queued','running') "
                                 "ORDER BY version DESC LIMIT 1", [scanId])
                row = self.dbh.fetchone()
                if row:
                    return self._report_row(LIGHT_FIELDS, row), False
                self.dbh.execute("SELECT COALESCE(MAX(version), 0) FROM tbl_scan_report WHERE scan_id = ?", [scanId])
                version = int(self.dbh.fetchone()[0]) + 1
                self.dbh.execute(
                    "INSERT INTO tbl_scan_report (scan_id, version, status, trigger, model, options, requested_by, scan_status, "
                    "scan_ended, created) VALUES (?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?)",
                    [scanId, version, trigger, model or '', json.dumps(options or {}), requestedBy, scanStatus or '',
                     int(scanEnded or 0), int(time.time())])
                self.conn.commit()
                self.dbh.execute(f"SELECT {cols} FROM tbl_scan_report WHERE scan_id = ? AND version = ?", [scanId, version])
                return self._report_row(LIGHT_FIELDS, self.dbh.fetchone()), True
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when queueing a report") from e

    def reportGet(self, scanId: str, version: typing.Optional[int] = None, onlyDone: bool = False) -> typing.Optional[dict]:
        """A full report row (all columns, JSON decoded). ``version`` None: the newest (the newest finished one with onlyDone)."""
        names = LIGHT_FIELDS + ('markdown',) + JSON_FIELDS
        qry = f"SELECT {', '.join(names)} FROM tbl_scan_report WHERE scan_id = ?"
        args: list = [scanId]
        if version is not None:
            qry += " AND version = ?"
            args.append(int(version))
        if onlyDone:
            qry += " AND status = 'done'"
        qry += " ORDER BY version DESC LIMIT 1"
        with self.dbhLock:
            try:
                self.dbh.execute(qry, args)
                row = self.dbh.fetchone()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading a report") from e
        return self._report_row(names, row) if row else None

    def reportGetById(self, reportId: int) -> typing.Optional[dict]:
        """A full report row by its row id."""
        names = LIGHT_FIELDS + ('markdown',) + JSON_FIELDS
        with self.dbhLock:
            try:
                self.dbh.execute(f"SELECT {', '.join(names)} FROM tbl_scan_report WHERE id = ?", [int(reportId)])
                row = self.dbh.fetchone()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading a report") from e
        return self._report_row(names, row) if row else None

    def reportList(self, scanId: str) -> typing.List[dict]:
        """Light rows of every version of a scan, newest first (no markdown or digests)."""
        with self.dbhLock:
            try:
                self.dbh.execute(f"SELECT {', '.join(LIGHT_FIELDS)} FROM tbl_scan_report WHERE scan_id = ? ORDER BY version DESC", [scanId])
                rows = self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when listing reports") from e
        return [self._report_row(LIGHT_FIELDS, r) for r in rows]

    def reportUpdate(self, reportId: int, **fields) -> None:
        fields = {k: v for k, v in fields.items() if k in UPDATABLE}
        for k in JSON_FIELDS:
            if k in fields and not isinstance(fields[k], str):
                fields[k] = json.dumps(fields[k])
        if not fields:
            return
        sets = ', '.join(f"{k} = ?" for k in fields)
        with self.dbhLock:
            try:
                self.dbh.execute(f"UPDATE tbl_scan_report SET {sets} WHERE id = ?", list(fields.values()) + [int(reportId)])
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when updating a report") from e

    def reportClaim(self, reportId: int) -> bool:
        """queued -> running, atomically. False when somebody else took it."""
        with self.dbhLock:
            try:
                self.dbh.execute("UPDATE tbl_scan_report SET status = 'running', started = ?, message = '' WHERE id = ? AND status = 'queued'",
                                 [int(time.time()), int(reportId)])
                n = self.dbh.rowcount
                self.conn.commit()
                return n == 1
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when claiming a report") from e

    def reportQueued(self, limit: int = 10) -> typing.List[dict]:
        """Light rows of the queued reports, oldest first."""
        with self.dbhLock:
            try:
                self.dbh.execute(f"SELECT {', '.join(LIGHT_FIELDS)} FROM tbl_scan_report WHERE status = 'queued' ORDER BY id LIMIT ?", [int(limit)])
                rows = self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading the report queue") from e
        return [self._report_row(LIGHT_FIELDS, r) for r in rows]

    def reportRunningCount(self) -> int:
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT COUNT(*) FROM tbl_scan_report WHERE status = 'running'")
                return int(self.dbh.fetchone()[0])
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when counting running reports") from e

    def reportDelete(self, scanId: str, version: int) -> int:
        """Delete one version (a queued or running one cannot be deleted). Returns the rows removed."""
        with self.dbhLock:
            try:
                self.dbh.execute("DELETE FROM tbl_scan_report WHERE scan_id = ? AND version = ? AND status NOT IN ('queued','running')",
                                 [scanId, int(version)])
                n = self.dbh.rowcount
                self.conn.commit()
                return n
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when deleting a report") from e

    def reportPrune(self, scanId: str, keep: int) -> int:
        """Keep the newest ``keep`` finished or failed versions of a scan (queued and running ones are never touched)."""
        keep = max(1, int(keep))
        with self.dbhLock:
            try:
                self.dbh.execute(
                    "DELETE FROM tbl_scan_report WHERE scan_id = ? AND status IN ('done','failed') AND version NOT IN ("
                    "SELECT version FROM tbl_scan_report WHERE scan_id = ? AND status IN ('done','failed') ORDER BY version DESC LIMIT ?)",
                    [scanId, scanId, keep])
                n = self.dbh.rowcount
                self.conn.commit()
                return n
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when pruning reports") from e

    def reportReadyMap(self, scanIds: typing.Iterable[str]) -> typing.Dict[str, int]:
        """{scan id: newest finished version} for the scans that have a report (for the "Report ready" badges)."""
        ids = list(scanIds)
        out: typing.Dict[str, int] = {}
        with self.dbhLock:
            try:
                for i in range(0, len(ids), 500):
                    part = ids[i:i + 500]
                    self.dbh.execute("SELECT scan_id, MAX(version) FROM tbl_scan_report WHERE status = 'done' AND scan_id IN ("
                                     + ','.join('?' for _ in part) + ") GROUP BY scan_id", part)
                    out.update({s: int(v) for s, v in self.dbh.fetchall()})
            except sqlite3.Error:
                return {}
        return out

    def reportReconcile(self) -> int:
        """Reports that were 'running' when the server stopped go back to the queue (finished sections are kept and reused)."""
        with self.dbhLock:
            try:
                self.dbh.execute("UPDATE tbl_scan_report SET status = 'queued', phase = 'resuming', "
                                 "message = 'Resumed after a restart.' WHERE status = 'running'")
                n = self.dbh.rowcount
                self.conn.commit()
                return n
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reconciling reports") from e

    def reportDeleteScan(self, scanId: str) -> None:
        """Remove every report row of a deleted scan."""
        with self.dbhLock:
            for table in ('tbl_scan_report', 'tbl_report_pref'):
                try:
                    self.dbh.execute(f"DELETE FROM {table} WHERE scan_id = ?", [scanId])
                except sqlite3.Error:
                    pass   # an older database that has not been migrated yet

    # ------------------------------------------------------------------ reading a scan for the digests

    def reportEvents(self, scanId: str, dataLimit: int = 700) -> list:
        """Every event of a scan as (hash, type, module, data cut to ``dataLimit`` characters, data length, source hash,
        generated, risk, confidence, false_positive). Raw records are not read in full."""
        with self.dbhLock:
            try:
                self.dbh.execute(
                    "SELECT hash, type, module, substr(data, 1, ?), length(data), source_event_hash, generated, risk, confidence, "
                    "false_positive FROM tbl_scan_results WHERE scan_instance_id = ?", [int(dataLimit), scanId])
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading the events for a report") from e

    def reportEventsByHash(self, scanId: str, hashes: typing.Iterable[str], dataLimit: int = 2000) -> dict:
        """{hash: (type, module, data cut to ``dataLimit``, source hash, generated, risk, confidence)} for some events."""
        hashes = list(hashes)
        out = {}
        with self.dbhLock:
            try:
                for i in range(0, len(hashes), 400):
                    part = hashes[i:i + 400]
                    self.dbh.execute(
                        "SELECT hash, type, module, substr(data, 1, ?), source_event_hash, generated, risk, confidence FROM tbl_scan_results "
                        "WHERE scan_instance_id = ? AND hash IN (" + ','.join('?' for _ in part) + ")", [int(dataLimit), scanId] + part)
                    for r in self.dbh.fetchall():
                        out.setdefault(r[0], r[1:])
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading events for a report") from e
        return out

    def reportLogProblems(self, scanId: str) -> list:
        """(component, type, message, count) of the ERROR and WARNING log lines of a scan, grouped, most frequent first."""
        with self.dbhLock:
            try:
                self.dbh.execute(
                    "SELECT component, type, substr(message, 1, 300), COUNT(*) FROM tbl_scan_log WHERE scan_instance_id = ? "
                    "AND type IN ('ERROR', 'WARNING', 'CRITICAL') GROUP BY component, type, substr(message, 1, 300) "
                    "ORDER BY COUNT(*) DESC LIMIT 400", [scanId])
                return self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when reading the scan log for a report") from e

    def reportModuleCounts(self, scanId: str) -> dict:
        """{module: number of events} of a scan."""
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT module, COUNT(*) FROM tbl_scan_results WHERE scan_instance_id = ? GROUP BY module", [scanId])
                return {m: n for m, n in self.dbh.fetchall()}
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when counting events per module") from e

    def reportCorrelations(self, scanId: str) -> list:
        """(id, title, rule id, risk, description, event count) of the correlation results of a scan (empty on older databases)."""
        with self.dbhLock:
            try:
                self.dbh.execute(
                    "SELECT c.id, c.title, c.rule_id, c.rule_risk, c.rule_descr, "
                    "(SELECT COUNT(*) FROM tbl_scan_correlation_results_events e WHERE e.correlation_id = c.id) "
                    "FROM tbl_scan_correlation_results c WHERE c.scan_instance_id = ? ORDER BY c.rule_risk, c.title", [scanId])
                return self.dbh.fetchall()
            except sqlite3.Error:
                return []
