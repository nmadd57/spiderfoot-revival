# -*- coding: utf-8 -*-
"""Database support for users, scan access control and personal MCP tokens.

Mixed into :class:`spiderfoot.db.SpiderFootDb`. The tables are created (and an ``owner`` column is
added to ``tbl_scan_instance``) idempotently every time a database is opened, so existing databases
are migrated in place and no data is touched.
"""

import json
import sqlite3
import time
import typing

LEVELS = ('view', 'edit')
PRINCIPAL_TYPES = ('user', 'group')

# Settings that must survive "reset to default" (wiping them could open the application up).
PRESERVED_CONFIG_PREFIXES = ('_oidc_', '_auth_')

# Settings of the retired shared MCP token; removed on migration.
LEGACY_MCP_KEYS = ('_mcp_token_hash', '_mcp_token_hint', '_mcp_token_created')


class IdentityDbMixin:
    identitySchemaQueries = [
        "CREATE TABLE IF NOT EXISTS tbl_users ( \
            id            INTEGER PRIMARY KEY AUTOINCREMENT, \
            subject       TEXT NOT NULL UNIQUE, \
            username      TEXT NOT NULL DEFAULT '', \
            email         TEXT NOT NULL DEFAULT '', \
            display_name  TEXT NOT NULL DEFAULT '', \
            groups        TEXT NOT NULL DEFAULT '[]', \
            role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin','user')), \
            created       INTEGER NOT NULL DEFAULT 0, \
            last_login    INTEGER NOT NULL DEFAULT 0 \
        )",
        "CREATE TABLE IF NOT EXISTS tbl_scan_acl ( \
            scan_id        TEXT NOT NULL, \
            principal_type TEXT NOT NULL CHECK (principal_type IN ('user','group')), \
            principal      TEXT NOT NULL, \
            level          TEXT NOT NULL CHECK (level IN ('view','edit')), \
            granted_by     INTEGER, \
            created        INTEGER NOT NULL DEFAULT 0, \
            UNIQUE (scan_id, principal_type, principal) \
        )",
        "CREATE INDEX IF NOT EXISTS idx_scan_acl_scan ON tbl_scan_acl (scan_id)",
        "CREATE TABLE IF NOT EXISTS tbl_mcp_tokens ( \
            id        INTEGER PRIMARY KEY AUTOINCREMENT, \
            user_id   INTEGER NOT NULL, \
            name      TEXT NOT NULL DEFAULT '', \
            hash      TEXT NOT NULL UNIQUE, \
            hint      TEXT NOT NULL DEFAULT '', \
            created   INTEGER NOT NULL DEFAULT 0, \
            last_used INTEGER NOT NULL DEFAULT 0, \
            expires   INTEGER \
        )",
        "CREATE INDEX IF NOT EXISTS idx_mcp_tokens_user ON tbl_mcp_tokens (user_id)",
    ]

    def _migrate_identity(self) -> None:
        """Create the identity tables and the scan owner column when missing (idempotent)."""
        try:
            for query in self.identitySchemaQueries:
                self.dbh.execute(query)
            self.dbh.execute("PRAGMA table_info(tbl_scan_instance)")
            columns = [row[1] for row in self.dbh.fetchall()]
            if 'owner' not in columns:
                self.dbh.execute("ALTER TABLE tbl_scan_instance ADD COLUMN owner INTEGER")
            self.dbh.execute("CREATE INDEX IF NOT EXISTS idx_scan_instance_owner ON tbl_scan_instance (owner)")
            marks = ','.join('?' for _ in LEGACY_MCP_KEYS)
            self.dbh.execute(f"DELETE FROM tbl_config WHERE scope = 'GLOBAL' AND opt IN ({marks})", LEGACY_MCP_KEYS)
            self.conn.commit()
        except sqlite3.Error as e:
            raise IOError("Failed to migrate the database for users and scan access control") from e

    # ------------------------------------------------------------------ settings

    def configGetPrefix(self, prefixes: typing.Iterable[str]) -> dict:
        """Global settings whose name starts with one of ``prefixes`` (cheap; avoids reading every setting)."""
        clauses = ' OR '.join("opt LIKE ? ESCAPE '\\'" for _ in prefixes)
        args = [p.replace('\\', '\\\\').replace('_', '\\_').replace('%', '\\%') + '%' for p in prefixes]
        if not args:
            return {}
        with self.dbhLock:
            try:
                self.dbh.execute(f"SELECT opt, val FROM tbl_config WHERE scope = 'GLOBAL' AND ({clauses})", args)
                return {opt: val for opt, val in self.dbh.fetchall()}
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching configuration") from e

    # ------------------------------------------------------------------ scan owner

    def scanOwnerGet(self, instanceId: str) -> typing.Optional[int]:
        """Owner (user id) of a scan, None when the scan has no owner or does not exist."""
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT owner FROM tbl_scan_instance WHERE guid = ?", [instanceId])
                row = self.dbh.fetchone()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching the scan owner") from e
        return row[0] if row else None

    def scanExists(self, instanceId: str) -> bool:
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT 1 FROM tbl_scan_instance WHERE guid = ?", [instanceId])
                return self.dbh.fetchone() is not None
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when looking up a scan") from e

    def scanOwnerSet(self, instanceId: str, owner: typing.Optional[int]) -> None:
        with self.dbhLock:
            try:
                self.dbh.execute("UPDATE tbl_scan_instance SET owner = ? WHERE guid = ?", [owner, instanceId])
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when setting the scan owner") from e

    def scanOwners(self) -> dict:
        """{scan id: owner user id or None} for every scan."""
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT guid, owner FROM tbl_scan_instance")
                return {guid: owner for guid, owner in self.dbh.fetchall()}
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching scan owners") from e

    def scanOwnerOfCorrelation(self, correlationId: str) -> typing.Optional[str]:
        """The scan a correlation result belongs to."""
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT scan_instance_id FROM tbl_scan_correlation_results WHERE id = ?", [correlationId])
                row = self.dbh.fetchone()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching a correlation") from e
        return row[0] if row else None

    # ------------------------------------------------------------------ users

    _USER_COLUMNS = "id, subject, username, email, display_name, groups, role, created, last_login"

    @staticmethod
    def _user_row(row) -> dict:
        try:
            groups = json.loads(row[5] or '[]')
        except ValueError:
            groups = []
        return {'id': row[0], 'subject': row[1], 'username': row[2], 'email': row[3], 'display_name': row[4],
                'groups': [str(g) for g in groups] if isinstance(groups, list) else [],
                'role': row[6], 'created': row[7], 'last_login': row[8]}

    def userGet(self, userId: int) -> typing.Optional[dict]:
        with self.dbhLock:
            try:
                self.dbh.execute(f"SELECT {self._USER_COLUMNS} FROM tbl_users WHERE id = ?", [userId])
                row = self.dbh.fetchone()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching a user") from e
        return self._user_row(row) if row else None

    def userGetBySubject(self, subject: str) -> typing.Optional[dict]:
        with self.dbhLock:
            try:
                self.dbh.execute(f"SELECT {self._USER_COLUMNS} FROM tbl_users WHERE subject = ?", [subject])
                row = self.dbh.fetchone()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching a user") from e
        return self._user_row(row) if row else None

    def userList(self) -> list:
        with self.dbhLock:
            try:
                self.dbh.execute(f"SELECT {self._USER_COLUMNS} FROM tbl_users ORDER BY lower(display_name), lower(username), id")
                return [self._user_row(r) for r in self.dbh.fetchall()]
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when listing users") from e

    def userUpsert(self, subject: str, username: str = '', email: str = '', display_name: str = '',
                   groups: typing.Optional[list] = None, role: str = 'user', login: bool = True) -> dict:
        """Create the user for ``subject`` or refresh its profile and groups; returns the stored row.

        ``login`` records the time as the last login. The role is the one computed at this login.
        """
        if role not in ('admin', 'user'):
            raise ValueError("role must be 'admin' or 'user'")
        now = int(time.time())
        groups_json = json.dumps(sorted({str(g) for g in (groups or []) if str(g)}))
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT id FROM tbl_users WHERE subject = ?", [subject])
                row = self.dbh.fetchone()
                if row:
                    self.dbh.execute(
                        "UPDATE tbl_users SET username = ?, email = ?, display_name = ?, groups = ?, role = ?, "
                        "last_login = CASE WHEN ? THEN ? ELSE last_login END WHERE id = ?",
                        [username, email, display_name, groups_json, role, 1 if login else 0, now, row[0]])
                else:
                    self.dbh.execute(
                        "INSERT INTO tbl_users (subject, username, email, display_name, groups, role, created, last_login) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        [subject, username, email, display_name, groups_json, role, now, now if login else 0])
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when storing a user") from e
        return self.userGetBySubject(subject)

    def userGroups(self) -> list:
        """Every group name seen on a user, sorted."""
        seen = set()
        for user in self.userList():
            seen.update(user['groups'])
        return sorted(seen, key=str.lower)

    # ------------------------------------------------------------------ scan access grants

    def aclList(self, scanId: str) -> list:
        """Grants on a scan: dicts with principal_type, principal, level, granted_by, created."""
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT principal_type, principal, level, granted_by, created FROM tbl_scan_acl "
                                 "WHERE scan_id = ? ORDER BY principal_type, lower(principal)", [scanId])
                return [{'principal_type': r[0], 'principal': r[1], 'level': r[2], 'granted_by': r[3], 'created': r[4]}
                        for r in self.dbh.fetchall()]
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when listing scan grants") from e

    def aclSet(self, scanId: str, principalType: str, principal: str, level: str, grantedBy: typing.Optional[int] = None) -> None:
        if principalType not in PRINCIPAL_TYPES:
            raise ValueError("principal type must be 'user' or 'group'")
        if level not in LEVELS:
            raise ValueError("level must be 'view' or 'edit'")
        if not str(principal).strip():
            raise ValueError("principal is empty")
        with self.dbhLock:
            try:
                self.dbh.execute(
                    "INSERT INTO tbl_scan_acl (scan_id, principal_type, principal, level, granted_by, created) "
                    "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (scan_id, principal_type, principal) "
                    "DO UPDATE SET level = excluded.level, granted_by = excluded.granted_by",
                    [scanId, principalType, str(principal), level, grantedBy, int(time.time())])
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when storing a scan grant") from e

    def aclRemove(self, scanId: str, principalType: str, principal: str) -> bool:
        with self.dbhLock:
            try:
                self.dbh.execute("DELETE FROM tbl_scan_acl WHERE scan_id = ? AND principal_type = ? AND principal = ?",
                                 [scanId, principalType, str(principal)])
                removed = self.dbh.rowcount > 0
                self.conn.commit()
                return removed
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when removing a scan grant") from e

    def aclForPrincipals(self, userId: typing.Optional[int], groups: typing.Iterable[str]) -> dict:
        """{scan id: highest granted level} for a user and groups (grants to the user or any of the groups)."""
        found = {}
        groups = list(groups or [])
        with self.dbhLock:
            try:
                clauses, args = [], []
                if userId is not None:
                    clauses.append("(principal_type = 'user' AND principal = ?)")
                    args.append(str(userId))
                if groups:
                    clauses.append("(principal_type = 'group' AND principal IN (%s))" % ','.join('?' for _ in groups))
                    args.extend(groups)
                if not clauses:
                    return found
                self.dbh.execute("SELECT scan_id, level FROM tbl_scan_acl WHERE " + ' OR '.join(clauses), args)
                rows = self.dbh.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching scan grants") from e
        for scan_id, level in rows:
            if level == 'edit' or found.get(scan_id) != 'edit':
                found[scan_id] = level
        return found

    # ------------------------------------------------------------------ personal MCP tokens

    def mcpTokenCreate(self, userId: int, name: str, tokenHash: str, hint: str, expires: typing.Optional[int] = None) -> int:
        with self.dbhLock:
            try:
                self.dbh.execute("INSERT INTO tbl_mcp_tokens (user_id, name, hash, hint, created, last_used, expires) "
                                 "VALUES (?, ?, ?, ?, ?, 0, ?)", [userId, name, tokenHash, hint, int(time.time()), expires])
                self.conn.commit()
                return self.dbh.lastrowid
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when storing a token") from e

    def mcpTokenList(self, userId: int) -> list:
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT id, name, hint, created, last_used, expires FROM tbl_mcp_tokens "
                                 "WHERE user_id = ? ORDER BY created DESC, id DESC", [userId])
                return [{'id': r[0], 'name': r[1], 'hint': r[2], 'created': r[3], 'last_used': r[4], 'expires': r[5]}
                        for r in self.dbh.fetchall()]
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when listing tokens") from e

    def mcpTokenByHash(self, tokenHash: str) -> typing.Optional[dict]:
        with self.dbhLock:
            try:
                self.dbh.execute("SELECT id, user_id, name, expires, last_used FROM tbl_mcp_tokens WHERE hash = ?", [tokenHash])
                row = self.dbh.fetchone()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when looking up a token") from e
        return {'id': row[0], 'user_id': row[1], 'name': row[2], 'expires': row[3], 'last_used': row[4]} if row else None

    def mcpTokenTouch(self, tokenId: int) -> None:
        with self.dbhLock:
            try:
                self.dbh.execute("UPDATE tbl_mcp_tokens SET last_used = ? WHERE id = ?", [int(time.time()), tokenId])
                self.conn.commit()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when updating a token") from e

    def mcpTokenRevoke(self, userId: int, tokenId: int) -> bool:
        """Delete one of a user's tokens (a user can only ever revoke their own)."""
        with self.dbhLock:
            try:
                self.dbh.execute("DELETE FROM tbl_mcp_tokens WHERE id = ? AND user_id = ?", [tokenId, userId])
                removed = self.dbh.rowcount > 0
                self.conn.commit()
                return removed
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when revoking a token") from e
