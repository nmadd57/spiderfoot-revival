"""The group registry: which identity-provider groups are administrators and which are plain users.

The registry is a list of ``{name, role, description, added_by, added}`` stored as JSON in the config option
``_oidc_groups``. Names are matched exactly (case-sensitive) against the values of the provider's ``groups``
claim after trimming surrounding whitespace. Everything here is pure (no Flask, no database) so it can be
tested exhaustively; ``services/identity.py`` and ``blueprints/access.py`` do the loading and saving.

Role of a signed-in account (``resolve``): ``admin`` when any of its groups is registered as admin, else
``user`` when any is registered as user, else the *default role* for unlisted accounts. The default role is
the setting ``_oidc_default_role``: ``user``, ``none`` (denied) or empty ("automatic"). Automatic keeps what
the two old comma lists did: unlisted accounts are users while no user-role group is registered and are
turned away as soon as one is.
"""

import json
import re
import time
import typing

ROLE_ADMIN = 'admin'
ROLE_USER = 'user'
ROLES = (ROLE_ADMIN, ROLE_USER)
ROLE_DENIED = 'denied'

NAME_MAX = 100
DESCRIPTION_MAX = 200
MAX_GROUPS = 500
MAX_DENIED = 100
DENIED_REFRESH = 24 * 3600

DEFAULT_AUTO, DEFAULT_USER, DEFAULT_NONE = '', 'user', 'none'
DEFAULT_ROLES = (DEFAULT_AUTO, DEFAULT_USER, DEFAULT_NONE)

_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f  ]')


class GroupError(ValueError):
    """A registry change that was refused; the message is safe to show to the administrator."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------------------------ names and entries

def clean_name(raw) -> str:
    """A valid group name (trimmed) or GroupError."""
    if not isinstance(raw, str):
        raise GroupError('Enter a group name.')
    name = raw.strip()
    if not name:
        raise GroupError('Enter a group name.')
    if len(name) > NAME_MAX:
        raise GroupError(f'A group name can have at most {NAME_MAX} characters.')
    if _CONTROL.search(name):
        raise GroupError('A group name cannot contain control characters.')
    if ',' in name:
        raise GroupError('A group name cannot contain a comma.')
    return name


def clean_role(raw) -> str:
    role = str(raw or '').strip().lower() if isinstance(raw, str) else ''
    if role not in ROLES:
        raise GroupError("The role must be 'admin' or 'user'.")
    return role


def clean_description(raw) -> str:
    if raw is None:
        return ''
    if not isinstance(raw, str):
        raise GroupError('The description is not valid.')
    text = raw.strip()
    if len(text) > DESCRIPTION_MAX:
        raise GroupError(f'The description can have at most {DESCRIPTION_MAX} characters.')
    if _CONTROL.search(text):
        raise GroupError('The description cannot contain control characters.')
    return text


def _entry(name, role, description='', added_by='', added=0) -> dict:
    return {'name': name, 'role': role, 'description': description, 'added_by': str(added_by or '')[:200],
            'added': int(added or 0)}


def normalise(entries) -> list:
    """Valid entries only, one per name (an admin entry beats a user entry for the same name), in a stable order."""
    best = {}
    for item in entries if isinstance(entries, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            name, role = clean_name(item.get('name')), clean_role(item.get('role'))
            description = clean_description(item.get('description') or '')
        except GroupError:
            continue
        added = item.get('added')
        added = int(added) if isinstance(added, (int, float)) and not isinstance(added, bool) else 0
        entry = _entry(name, role, description, item.get('added_by') if isinstance(item.get('added_by'), str) else '', added)
        if name not in best or (role == ROLE_ADMIN and best[name]['role'] != ROLE_ADMIN):
            best[name] = entry
    return list(best.values())[:MAX_GROUPS]


# ------------------------------------------------------------------------------ storage format

def parse(text) -> typing.Tuple[typing.Optional[list], bool]:
    """(registry, readable). ``registry`` is None when nothing is stored; an unreadable value is (None, False)."""
    if text is None or str(text).strip() == '':
        return None, True
    try:
        data = json.loads(str(text))
    except ValueError:
        return None, False
    if not isinstance(data, list):
        return None, False
    return normalise(data), True


def dumps(registry: list) -> str:
    return json.dumps(normalise(registry), separators=(',', ':'), sort_keys=True)


def split_names(text) -> list:
    """A comma (or newline) separated list of group names, without blanks, duplicates or invalid names."""
    if isinstance(text, (list, tuple, set)):
        parts = [str(p) for p in text]
    else:
        parts = str(text or '').replace('\n', ',').split(',')
    out = []
    for part in parts:
        try:
            name = clean_name(part)
        except GroupError:
            continue
        if name not in out:
            out.append(name)
    return out


def seed(admin_names, user_names, added_by: str, now: typing.Optional[int] = None) -> list:
    """Registry entries for two name lists (the old settings, or environment seeds). Admin wins on a clash."""
    now = int(time.time() if now is None else now)
    entries = [_entry(n, ROLE_ADMIN, '', added_by, now) for n in split_names(admin_names)]
    taken = {e['name'] for e in entries}
    entries += [_entry(n, ROLE_USER, '', added_by, now) for n in split_names(user_names) if n not in taken]
    return entries


def merge_missing(registry: list, extra: list) -> list:
    """``registry`` plus the entries of ``extra`` whose names it does not have."""
    have = {e['name'] for e in registry}
    return registry + [e for e in extra if e['name'] not in have]


def effective(stored: typing.Optional[list], readable: bool, legacy_admin, legacy_user, env_admin, env_user,
              now: typing.Optional[int] = None) -> typing.Tuple[list, str]:
    """The registry in force and where it comes from: ``stored``, ``migrated`` or ``unreadable``.

    * nothing stored: built from the old ``_oidc_admin_groups`` / ``_oidc_user_groups`` options and the
      ``SF_OIDC_ADMIN_GROUPS`` / ``SF_OIDC_USER_GROUPS`` seeds;
    * stored but empty: the environment seeds apply (they only count while the registry is empty);
    * stored: used as is;
    * unreadable: empty (and ``resolve`` turns everybody away).
    """
    if not readable:
        return [], 'unreadable'
    env = seed(env_admin, env_user, 'environment', now)
    if stored is None:
        old = seed(legacy_admin, legacy_user, 'migrated', now)
        return normalise(merge_missing(old, env)), 'migrated'
    if not stored:
        return normalise(env), 'stored'
    return stored, 'stored'


# ------------------------------------------------------------------------------ roles

def default_role_setting(raw) -> str:
    raw = str(raw or '').strip().lower()
    return raw if raw in DEFAULT_ROLES else DEFAULT_AUTO


def effective_default(setting: str, registry: list, readable: bool = True) -> str:
    """'user' or 'none': what an authenticated account without a registered group is."""
    if not readable:
        return DEFAULT_NONE
    setting = default_role_setting(setting)
    if setting:
        return setting
    return DEFAULT_NONE if any(e['role'] == ROLE_USER for e in registry) else DEFAULT_USER


def resolve(groups: typing.Iterable[str], registry: list, default: str) -> str:
    """'admin', 'user' or 'denied' for an account in ``groups`` (exact, case-sensitive, trimmed names)."""
    roles = {e['name']: e['role'] for e in registry}
    best = None
    for group in groups or []:
        role = roles.get(str(group).strip())
        if role == ROLE_ADMIN:
            return ROLE_ADMIN
        if role == ROLE_USER:
            best = ROLE_USER
    if best:
        return best
    return ROLE_USER if default == DEFAULT_USER else ROLE_DENIED


# ------------------------------------------------------------------------------ changes

def add(registry: list, name, role, description, added_by: str, now: typing.Optional[int] = None) -> list:
    name, role, description = clean_name(name), clean_role(role), clean_description(description)
    if any(e['name'] == name for e in registry):
        raise GroupError('That group is already registered.', 409)
    if len(registry) >= MAX_GROUPS:
        raise GroupError('Too many groups are registered.')
    return registry + [_entry(name, role, description, added_by, int(time.time() if now is None else now))]


def change(registry: list, name, role=None, description=None) -> list:
    """The registry with the role and/or description of one group changed."""
    name = clean_name(name)
    out, found = [], False
    for e in registry:
        if e['name'] == name:
            found = True
            e = dict(e)
            if role is not None:
                e['role'] = clean_role(role)
            if description is not None:
                e['description'] = clean_description(description)
        out.append(e)
    if not found:
        raise GroupError('That group is not registered.', 404)
    return out


def remove(registry: list, name) -> list:
    name = clean_name(name)
    out = [e for e in registry if e['name'] != name]
    if len(out) == len(registry):
        raise GroupError('That group is not registered.', 404)
    return out


def names(registry: list, role: str) -> list:
    return [e['name'] for e in registry if e['role'] == role]


# ------------------------------------------------------------------------------ seen at sign-in

def note_denied(stored_text, groups: typing.Iterable[str], now: typing.Optional[int] = None) -> typing.Optional[str]:
    """JSON for ``_oidc_denied_groups`` after a refused sign-in, or None when nothing needs saving.

    Remembers group names of refused accounts (name -> last seen) so the administrator can register them
    later. Bounded: at most ``MAX_DENIED`` names, newest kept. A name is rewritten at most once a day.
    """
    now = int(time.time() if now is None else now)
    try:
        current = json.loads(stored_text) if stored_text else {}
    except ValueError:
        current = {}
    current = {k: v for k, v in current.items() if isinstance(k, str) and isinstance(v, int)} if isinstance(current, dict) else {}
    changed = False
    for group in list(groups or [])[:50]:
        try:
            name = clean_name(group)
        except GroupError:
            continue
        if name not in current or now - current[name] > DENIED_REFRESH:
            current[name] = now
            changed = True
    if not changed:
        return None
    if len(current) > MAX_DENIED:
        keep = sorted(current.items(), key=lambda kv: kv[1], reverse=True)[:MAX_DENIED]
        current = dict(keep)
    return json.dumps(current, separators=(',', ':'), sort_keys=True)


def denied_names(stored_text) -> dict:
    try:
        data = json.loads(stored_text) if stored_text else {}
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, int)}
