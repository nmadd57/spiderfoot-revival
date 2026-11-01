"""Global per-module state kept in the GLOBAL config.

Two comma-separated lists are stored:

* ``_disabled_modules``    - modules that are hidden from New Scan and never run.
* ``_default_off_modules`` - modules that stay available but are not pre-selected
                             on New Scan.
"""

KEY = '_disabled_modules'
DEFAULT_OFF_KEY = '_default_off_modules'
KINDS = {'disabled': KEY, 'default_off': DEFAULT_OFF_KEY}


def parse(value) -> set:
    return {m.strip() for m in (value or '').split(',') if m.strip()}


def get_names(dbh, key: str = KEY) -> set:
    try:
        return parse(dbh.configGet().get(key, ''))
    except Exception:
        return set()


def set_names(dbh, names, key: str = KEY) -> None:
    dbh.configSet({key: ','.join(sorted(set(names)))})


# Backwards-compatible helpers for the "disabled" list.
def get_disabled(dbh) -> set:
    return get_names(dbh, KEY)


def set_disabled(dbh, names) -> None:
    set_names(dbh, names, KEY)
