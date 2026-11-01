"""Global enable/disable state for modules.

Disabled module names are kept in the GLOBAL config key ``_disabled_modules``
as a comma-separated string. Disabled modules are hidden from the new-scan
page and stripped from any scan the API starts.
"""

KEY = '_disabled_modules'


def parse(value) -> set:
    return {m.strip() for m in (value or '').split(',') if m.strip()}


def get_disabled(dbh) -> set:
    try:
        return parse(dbh.configGet().get(KEY, ''))
    except Exception:
        return set()


def set_disabled(dbh, names) -> None:
    # configSet rejects an empty map, but the map always has the one key here.
    dbh.configSet({KEY: ','.join(sorted(set(names)))})
