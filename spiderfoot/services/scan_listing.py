"""Owner names and the viewer's relation to each scan, for scan lists (dashboard, table fragment, JSON)."""

from spiderfoot.services import access


def annotate(scan_ids, user, dbh, settings) -> dict:
    """{scan id: {'owner': name or '', 'owner_id', 'level': 'view'|'edit'|'owner', 'relation': 'mine'|'shared'|'other'}}."""
    ids = list(scan_ids)
    owners = dbh.scanOwners() if ids else {}
    names = {}
    if any(owners.get(i) is not None for i in ids):
        for u in dbh.userList():
            names[u['id']] = u['display_name'] or u['username'] or u['subject']
    levels = access.scan_levels(user, dbh, settings.unowned_visible)
    out = {}
    for sid in ids:
        owner = owners.get(sid)
        level = access.OWNER if levels is None else levels.get(sid, access.NONE)
        out[sid] = {
            'owner': names.get(owner, '') if owner is not None else '',
            'owner_id': owner,
            'unowned': owner is None,
            'level': access.level_name(level),
            'relation': access.relation(user, owner, level),
        }
    return out


def matches_filter(entry: dict, which: str) -> bool:
    """The dashboard filter: 'mine', 'shared' (shared with me) or anything else for all."""
    if which == 'mine':
        return entry['relation'] == 'mine'
    if which == 'shared':
        return entry['relation'] == 'shared'
    return True
