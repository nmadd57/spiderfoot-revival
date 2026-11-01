"""Detection of external-tool modules (sfp_tool_*) whose binary is not installed."""

import os
import shutil

_NOT_BINARY = ('template', 'python', 'node', 'ruby')
_ALIASES = {'testsslsh': ('testssl.sh', 'testssl'), 'retirejs': ('retire',), 'dnstwist': ('dnstwist', 'dnstwist.py')}


def _tool_opt(opts: dict):
    for k in opts:
        kl = k.lower()
        if kl.endswith('path') and not any(kl.startswith(x) for x in _NOT_BINARY):
            return k
    return None


def tool_installed(mod_name: str, opts: dict, saved_config: dict) -> bool:
    """True if the tool a ``sfp_tool_*`` module drives can be found.

    Uses the module's own path option (saved value, else default); when that is
    empty the tool must be on PATH. Modules without a recognisable path option
    are assumed to be fine.
    """
    opt = _tool_opt(opts)
    if not opt:
        return True
    val = str(saved_config.get(f'{mod_name}:{opt}', '') or opts.get(opt, '') or '').strip()
    if val:
        return os.path.isdir(val) if val.endswith('/') else os.path.isfile(val)
    base = opt.lower().replace('_', '')[:-4]
    names = _ALIASES.get(base, (base, base + '.py'))
    return any(shutil.which(n) for n in names)
