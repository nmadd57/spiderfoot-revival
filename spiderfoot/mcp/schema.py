"""Argument validation for the tools: the small subset of JSON Schema the tool schemas use.

Supports ``type`` (string, integer, number, boolean, array), ``enum``, ``minLength``/``maxLength``,
``minimum``/``maximum`` (clamped, not rejected), ``maxItems``, ``items``, ``default``, ``required`` and
``additionalProperties: false``. Light coercion is applied because clients often send "10" or "true".
"""

from spiderfoot.mcp.context import ToolError


def _coerce(name, spec, value):
    kind = spec.get('type')
    if kind == 'string':
        if not isinstance(value, str):
            raise ToolError(f"'{name}' must be a string")
        if len(value) > spec.get('maxLength', 10 ** 6):
            raise ToolError(f"'{name}' is too long (maximum {spec['maxLength']} characters)")
        if len(value.strip()) < spec.get('minLength', 0):
            raise ToolError(f"'{name}' must not be empty")
    elif kind == 'integer':
        if isinstance(value, str) and value.strip().lstrip('-').isdigit():
            value = int(value)
        if isinstance(value, float) and value == int(value):
            value = int(value)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ToolError(f"'{name}' must be an integer")
        value = max(spec.get('minimum', value), min(spec.get('maximum', value), value))
    elif kind == 'boolean':
        if isinstance(value, str) and value.lower() in ('true', 'false'):
            value = value.lower() == 'true'
        if not isinstance(value, bool):
            raise ToolError(f"'{name}' must be true or false")
    elif kind == 'array':
        if not isinstance(value, list):
            raise ToolError(f"'{name}' must be an array")
        if len(value) > spec.get('maxItems', 10 ** 6):
            raise ToolError(f"'{name}' has too many items (maximum {spec['maxItems']})")
        item_spec = spec.get('items') or {}
        value = [_coerce(f'{name}[{i}]', item_spec, v) for i, v in enumerate(value)]
    if 'enum' in spec and value not in spec['enum']:
        raise ToolError(f"'{name}' must be one of: {', '.join(str(v) for v in spec['enum'])}")
    return value


def validate(schema: dict, arguments) -> dict:
    """Check ``arguments`` against an object schema; return them with defaults filled in."""
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise ToolError('arguments must be an object')
    props = schema.get('properties', {})
    if schema.get('additionalProperties') is False:
        extra = sorted(set(arguments) - set(props))
        if extra:
            raise ToolError(f"Unknown argument(s): {', '.join(str(e) for e in extra)}. "
                            f"Accepted: {', '.join(props) or 'none'}")
    missing = [r for r in schema.get('required', []) if arguments.get(r) in (None, '')]
    if missing:
        raise ToolError(f"Missing required argument(s): {', '.join(missing)}")
    out = {}
    for name, spec in props.items():
        if arguments.get(name) is not None:
            out[name] = _coerce(name, spec, arguments[name])
        elif 'default' in spec:
            out[name] = spec['default']
    return out
