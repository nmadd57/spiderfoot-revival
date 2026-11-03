import json

from spiderfoot.mcp import protocol, tools

VALID_TYPES = {'string', 'integer', 'number', 'boolean', 'array', 'object'}


def _check_schema(schema, path='schema'):
    """Structural check that a tool schema is a well-formed JSON Schema object."""
    assert isinstance(schema, dict), path
    assert schema.get('type') in VALID_TYPES, path
    if schema['type'] == 'object':
        assert isinstance(schema.get('properties'), dict), path
        assert isinstance(schema.get('required', []), list), path
        assert set(schema.get('required', [])) <= set(schema['properties']), path
        assert schema.get('additionalProperties') is False, path
        for name, sub in schema['properties'].items():
            _check_schema(sub, f'{path}.{name}')
            assert sub.get('description'), f'{path}.{name} needs a description'
    if schema['type'] == 'array':
        _check_schema(schema['items'], path + '[]')
    if 'enum' in schema:
        assert schema['enum'] and all(isinstance(v, (str, int)) for v in schema['enum'])
    if 'default' in schema and 'enum' in schema:
        assert schema['default'] in schema['enum']
    if 'minimum' in schema and 'maximum' in schema:
        assert schema['minimum'] <= schema['maximum']
        if 'default' in schema:
            assert schema['minimum'] <= schema['default'] <= schema['maximum']


class TestInitialize:
    def test_initialize_returns_server_info(self, env):
        resp = env.post(env.rpc('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'x', 'version': '1'}}))
        assert resp.status_code == 200
        assert resp.headers['Content-Type'].startswith('application/json')
        result = resp.get_json()['result']
        assert result['protocolVersion'] == '2025-06-18'
        assert result['capabilities'] == {'tools': {'listChanged': False}}
        assert result['serverInfo']['name'] == 'spiderfoot'
        assert result['serverInfo']['version']
        text = result['instructions']
        for word in ('validate_target', 'create_scan', 'get_scan', 'get_scan_events', 'permission'):
            assert word in text

    def test_version_negotiation(self, env):
        for asked, answer in [('2025-03-26', '2025-03-26'), ('2024-11-05', '2024-11-05'),
                              ('2099-01-01', '2025-06-18'), ('nonsense', '2025-06-18')]:
            result = env.post(env.rpc('initialize', {'protocolVersion': asked})).get_json()['result']
            assert result['protocolVersion'] == answer

    def test_initialize_needs_params(self, env):
        body = env.post(env.rpc('initialize')).get_json()
        assert body['error']['code'] == -32602


class TestMessages:
    def test_ping(self, env):
        assert env.post(env.rpc('ping', rid=7)).get_json() == {'jsonrpc': '2.0', 'id': 7, 'result': {}}

    def test_notifications_get_202_and_no_body(self, env):
        for method in ('notifications/initialized', 'notifications/cancelled', 'notifications/whatever'):
            resp = env.post({'jsonrpc': '2.0', 'method': method})
            assert resp.status_code == 202
            assert resp.get_data() == b''

    def test_client_response_is_accepted(self, env):
        assert env.post({'jsonrpc': '2.0', 'id': 3, 'result': {}}).status_code == 202

    def test_batch(self, env):
        batch = [env.rpc('ping', rid=1), {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                 env.rpc('nope', rid='b'), env.rpc('tools/list', rid=3)]
        resp = env.post(batch)
        assert resp.status_code == 200
        body = resp.get_json()
        assert [m['id'] for m in body] == [1, 'b', 3]
        assert body[1]['error']['code'] == -32601
        assert 'tools' in body[2]['result']

    def test_batch_of_notifications_only(self, env):
        assert env.post([{'jsonrpc': '2.0', 'method': 'notifications/initialized'}]).status_code == 202

    def test_empty_batch_is_invalid(self, env):
        resp = env.post([])
        assert resp.status_code == 400
        assert resp.get_json()['error']['code'] == -32600

    def test_malformed_json(self, env):
        resp = env.post(None, raw='{"jsonrpc": ')
        assert resp.status_code == 400
        assert resp.get_json()['error']['code'] == -32700

    def test_invalid_utf8(self, env):
        resp = env.post(None, raw=b'\xff\xfe')
        assert resp.get_json()['error']['code'] == -32700

    def test_invalid_requests(self, env):
        for bad in ({'id': 1, 'method': 'ping'}, {'jsonrpc': '2.0', 'id': 1, 'method': 5}, 'text', 5,
                    {'jsonrpc': '2.0', 'id': True, 'method': 'ping'}, {'jsonrpc': '2.0', 'id': 1, 'method': 'ping', 'params': 5}):
            body = env.post(bad).get_json()
            assert body['error']['code'] == -32600, bad

    def test_oversize_body(self, env):
        resp = env.post(None, raw='{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"' + 'a' * 262144 + '"}}')
        assert resp.status_code == 413

    def test_unknown_methods(self, env):
        for method in ('resources/list', 'resources/read', 'prompts/list', 'prompts/get', 'completion/complete', 'foo'):
            error = env.post(env.rpc(method)).get_json()['error']
            assert error['code'] == -32601, method

    def test_unknown_tool_is_invalid_params(self, env):
        assert env.post(env.rpc('tools/call', {'name': 'drop_tables'})).get_json()['error']['code'] == -32602
        assert env.post(env.rpc('tools/call', {})).get_json()['error']['code'] == -32602

    def test_internal_error_has_no_details(self, env):
        from unittest import mock
        with mock.patch.object(tools, 'definitions', side_effect=RuntimeError('secret-stack-detail')):
            body = env.post(env.rpc('tools/list')).get_json()
        assert body['error']['code'] == -32603
        assert 'secret-stack-detail' not in json.dumps(body)


class TestToolList:
    def test_names_and_schemas(self, env):
        listed = env.post(env.rpc('tools/list')).get_json()['result']['tools']
        names = [t['name'] for t in listed]
        assert names == ['list_modules', 'get_module', 'list_presets', 'suggest_modules', 'validate_target', 'list_event_types',
                         'list_scans', 'get_scan', 'get_scan_summary', 'get_scan_events', 'get_scan_correlations', 'get_scan_log',
                         'get_scan_report', 'create_scan', 'stop_scan', 'rerun_scan', 'reassess_relevance', 'generate_scan_report',
                         'mark_event', 'delete_scan']
        for t in listed:
            assert len(t['description']) > 60, t['name']
            _check_schema(t['inputSchema'], t['name'])
            ann = t['annotations']
            assert {'readOnlyHint', 'destructiveHint', 'idempotentHint'} <= set(ann)

    def test_annotations(self, env):
        by_name = {t['name']: t['annotations'] for t in env.post(env.rpc('tools/list')).get_json()['result']['tools']}
        for name in ('list_modules', 'get_scan', 'get_scan_events', 'validate_target'):
            assert by_name[name]['readOnlyHint'] is True and by_name[name]['destructiveHint'] is False
        assert by_name['delete_scan']['destructiveHint'] is True and by_name['delete_scan']['readOnlyHint'] is False
        assert by_name['create_scan']['readOnlyHint'] is False and by_name['create_scan']['idempotentHint'] is False
        assert by_name['stop_scan']['destructiveHint'] is False

    def test_no_secret_or_sql_tools(self, env):
        names = ' '.join(t['name'] for t in env.post(env.rpc('tools/list')).get_json()['result']['tools'])
        for word in ('key', 'setting', 'config', 'sql', 'query', 'passwd', 'enable', 'option'):
            assert word not in names

    def test_tool_result_shape(self, env):
        result = env.post(env.rpc('tools/call', {'name': 'list_event_types', 'arguments': {}})).get_json()['result']
        assert result['isError'] is False
        assert result['content'][0]['type'] == 'text'
        assert json.loads(result['content'][0]['text']) == result['structuredContent']
        assert ' ' not in result['content'][0]['text'].split('"total"')[0]  # compact JSON

    def test_tool_failure_is_a_result_not_a_protocol_error(self, env):
        body = env.post(env.rpc('tools/call', {'name': 'get_scan', 'arguments': {'scan_id': 'NOPE'}})).get_json()
        assert 'error' not in body
        assert body['result']['isError'] is True
        assert 'does not exist' in body['result']['content'][0]['text']

    def test_bad_arguments_are_tool_errors(self, env):
        for args in ({}, {'scan_id': 5}, {'scan_id': 'x', 'extra': 1}):
            body = env.post(env.rpc('tools/call', {'name': 'get_scan', 'arguments': args})).get_json()
            assert body['result']['isError'] is True, args

    def test_unexpected_exception_is_generic(self, env):
        from unittest import mock
        with mock.patch('spiderfoot.mcp.catalog.module_index', side_effect=RuntimeError('db password hunter2 in /srv/path')):
            body = env.post(env.rpc('tools/call', {'name': 'list_modules', 'arguments': {}})).get_json()
        assert body['result']['isError'] is True
        assert 'hunter2' not in json.dumps(body) and '/srv/path' not in json.dumps(body)


class TestDirect:
    def test_handle_message(self):
        assert protocol.handle_message({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'}, None)['result'] == {}
