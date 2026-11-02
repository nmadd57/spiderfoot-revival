"""Output shapes of the read-only tools, against a temp database with a couple of scans and events."""
import pytest


@pytest.fixture
def seeded(env):
    env.seed_scan('SCAN0001', 'example.com', 'first scan')
    env.seed_scan('SCAN0002', 'example.org', 'mcp: second scan', status='RUNNING')
    return env


class TestModules:
    def test_list_modules_defaults_to_available(self, env):
        err, out = env.call('list_modules')
        assert not err
        ids = [m['id'] for m in out['modules']]
        assert 'sfp_dnsresolve' in ids and 'sfp_crt' in ids and 'sfp_keyed' in ids
        assert 'sfp_nokey' not in ids and 'sfp_tool_nmap' not in ids  # auto-disabled
        assert out['total'] == len(ids)
        assert 'DNS' in out['categories']
        first = out['modules'][0]
        assert {'id', 'name', 'summary', 'category', 'pricing', 'flags', 'active', 'tool', 'requiresKey', 'available'} <= set(first)

    def test_unavailable_modules_carry_the_reason(self, env):
        env.db().configSet({'_disabled_modules': 'sfp_opsoff'})
        err, out = env.call('list_modules', only_available=False)
        by_id = {m['id']: m for m in out['modules']}
        assert by_id['sfp_nokey']['available'] is False and 'no API key' in by_id['sfp_nokey']['unavailableReason']
        assert by_id['sfp_tool_nmap']['unavailableReason'].endswith('tool not installed')
        assert by_id['sfp_opsoff']['unavailableReason'] == 'disabled by the operator'
        assert 'unavailableReason' not in by_id['sfp_dnsresolve']
        assert by_id['sfp_keyed']['available'] is True and by_id['sfp_keyed']['keyConfigured'] is True

    def test_active_and_tool_flags(self, env):
        err, out = env.call('list_modules', only_available=False)
        by_id = {m['id']: m for m in out['modules']}
        assert by_id['sfp_portscan_tcp']['active'] and 'invasive' in by_id['sfp_portscan_tcp']['flags']
        assert by_id['sfp_dnsbrute']['active'] and by_id['sfp_dnsbrute']['flags'] == []
        assert by_id['sfp_tool_nmap']['active'] and by_id['sfp_tool_nmap']['tool']
        assert not by_id['sfp_crt']['active'] and not by_id['sfp_crt']['tool']

    def test_filters(self, env):
        def ids(**f):
            return {m['id'] for m in env.call('list_modules', **f)[1]['modules']}
        assert ids(query='resolve') == {'sfp_dnsresolve'}
        assert ids(category='passive dns') == {'sfp_crt'}
        assert ids(pricing='free_key') == {'sfp_keyed'}
        assert ids(pricing='free_key', only_available=False) == {'sfp_keyed', 'sfp_nokey'}
        assert ids(produces='COUNTRY_NAME') == {'sfp_countryname'}
        assert ids(consumes='EMAILADDR') == {'sfp_mail'}
        assert ids(active=True) == {'sfp_portscan_tcp', 'sfp_dnsbrute'}
        assert 'sfp_portscan_tcp' not in ids(active=False)

    def test_paging(self, env):
        err, out = env.call('list_modules', limit=2, offset=1)
        assert out['returned'] == 2 and out['offset'] == 1 and out['hasMore'] is True

    def test_get_module(self, env):
        err, out = env.call('get_module', module='dnsresolve')
        assert not err
        assert out['id'] == 'sfp_dnsresolve' and out['watches'] == ['INTERNET_NAME', 'IP_ADDRESS']
        assert out['produces'] == ['IP_ADDRESS', 'DOMAIN_NAME']
        assert {'name': 'validatereverse', 'type': 'bool', 'default': True, 'description': 'Validate reverse lookups.'} in out['options']

    def test_get_module_hides_secrets(self, env):
        err, out = env.call('get_module', module='sfp_keyed')
        assert [o['name'] for o in out['options']] == ['limit']
        assert out['hiddenOptions'] == 1 and out['keyConfigured'] is True
        assert 'api_key' not in str(out)

    def test_get_module_unknown(self, env):
        err, out = env.call('get_module', module='sfp_missing')
        assert err and 'Unknown module' in out


class TestPresets:
    def test_list_presets(self, env):
        from spiderfoot.services.preset_service import seed_builtin_presets
        seed_builtin_presets(env.db(), env.app.config['SF_CONFIG']['__modules__'])
        err, out = env.call('list_presets')
        assert not err
        assert [u['name'] for u in out['useCases']] == ['Footprint', 'Investigate', 'Passive']
        by_id = {p['id']: p for p in out['presets']}
        assert by_id['builtin:passive']['useCase'] == 'Passive'
        assert 'sfp_portscan_tcp' in by_id['builtin:footprint']['activeModules']
        assert 'sfp_dnsresolve' in by_id['builtin:footprint']['modules']
        assert by_id['builtin:footprint']['unavailableCount'] >= 2
        assert next(u for u in out['useCases'] if u['name'] == 'Passive')['activeCount'] == 0


class TestSuggest:
    def test_by_target_type_grouped(self, env):
        err, out = env.call('suggest_modules', target_type='INTERNET_NAME')
        assert not err
        flat = {m['id']: m for g in out['groups'] for m in g['modules']}
        assert {'sfp_dnsresolve', 'sfp_crt', 'sfp_keyed', 'sfp_dnsbrute'} <= set(flat)
        assert flat['sfp_dnsbrute']['active'] is True
        assert 'sfp_mail' not in flat and 'sfp_nokey' not in flat
        assert {g['category'] for g in out['groups']} >= {'DNS', 'Passive DNS'}

    def test_goal_ranks(self, env):
        err, out = env.call('suggest_modules', target_type='INTERNET_NAME', goal='certificate transparency crt')
        assert out['groups'][0]['modules'][0]['id'] == 'sfp_crt'
        flat = {m['id']: m for g in out['groups'] for m in g['modules']}
        assert flat['sfp_crt']['relevance'] >= 1 and flat['sfp_dnsresolve']['relevance'] == 0

    def test_by_event_type_and_filters(self, env):
        err, out = env.call('suggest_modules', event_type='ip_address', include_active=False)
        flat = {m['id'] for g in out['groups'] for m in g['modules']}
        assert flat == {'sfp_dnsresolve', 'sfp_countryname'}
        err, out = env.call('suggest_modules', event_type='NOT_A_TYPE')
        assert err and 'Unknown event type' in out

    def test_needs_exactly_one_input(self, env):
        assert env.call('suggest_modules')[0]
        assert env.call('suggest_modules', target_type='EMAILADDR', event_type='IP_ADDRESS')[0]


class TestValidateTarget:
    @pytest.mark.parametrize('target,ttype,normal', [
        ('Example.COM', 'INTERNET_NAME', 'example.com'), ('93.184.216.34', 'IP_ADDRESS', '93.184.216.34'),
        ('93.184.216.0/24', 'NETBLOCK_OWNER', '93.184.216.0/24'), ('Jane@Example.com', 'EMAILADDR', 'jane@example.com'),
        ('+15551234567', 'PHONE_NUMBER', '+15551234567'), ('"Jane Doe"', 'HUMAN_NAME', 'Jane Doe'),
        ('Jane Doe', 'HUMAN_NAME', 'Jane Doe'), ('"janedoe"', 'USERNAME', 'janedoe'),
        ('13335', 'BGP_AS_OWNER', '13335'), ('business:Acme Widgets LLC', 'COMPANY_NAME', 'Acme Widgets LLC'),
        ('company: Acme & Sons', 'COMPANY_NAME', 'Acme & Sons'),
    ])
    def test_types_and_normalisation(self, env, target, ttype, normal):
        err, out = env.call('validate_target', target=target)
        assert not err and out['valid'] is True
        assert out['targetType'] == ttype and out['target'] == normal
        assert out['private'] is False
        assert [s['useCase'] for s in out['moduleSets']] == ['Footprint', 'Investigate', 'Passive']

    def test_invalid_target(self, env):
        err, out = env.call('validate_target', target='!!!')
        assert not err and out['valid'] is False and 'INTERNET_NAME' in out['accepted']

    @pytest.mark.parametrize('target,kind', [
        ('127.0.0.1', 'loopback'), ('10.1.2.3', 'private'), ('192.168.0.9', 'private'), ('169.254.169.254', 'link-local'),
        ('0.0.0.0', 'unspecified'), ('::1', 'loopback'), ('fe80::1', 'link-local'), ('10.0.0.0/8', 'private'),
        ('127.0.0.0/8', 'loopback'), ('server.localhost', 'internal hostname'), ('nas.home.arpa', 'internal hostname'),
    ])
    def test_private_detection(self, env, target, kind):
        err, out = env.call('validate_target', target=target)
        assert out['private'] is True and kind in out['privateKinds'], out
        assert out['privateAllowed'] is False
        assert 'not allowed private targets' in out['note']

    def test_private_allowed_is_reported(self, env):
        env.configure(allow_private=1)
        err, out = env.call('validate_target', target='10.0.0.5')
        assert out['privateAllowed'] is True

    def test_private_ip_restricts_module_sets(self, env):
        err, pub = env.call('validate_target', target='93.184.216.34')
        err, priv = env.call('validate_target', target='10.0.0.5')
        assert priv['moduleSets'][0]['availableModules'] < pub['moduleSets'][0]['availableModules']


class TestEventTypes:
    def test_list_and_filter(self, env):
        err, out = env.call('list_event_types')
        ids = {e['id'] for e in out['eventTypes']}
        assert {'INTERNET_NAME', 'IP_ADDRESS', 'EMAILADDR'} <= ids
        err, out = env.call('list_event_types', query='email')
        assert out['total'] >= 1 and all('email' in f"{e['id']} {e['description']}".lower() for e in out['eventTypes'])
        err, out = env.call('list_event_types', kind='ENTITY')
        assert out['eventTypes'] and {e['kind'] for e in out['eventTypes']} == {'ENTITY'}


class TestScans:
    def test_list_scans(self, seeded):
        err, out = seeded.call('list_scans')
        assert not err and out['total'] == 2
        one = next(s for s in out['scans'] if s['scanId'] == 'SCAN0001')
        assert one['name'] == 'first scan' and one['status'] == 'FINISHED' and one['events'] >= 5
        assert one['started'].endswith('Z') and one['ended'].endswith('Z')

    def test_list_filters(self, seeded):
        assert [s['scanId'] for s in seeded.call('list_scans', status='RUNNING')[1]['scans']] == ['SCAN0002']
        assert [s['scanId'] for s in seeded.call('list_scans', mcp_only=True)[1]['scans']] == ['SCAN0002']
        out = seeded.call('list_scans', limit=1, offset=1)[1]
        assert out['returned'] == 1 and out['total'] == 2 and out['hasMore'] is False

    def test_get_scan(self, seeded):
        err, out = seeded.call('get_scan', scan_id='SCAN0001')
        assert not err
        assert out['status'] == 'FINISHED' and out['done'] is True and out['target'] == 'example.com'
        assert out['targetType'] == 'INTERNET_NAME'
        assert out['modules'] == ['sfp_crt', 'sfp_dnsresolve'] and out['modulesSelected'] == 2 and out['modulesWithResults'] == 2
        assert out['events'] >= 6 and out['correlations'] == {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        assert out['errors'] == 1
        assert out['progress']['percent'] == 100 and out['durationSeconds'] >= 50
        assert out['ended'].endswith('Z')

    def test_get_scan_running(self, seeded):
        err, out = seeded.call('get_scan', scan_id='scan0002')  # ids are matched case-insensitively
        assert out['scanId'] == 'SCAN0002' and out['done'] is False and out['ended'] is None
        assert 5 <= out['progress']['percent'] <= 95 and out['progress']['estimate'] is True

    def test_summary(self, seeded):
        err, out = seeded.call('get_scan_summary', scan_id='SCAN0001')
        by_type = {t['type']: t for t in out['byType']}
        assert by_type['INTERNET_NAME']['count'] == 4 and by_type['INTERNET_NAME']['unique'] == 4
        assert by_type['IP_ADDRESS']['description'] == 'IP Address'
        assert out['totalEvents'] == sum(t['count'] for t in out['byType'])
        assert {m['module'] for m in out['byModule']} >= {'sfp_crt', 'sfp_dnsresolve'}

    def test_events_filters_and_shape(self, seeded):
        err, out = seeded.call('get_scan_events', scan_id='SCAN0001', event_type='INTERNET_NAME')
        assert out['total'] == 4 and out['returned'] == 4 and out['hasMore'] is False
        ev = next(e for e in out['events'] if e['data'] == 'www.example.com')
        assert ev['type'] == 'INTERNET_NAME' and ev['module'] == 'sfp_crt' and ev['source'] == 'example.com'
        assert {'confidence', 'risk', 'generated', 'truncated', 'falsePositive'} <= set(ev)
        assert [e['data'] for e in seeded.call('get_scan_events', scan_id='SCAN0001', module='sfp_dnsresolve')[1]['events']] == ['93.184.216.34']
        out = seeded.call('get_scan_events', scan_id='SCAN0001', query='MAIL.')[1]
        assert [e['data'] for e in out['events']] == ['mail.example.com']

    def test_events_paging_and_limit_cap(self, seeded):
        out = seeded.call('get_scan_events', scan_id='SCAN0001', limit=2, offset=1)[1]
        assert out['returned'] == 2 and out['offset'] == 1 and out['hasMore'] is True
        seeded.call('get_scan_events', scan_id='SCAN0001', limit=100000)  # clamped, not rejected
        assert seeded.call('get_scan_events', scan_id='SCAN0001', limit='3')[1]['returned'] == 3

    def test_event_data_truncated(self, seeded):
        out = seeded.call('get_scan_events', scan_id='SCAN0001', event_type='RAW_RIR_DATA')[1]
        ev = out['events'][0]
        assert ev['truncated'] is True and len(ev['data']) <= 503

    def test_event_cap_per_call(self, env):
        env.seed_scan('BIG00001')
        from spiderfoot.event import SpiderFootEvent
        dbh = env.db()
        root = SpiderFootEvent('ROOT', 'example.com', '', None)
        for i in range(350):
            dbh.scanEventStore('BIG00001', SpiderFootEvent('INTERNET_NAME', f'h{i}.example.com', 'sfp_crt', root))
        out = env.call('get_scan_events', scan_id='BIG00001', event_type='INTERNET_NAME', limit=500)[1]
        assert out['returned'] == 300 and out['hasMore'] is True

    def test_correlations(self, seeded):
        err, out = seeded.call('get_scan_correlations', scan_id='SCAN0001')
        assert not err and out['total'] == 0 and out['correlations'] == [] and out['status'] == 'FINISHED'

    def test_log(self, seeded):
        out = seeded.call('get_scan_log', scan_id='SCAN0001')[1]
        assert out['returned'] == 3 and {entry['level'] for entry in out['log']} == {'STATUS', 'ERROR', 'DEBUG'}
        out = seeded.call('get_scan_log', scan_id='SCAN0001', level='ERROR')[1]
        assert [entry['component'] for entry in out['log']] == ['sfp_crt']
        out = seeded.call('get_scan_log', scan_id='SCAN0001', limit=1, newest_first=False)[1]
        assert out['returned'] == 1 and out['log'][0]['time'].endswith('Z')

    def test_unknown_scan_everywhere(self, env):
        for tool in ('get_scan', 'get_scan_summary', 'get_scan_events', 'get_scan_correlations', 'get_scan_log'):
            err, text = env.call(tool, scan_id='MISSING')
            assert err and 'does not exist' in text, tool
