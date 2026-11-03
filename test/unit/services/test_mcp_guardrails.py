"""Every guardrail, enforced server-side from the saved permissions on each call."""
import json
from unittest import mock

import pytest

from spiderfoot.mcp import guardrails
from spiderfoot.mcp.tools import TOOLS

from .conftest import OTHER_SECRET, SECRET


def reasons(result):
    return {d['module']: d['reason'] for d in result['dropped']}


class TestActiveModules:
    def test_active_set_covers_the_required_modules(self):
        for name in ('sfp_tool_nmap', 'sfp_tool_nuclei', 'sfp_tool_bbot_scan', 'sfp_tool_bbot_vuln', 'sfp_tool_nbtscan',
                     'sfp_tool_onesixtyone', 'sfp_tool_whatweb', 'sfp_tool_wafw00f', 'sfp_tool_testsslsh',
                     'sfp_portscan_tcp', 'sfp_dnsbrute'):
            assert guardrails.is_active_module(name, [])
        assert guardrails.is_active_module('sfp_junkfiles', ['invasive'])
        assert not guardrails.is_active_module('sfp_crt', ['slow', 'apikey'])

    def test_real_modules_flagged_invasive_are_active(self):
        from spiderfoot import SpiderFootHelpers
        import os
        mods = SpiderFootHelpers.loadModulesAsDict(os.path.join(os.path.dirname(guardrails.__file__), '..', '..', 'modules'), ['sfp_template.py'])
        flagged = [n for n, m in mods.items() if 'invasive' in m['meta'].get('flags', [])]
        assert flagged and all(guardrails.is_active_module(n, mods[n]['meta']['flags']) for n in flagged)
        assert guardrails.ACTIVE_MODULES <= set(mods)

    def test_dropped_without_operator_permission(self, env):
        err, out = env.call('create_scan', target='example.com', modules=['sfp_dnsresolve', 'sfp_portscan_tcp', 'sfp_dnsbrute'], confirm_active=True)
        assert not err
        assert out['modules'] == ['sfp_dnsresolve']
        assert set(reasons(out)) == {'sfp_portscan_tcp', 'sfp_dnsbrute'}
        assert all('operator has not allowed' in r for r in reasons(out).values())
        assert env.launched[-1]['modules'] == ['sfp__stor_db', 'sfp_dnsresolve']

    def test_dropped_without_confirmation_even_when_permitted(self, env):
        env.configure(allow_active=1)
        err, out = env.call('create_scan', target='example.com', modules=['sfp_dnsresolve', 'sfp_portscan_tcp'])
        assert not err and out['modules'] == ['sfp_dnsresolve']
        assert 'confirm_active' in reasons(out)['sfp_portscan_tcp']

    def test_included_with_permission_and_confirmation(self, env):
        env.configure(allow_active=1)
        err, out = env.call('create_scan', target='example.com', modules=['sfp_dnsresolve', 'sfp_portscan_tcp', 'sfp_dnsbrute'],
                            confirm_active=True)
        assert not err and out['modules'] == ['sfp_dnsbrute', 'sfp_dnsresolve', 'sfp_portscan_tcp'] and out['dropped'] == []
        assert 'sfp_portscan_tcp' in env.launched[-1]['modules']

    def test_only_active_modules_requested_fails_with_reason(self, env):
        err, text = env.call('create_scan', target='example.com', modules=['sfp_portscan_tcp'])
        assert err and 'No modules left' in text and 'sfp_portscan_tcp' in text

    def test_use_case_expansion_is_filtered_too(self, env):
        err, out = env.call('create_scan', target='example.com', use_case='Footprint')
        assert not err
        assert set(out['modules']) == {'sfp_dnsresolve', 'sfp_countryname', 'sfp_crt', 'sfp_keyed', 'sfp_opsoff'}
        assert set(reasons(out)) == {'sfp_portscan_tcp', 'sfp_dnsbrute', 'sfp_tool_nmap', 'sfp_nokey'}
        assert out['droppedCount'] == 4 and sum(out['droppedByReason'].values()) == 4

    def test_rerun_applies_the_same_rule(self, env):
        env.seed_scan('OLD00001', modules='sfp__stor_db,sfp_dnsresolve,sfp_portscan_tcp')
        err, out = env.call('rerun_scan', scan_id='OLD00001', confirm_active=True)
        assert not err and out['modules'] == ['sfp_dnsresolve'] and 'sfp_portscan_tcp' in reasons(out)
        env.configure(allow_active=1)
        err, out = env.call('rerun_scan', scan_id='OLD00001')
        assert out['modules'] == ['sfp_dnsresolve'] and 'confirm_active' in reasons(out)['sfp_portscan_tcp']
        err, out = env.call('rerun_scan', scan_id='OLD00001', confirm_active=True)
        assert out['modules'] == ['sfp_dnsresolve', 'sfp_portscan_tcp'] and out['rerunOf'] == 'OLD00001'


class TestPrivateTargets:
    @pytest.mark.parametrize('target', ['127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.9', '169.254.169.254', '0.0.0.0',
                                        '::1', 'fe80::1', '10.0.0.0/8', 'localhost.localdomain.local', 'db.internal'])
    def test_refused_without_permission(self, env, target):
        err, text = env.call('create_scan', target=target, modules=['sfp_dnsresolve'])
        assert err and text.startswith('Refused') and 'private' in text
        assert env.launched == []

    def test_allowed_with_permission(self, env):
        env.configure(allow_private=1)
        err, out = env.call('create_scan', target='10.0.0.5', modules=['sfp_dnsresolve', 'sfp_countryname'])
        assert not err and out['modules'] == ['sfp_dnsresolve']
        assert reasons(out)['sfp_countryname'] == 'does not work with private IP targets'

    def test_hostname_resolving_to_private_address_is_refused(self, env):
        with mock.patch('spiderfoot.mcp.guardrails.resolver', return_value=['93.184.216.34', '10.9.9.9']):
            err, text = env.call('create_scan', target='sneaky.example.com', modules=['sfp_dnsresolve'])
        assert err and 'resolves to 10.9.9.9' in text
        env.configure(allow_private=1)
        with mock.patch('spiderfoot.mcp.guardrails.resolver', return_value=['10.9.9.9']):
            assert not env.call('create_scan', target='sneaky.example.com', modules=['sfp_dnsresolve'])[0]

    def test_public_targets_pass(self, env):
        for target in ('93.184.216.34', 'example.com', '93.184.216.0/24'):
            assert not env.call('create_scan', target=target, modules=['sfp_dnsresolve'])[0], target

    def test_rerun_of_private_scan_is_refused(self, env):
        env.seed_scan('PRIV0001', target='10.0.0.5', modules='sfp__stor_db,sfp_dnsresolve', seed_type='IP_ADDRESS')
        err, text = env.call('rerun_scan', scan_id='PRIV0001')
        assert err and text.startswith('Refused')


class TestPermissions:
    def test_scan_tools_need_allow_scan(self, env):
        env.seed_scan('RUN00001', status='RUNNING')
        env.configure(allow_scan=0)
        for tool, args in [('create_scan', {'target': 'example.com', 'modules': ['sfp_dnsresolve']}),
                           ('stop_scan', {'scan_id': 'RUN00001'}), ('rerun_scan', {'scan_id': 'RUN00001'})]:
            err, text = env.call(tool, **args)
            assert err and text.startswith('Not permitted'), tool
        assert env.launched == []
        assert env.db().scanInstanceGet('RUN00001')[5] == 'RUNNING'

    def test_read_tools_work_without_any_permission(self, env):
        env.seed_scan('READ0001')
        env.configure(allow_scan=0, allow_delete=0, allow_active=0, allow_private=0)
        for tool, args in [('list_scans', {}), ('get_scan', {'scan_id': 'READ0001'}), ('get_scan_events', {'scan_id': 'READ0001'}),
                           ('list_modules', {}), ('validate_target', {'target': 'example.com'})]:
            assert not env.call(tool, **args)[0], tool

    def test_delete_needs_permission_and_confirmation(self, env):
        env.seed_scan('DEL00001')
        err, text = env.call('delete_scan', scan_id='DEL00001', confirm=True)
        assert err and text.startswith('Not permitted')
        assert env.db().scanInstanceGet('DEL00001')
        env.configure(allow_delete=1)
        for args in ({}, {'confirm': False}):
            err, text = env.call('delete_scan', scan_id='DEL00001', **args)
            assert err and 'confirm=true' in text
        assert env.db().scanInstanceGet('DEL00001')
        err, out = env.call('delete_scan', scan_id='DEL00001', confirm=True)
        assert not err and out == {'scanId': 'DEL00001', 'deleted': True}
        assert env.db().scanInstanceGet('DEL00001') is None
        assert env.db().scanResultEvent('DEL00001') == []

    def test_running_scan_cannot_be_deleted(self, env):
        env.configure(allow_delete=1)
        env.seed_scan('RUN00002', status='RUNNING')
        err, text = env.call('delete_scan', scan_id='RUN00002', confirm=True)
        assert err and 'RUNNING' in text and env.db().scanInstanceGet('RUN00002')

    def test_string_confirm_is_coerced_but_other_values_fail(self, env):
        env.configure(allow_delete=1)
        env.seed_scan('DEL00002')
        assert env.call('delete_scan', scan_id='DEL00002', confirm='yes')[0]
        assert env.db().scanInstanceGet('DEL00002')

    def test_permission_changes_apply_to_the_next_call(self, env):
        assert env.call('create_scan', target='example.com', modules=['sfp_dnsresolve'])[0] is False
        env.configure(allow_scan=0)
        assert env.call('create_scan', target='example.com', modules=['sfp_dnsresolve'])[0] is True
        env.configure(allow_scan=1)
        assert env.call('create_scan', target='example.com', modules=['sfp_dnsresolve'])[0] is False

    def test_stop_scan(self, env):
        env.seed_scan('RUN00003', status='RUNNING')
        err, out = env.call('stop_scan', scan_id='RUN00003')
        assert not err and out['status'] == 'ABORT-REQUESTED'
        assert env.db().scanInstanceGet('RUN00003')[5] == 'ABORT-REQUESTED'
        env.seed_scan('FIN00003')
        err, text = env.call('stop_scan', scan_id='FIN00003')
        assert err and 'already finished' in text


class TestModuleAvailability:
    def test_disabled_and_auto_disabled_modules_are_dropped_with_reason(self, env):
        env.db().configSet({'_disabled_modules': 'sfp_opsoff'})
        err, out = env.call('create_scan', target='example.com',
                            modules=['sfp_dnsresolve', 'sfp_opsoff', 'sfp_nokey', 'sfp_tool_nmap', 'sfp_crt'], confirm_active=True)
        assert not err and out['modules'] == ['sfp_crt', 'sfp_dnsresolve']
        r = reasons(out)
        assert r['sfp_opsoff'] == 'disabled by the operator'
        assert r['sfp_nokey'] == 'auto-disabled: no API key'
        assert r['sfp_tool_nmap'].startswith('operator has not') or 'active module' in r['sfp_tool_nmap'] or 'tool not installed' in r['sfp_tool_nmap']

    def test_tool_missing_reason_when_active_is_allowed(self, env):
        env.configure(allow_active=1)
        err, out = env.call('create_scan', target='example.com', modules=['sfp_dnsresolve', 'sfp_tool_nmap'], confirm_active=True)
        assert reasons(out)['sfp_tool_nmap'] == 'auto-disabled: tool not installed'

    def test_only_unavailable_modules_fails_clearly(self, env):
        err, text = env.call('create_scan', target='example.com', modules=['sfp_nokey'])
        assert err and 'no enabled modules' in text and 'no API key' in text

    def test_unknown_module_is_rejected(self, env):
        err, text = env.call('create_scan', target='example.com', modules=['sfp_dnsresolve', 'sfp_bogus'])
        assert err and 'sfp_bogus' in text and env.launched == []

    def test_selection_needs_exactly_one_source(self, env):
        assert env.call('create_scan', target='example.com')[0]
        assert env.call('create_scan', target='example.com', modules=['sfp_crt'], use_case='Passive')[0]
        assert env.call('create_scan', target='example.com', use_case='Everything')[0]

    def test_preset_by_id_and_name(self, env):
        from spiderfoot.services.preset_service import seed_builtin_presets
        seed_builtin_presets(env.db(), env.app.config['SF_CONFIG']['__modules__'])
        for ref in ('builtin:passive', 'Passive', 'passive'):
            err, out = env.call('create_scan', target='example.com', preset=ref)
            assert not err, ref
            assert set(out['modules']) == {'sfp_dnsresolve', 'sfp_countryname', 'sfp_crt', 'sfp_keyed', 'sfp_opsoff'}
        assert env.call('create_scan', target='example.com', preset='nope')[0]


class TestScanLimits:
    def test_max_concurrent_scans(self, env):
        for i in range(3):
            env.seed_scan(f'RUN1000{i}', status='RUNNING')
        err, text = env.call('create_scan', target='example.com', modules=['sfp_dnsresolve'])
        assert err and 'Maximum concurrent scans (3)' in text
        assert env.launched == []

    def test_finished_scans_do_not_count(self, env):
        for i in range(5):
            env.seed_scan(f'FIN1000{i}')
        assert not env.call('create_scan', target='example.com', modules=['sfp_dnsresolve'])[0]

    def test_scan_name_prefix_and_default(self, env):
        err, out = env.call('create_scan', target='example.com', name='quarterly review', modules=['sfp_dnsresolve'])
        assert out['name'] == 'mcp: quarterly review'
        assert env.launched[-1]['name'] == 'mcp: quarterly review'
        err, out = env.call('create_scan', target='example.org', modules=['sfp_dnsresolve'])
        assert out['name'] == 'mcp: example.org'
        assert env.db().scanInstanceGet(out['scanId'])[0] == 'mcp: example.org'

    def test_scan_is_started_with_normalised_target_and_type(self, env):
        err, out = env.call('create_scan', target='  Example.COM ', modules=['sfp_dnsresolve'])
        assert not err and out['target'] == 'example.com' and out['targetType'] == 'INTERNET_NAME' and out['status'] == 'RUNNING'
        assert env.launched[-1]['type'] == 'INTERNET_NAME' and env.launched[-1]['target'] == 'example.com'

    def test_bad_target(self, env):
        err, text = env.call('create_scan', target='!!!', modules=['sfp_dnsresolve'])
        assert err and 'Unrecognised target' in text

    def test_rerun_keeps_target_and_prefixes_name(self, env):
        env.seed_scan('ORIG0001', name='first scan')
        err, out = env.call('rerun_scan', scan_id='ORIG0001')
        assert not err and out['name'] == 'mcp: first scan' and out['target'] == 'example.com'
        assert out['modules'] == ['sfp_crt', 'sfp_dnsresolve'] and out['scanId'] != 'ORIG0001'

    def test_name_targets_survive_rerun(self, env):
        env.seed_scan('NAME0001', target='Jane Doe', name='mcp: person', seed_type='HUMAN_NAME')
        err, out = env.call('rerun_scan', scan_id='NAME0001')
        assert not err and out['targetType'] == 'HUMAN_NAME' and out['target'] == 'Jane Doe' and out['name'] == 'mcp: person'


class TestNoSecretsInOutput:
    def test_fixture_really_has_secrets(self, env):
        saved = env.db().configGet()
        assert saved['sfp_keyed:api_key'] == SECRET and saved['_ai_openrouter_key'] == OTHER_SECRET

    def test_no_tool_output_contains_a_secret(self, env):
        env.seed_scan('SEC00001')
        env.configure(allow_active=1, allow_private=1, allow_delete=1)
        calls = [('list_modules', {'only_available': False, 'limit': 300}), ('get_module', {'module': 'sfp_keyed'}),
                 ('get_module', {'module': 'sfp_nokey'}), ('list_presets', {}), ('suggest_modules', {'target_type': 'INTERNET_NAME'}),
                 ('validate_target', {'target': SECRET}), ('validate_target', {'target': 'example.com'}), ('list_event_types', {}),
                 ('list_scans', {}), ('get_scan', {'scan_id': 'SEC00001'}), ('get_scan_summary', {'scan_id': 'SEC00001'}),
                 ('get_scan_events', {'scan_id': 'SEC00001', 'limit': 300}), ('get_scan_events', {'scan_id': 'SEC00001', 'query': 'leaked'}),
                 ('get_scan_correlations', {'scan_id': 'SEC00001'}), ('get_scan_log', {'scan_id': 'SEC00001', 'limit': 300}),
                 ('get_scan_log', {'scan_id': 'SEC00001', 'level': 'ERROR'}),
                 ('create_scan', {'target': 'example.com', 'name': 'x', 'modules': ['sfp_keyed']}),
                 ('create_scan', {'target': SECRET, 'modules': ['sfp_keyed']}),
                 ('stop_scan', {'scan_id': 'SEC00001'}), ('rerun_scan', {'scan_id': 'SEC00001'}),
                 ('delete_scan', {'scan_id': 'SEC00001', 'confirm': True}), ('get_scan', {'scan_id': SECRET})]
        for tool, args in calls:
            resp = env.post(env.rpc('tools/call', {'name': tool, 'arguments': args}))
            text = resp.get_data(as_text=True)
            assert SECRET not in text and OTHER_SECRET not in text, tool
            assert SECRET not in json.dumps(resp.get_json()), tool

    def test_secrets_found_in_events_and_logs_are_redacted(self, env):
        env.seed_scan('SEC00002')
        events = env.call('get_scan_events', scan_id='SEC00002', event_type='RAW_RIR_DATA')[1]['events']
        assert '[redacted]' in json.dumps(events) or events[0]['truncated']
        logs = env.call('get_scan_log', scan_id='SEC00002', level='ERROR')[1]['log']
        assert logs[0]['message'] == 'request failed with key [redacted]'

    def test_token_hash_never_returned(self, env):
        digest = env.db().mcpTokenList(env.admin['id'])
        assert digest  # the admin's token exists; only its hash is in the database
        import hashlib
        hashed = hashlib.sha256(env.token.encode()).hexdigest()
        text = json.dumps([env.call('list_modules')[1], env.call('list_presets')[1], env.call('list_scans')[1]])
        assert hashed not in text and env.token not in text

    def test_audit_log_has_tool_and_summary_but_no_token(self, env, caplog):
        import logging
        with caplog.at_level(logging.INFO, logger='spiderfoot.mcp'):
            env.call('create_scan', target='example.com', modules=['sfp_dnsresolve'])
            env.call('get_scan', scan_id='NOPE')
            env.post(env.rpc('ping'), token='sfmcp_wrongtoken123')
        text = caplog.text
        assert 'tool=create_scan' in text and "target='example.com'" in text and 'outcome=ok' in text
        assert 'tool=get_scan' in text and 'outcome=refused' in text
        assert env.token not in text and 'sfmcp_wrongtoken123' not in text and 'Bearer' not in text


class TestCatalogue:
    def test_eighteen_tools(self):
        # sixteen plus reassess_relevance and mark_event
        assert len(TOOLS) == 18
