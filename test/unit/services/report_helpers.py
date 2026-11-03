"""Synthetic scans and a fake chat endpoint for the report tests (no network)."""
import re
import time

from spiderfoot import SpiderFootDb
from spiderfoot.services import relevance_job as rel_job
from spiderfoot.services import report_job
from spiderfoot.services.report_llm import ReportLLM, ReportLLMError
from test.unit.services.relevance_fixture import TARGET, namesake_events

FAKE_KEY = 'sk-test-REPORT-KEY-0123456789abcdef'
NOW_MS = int(time.time() * 1000)


def ai_config(**extra):
    cfg = dict(report_job.DEFAULTS)
    cfg.update(rel_job.DEFAULTS)
    cfg.update({'_ai_enabled': True, '_ai_base_url': 'http://ai.test/v1', '_ai_openrouter_key': FAKE_KEY, '_ai_default_model': 'small',
                '_ai_fallback_model': 'backup', '_ai_redact_pii': False})
    cfg.update(extra)
    return cfg


def add_event(dbh, scan_id, h, etype, module, data, parent, risk=0, gen=None):
    dbh.dbh.execute("INSERT INTO tbl_scan_results (scan_instance_id,hash,type,generated,confidence,visibility,risk,module,data,false_positive,source_event_hash)"
                    " VALUES (?,?,?,?,100,100,?,?,?,0,?)", (scan_id, h, etype, gen or NOW_MS, risk, module, data, parent))


def seed_namesake(cfg, scan_id='NS000001', assess=True, status='FINISHED', owner=None, dbh=None):
    """The relevance tests' namesake scan (made-up people) stored in the database of ``cfg``; returns the db handle."""
    dbh = dbh or SpiderFootDb(cfg, init=True)
    dbh.scanInstanceCreate(scan_id, 'namesake scan', TARGET, owner)
    dbh.scanInstanceSet(scan_id, started=NOW_MS - 600000, ended=NOW_MS - 1000, status=status)
    for r in namesake_events():
        add_event(dbh, scan_id, r[0], r[1], r[2], r[3], r[4], gen=int(r[5] * 1000))
    dbh.conn.commit()
    dbh.scanConfigSet(scan_id, {'_modulesenabled': 'sfp__stor_db,sfp_accounts,sfp_brokercheck,sfp_npiregistry', 'api_key': FAKE_KEY})
    dbh.scanContextSet(scan_id, 'location: Missouri', True)
    if assess:
        rel_job.assess_scan(cfg, scan_id, dbh=dbh, network=False)
    return dbh


def seed_infra(cfg, scan_id='INF00001', status='FINISHED', owner=None, secret_in_event='', dbh=None):
    """A domain scan: hosts, an IP, ports, a leak, a CVE with a risk score, a correlation, a key problem in the log, a silent module."""
    dbh = dbh or SpiderFootDb(cfg, init=True)
    dbh.scanInstanceCreate(scan_id, 'infra scan', 'example.test', owner)
    dbh.scanInstanceSet(scan_id, started=NOW_MS - 120000, ended=NOW_MS - 1000, status=status)
    add_event(dbh, scan_id, 'r0', 'ROOT', '', 'example.test', 'ROOT')
    add_event(dbh, scan_id, 'seed', 'INTERNET_NAME', 'SpiderFoot UI', 'example.test', 'r0')
    add_event(dbh, scan_id, 'ip1', 'IP_ADDRESS', 'sfp_dnsresolve', '203.0.113.7', 'seed')
    add_event(dbh, scan_id, 'h1', 'INTERNET_NAME', 'sfp_crt', 'www.example.test', 'seed')
    add_event(dbh, scan_id, 'p1', 'TCP_PORT_OPEN', 'sfp_portscan_tcp', '203.0.113.7:443', 'ip1')
    add_event(dbh, scan_id, 'p2', 'TCP_PORT_OPEN', 'sfp_portscan_tcp', '203.0.113.7:22', 'ip1')
    add_event(dbh, scan_id, 'cve1', 'VULNERABILITY_CVE_HIGH', 'sfp_nuclei', 'CVE-2099-0001 on 203.0.113.7:443', 'p1', risk=80)
    add_event(dbh, scan_id, 'leak1', 'EMAILADDR_COMPROMISED', 'sfp_haveibeenpwned', 'admin@example.test [Example breach]', 'seed', risk=60)
    add_event(dbh, scan_id, 'xss', 'LINKED_URL_EXTERNAL', 'sfp_spider', 'https://other.test/<script>alert(1)</script>', 'seed')
    if secret_in_event:
        add_event(dbh, scan_id, 'sec1', 'RAW_RIR_DATA', 'sfp_whois', 'token=' + secret_in_event, 'seed')
        add_event(dbh, scan_id, 'sec2', 'SOFTWARE_USED', 'sfp_whatweb', 'Backend ' + secret_in_event, 'seed')
    dbh.dbh.execute("INSERT INTO tbl_scan_correlation_results (id,scan_instance_id,title,rule_risk,rule_id,rule_name,rule_descr,rule_logic)"
                    " VALUES ('c1',?,'Exposed admin service','HIGH','exposed_admin','Exposed admin','Admin service on the internet','x')", (scan_id,))
    dbh.dbh.execute("INSERT INTO tbl_scan_correlation_results_events (correlation_id,event_hash) VALUES ('c1','p1')")
    dbh.dbh.execute("INSERT INTO tbl_scan_log (scan_instance_id,generated,component,type,message) VALUES (?,?,?,?,?)",
                    (scan_id, NOW_MS, 'sfp_shodan', 'ERROR', 'Shodan API key rejected (HTTP 401)'))
    dbh.dbh.execute("INSERT INTO tbl_scan_log (scan_instance_id,generated,component,type,message) VALUES (?,?,?,?,?)",
                    (scan_id, NOW_MS, 'sfp_other', 'ERROR', 'could not parse the answer'))
    dbh.conn.commit()
    dbh.scanConfigSet(scan_id, {'_modulesenabled': 'sfp__stor_db,sfp_dnsresolve,sfp_crt,sfp_portscan_tcp,sfp_shodan,sfp_silent'})
    return dbh


class FakeLLM(ReportLLM):
    """A ReportLLM whose HTTP call is a function of the section prompt; it records every prompt it was sent."""

    def __init__(self, answer=None, **kw):
        kw.setdefault('retry_wait', 0)
        super().__init__('http://ai.test/v1', FAKE_KEY, 'small', 'backup', **kw)
        self.prompts = []
        self.models_asked = []
        self.answer = answer or default_answer

    def _post(self, model, messages, max_tokens):
        self.prompts.append(messages[1]['content'])
        self.models_asked.append(model)
        out = self.answer(messages[1]['content'], model)
        if isinstance(out, Exception):
            raise out
        return out, {'prompt_tokens': 700, 'completion_tokens': 120}, 'stop'


def offered_ids(prompt):
    return re.findall(r"^\[(E\d+|C\d+)\]", prompt, flags=re.M)


def default_answer(prompt, model):
    """A well-behaved model: cites the first two ids it was offered and uses only numbers from the data."""
    ids = offered_ids(prompt)
    cite = ' '.join(f'[{i}]' for i in ids[:2])
    return f"This part of the report is based on the data given. {cite}\n\n- The data supports one point {cite}."


def failing(prompt, model):
    return ReportLLMError('The AI endpoint answered HTTP 503.')
