import json
import unittest
from urllib.parse import urlparse
from unittest import mock

from modules.sfp_brokercheck import sfp_brokercheck
from modules.sfp_npiregistry import sfp_npiregistry
from modules.sfp_secedgar import sfp_secedgar
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from spiderfoot.services import people


class TestPeopleHelpers(unittest.TestCase):
    def test_split_name(self):
        self.assertEqual(people.split_name('Dr. John Q. Smith Jr.')[:2], ('john', 'smith'))
        self.assertEqual(people.split_name('Smith, John Q')[:2], ('john', 'smith'))
        self.assertEqual(people.split_name('Tim Cook')[:2], ('tim', 'cook'))
        self.assertIsNone(people.split_name('Madonna'))
        self.assertIsNone(people.split_name('Dr Smith'))

    def test_same_person(self):
        self.assertTrue(people.same_person('JOHN A SMITH', 'john', 'smith'))
        self.assertTrue(people.same_person('J Smith', 'john', 'smith', ['Johnny Smith', 'John Smith']))
        self.assertFalse(people.same_person('Jane Smith', 'john', 'smith'))

    def test_name_in_text_any_order(self):
        self.assertTrue(people.name_in_text('timothy', 'cook', 'COOK TIMOTHY D'))
        self.assertFalse(people.name_in_text('timothy', 'cook', 'NIKE INC'))

    def test_company_matching_ignores_suffixes(self):
        self.assertTrue(people.same_company('Apple Inc.', 'APPLE INC'))
        self.assertTrue(people.same_company('The Acme Corporation', 'Acme Corp'))
        self.assertFalse(people.same_company('Apple Hospitality REIT', 'Apple Inc'))


class Base(unittest.TestCase):
    cls = None
    opts = {}

    def setUp(self):
        self.sf = SpiderFoot(dict(self.default_options))
        self.module = self.cls()
        self.module.__name__ = self.cls.__name__
        self.module.opts = dict(self.cls.opts)
        self.module.setup(self.sf, {**self.default_options, 'delay': 0, **self.opts})
        self.module.setTarget(SpiderFootTarget('example.com', 'INTERNET_NAME'))
        self.out = []
        self.module.notifyListeners = lambda e: self.out.append(e)
        self.module.checkForStop = lambda: False
        self.root = SpiderFootEvent('ROOT', 'x', '', None)

    def feed(self, etype, data, src='test'):
        self.module.handleEvent(SpiderFootEvent(etype, data, src, self.root))

    def by_type(self, etype):
        return [e.data for e in self.out if e.eventType == etype]

    def serve(self, routes):
        def fetch(url, *a, **kw):
            for needle, body in routes:
                if needle in url:
                    return {'code': '200', 'content': json.dumps(body)} if body is not None else {'code': '404', 'content': None}
            return {'code': '404', 'content': None}
        return mock.patch.object(self.sf, 'fetchUrl', side_effect=fetch)


NIKE = {'name': 'NIKE, Inc.', 'cik': '320187', 'entityType': 'operating', 'sic': '3021',
        'sicDescription': 'Rubber & Plastics Footwear', 'tickers': ['NKE'], 'exchanges': ['NYSE'],
        'stateOfIncorporation': 'OR', 'fiscalYearEnd': '0531', 'ein': '930584541', 'formerNames': [],
        'phone': '5036713173',
        'addresses': {'business': {'street1': 'ONE BOWERMAN DRIVE', 'city': 'BEAVERTON', 'stateOrCountry': 'OR', 'zipCode': '97005'}},
        'filings': {'recent': {'form': ['4', '10-K', '8-K', '10-Q'], 'filingDate': ['2026-10-01', '2026-07-20', '2026-06-27', '2026-04-01'],
                               'accessionNumber': ['0000320187-26-000010', '0000320187-26-000008', '0000320187-26-000007', '0000320187-26-000003'],
                               'primaryDocument': ['x4.xml', 'nke-10k.htm', 'nke-8k.htm', 'nke-10q.htm']}}}
COOK_SELF = {'name': 'COOK TIMOTHY D', 'cik': '1214156', 'entityType': 'other'}


def fts_hit(form, date, adsh, doc, names, ciks):
    return {'_id': f"{adsh}:{doc}", '_source': {'form': form, 'file_date': date, 'adsh': adsh, 'display_names': names, 'ciks': ciks}}


class TestSecEdgar(Base):
    cls = sfp_secedgar

    def test_person_to_companies_and_filings(self):
        hits = {'hits': {'hits': [
            fts_hit('4', '2021-10-08', '0001127602-21-026859', 'doc4.xml',
                    ['COOK TIMOTHY D  (CIK 0001214156)', 'NIKE, Inc.  (NKE)  (CIK 0000320187)'], ['0001214156', '0000320187']),
            fts_hit('4', '2017-09-25', '0000320187-17-000156', 'doc4.xml',
                    ['COOK TIMOTHY D  (CIK 0001214156)', 'NIKE INC  (NKE)  (CIK 0000320187)'], ['0001214156', '0000320187']),
        ]}}
        with self.serve([('search-index', hits), ('CIK0000320187.json', NIKE), ('CIK0001214156.json', COOK_SELF)]):
            self.feed('HUMAN_NAME', 'Timothy Cook')
        self.assertEqual(self.by_type('COMPANY_NAME'), ['NIKE, Inc.'])
        filings = self.by_type('COMPANY_FILING')
        self.assertTrue(any('Form 4 · 2021-10-08' in f and '/data/320187/000112760221026859/doc4.xml' in f for f in filings), filings)
        self.assertTrue(any('Form 10-K · 2026-07-20' in f for f in filings))  # the company's own recent filings
        self.assertIn('ONE BOWERMAN DRIVE, BEAVERTON, OR, 97005', self.by_type('PHYSICAL_ADDRESS'))
        evidence = [json.loads(d) for d in self.by_type('RAW_RIR_DATA') if '"person"' in d][0]
        self.assertEqual(evidence['appearsIn'], {'4': 2})
        self.assertIn('name only', evidence['note'])

    def test_person_with_one_word_or_no_hits(self):
        with self.serve([('search-index', {'hits': {'hits': []}})]) as f:
            self.feed('HUMAN_NAME', 'Madonna')
            f.assert_not_called()
            self.feed('HUMAN_NAME', 'Nobody Atall')
        self.assertEqual(self.out, [])

    def test_non_operating_filers_are_not_companies(self):
        hits = {'hits': {'hits': [fts_hit('4', '2020-01-01', '0001-20-1', 'd.xml',
                                          ['COOK TIMOTHY D  (CIK 0001214156)', 'SMITH JANE  (CIK 0000999)'], ['0001214156', '0000999'])]}}
        with self.serve([('search-index', hits), ('CIK0000000999.json', {'name': 'SMITH JANE', 'entityType': 'other'})]):
            self.feed('HUMAN_NAME', 'Timothy Cook')
        self.assertEqual(self.by_type('COMPANY_NAME'), [])

    def test_company_lookup(self):
        typeahead = {'hits': {'hits': [{'_id': '320187', '_source': {'entity': 'NIKE INC (NKE)'}},
                                       {'_id': '999', '_source': {'entity': 'NIKE HOLDINGS LLC'}}]}}
        with self.serve([('keysTyped', typeahead), ('CIK0000320187.json', NIKE)]):
            self.feed('COMPANY_NAME', 'Nike Inc.')
        filings = self.by_type('COMPANY_FILING')
        self.assertEqual(len(filings), 3)  # the Form 4 is not in the default company form list
        self.assertTrue(all('NIKE, Inc. · Form' in f for f in filings))
        self.assertEqual(self.by_type('PHONE_NUMBER'), ['5036713173'])
        self.assertEqual(self.by_type('COMPANY_NAME'), [])

    def test_ignores_its_own_companies_and_blocked_requests(self):
        with self.serve([]) as f:
            self.feed('COMPANY_NAME', 'Nike Inc.', src='sfp_secedgar')
            f.assert_not_called()
        with mock.patch.object(self.sf, 'fetchUrl', return_value={'code': '403', 'content': 'x'}), \
                mock.patch.object(self.module, 'error') as err:
            self.feed('HUMAN_NAME', 'Timothy Cook')
        self.assertTrue(self.module.errorState)
        self.assertIn('contact email', err.call_args[0][0])

    def test_contact_goes_into_user_agent(self):
        self.module.opts['contact'] = 'me@example.org'
        self.assertTrue(self.module.userAgent().endswith('me@example.org'))


NPI_PERSON = {'results': [{'number': '1972813608', 'enumeration_type': 'NPI-1',
                           'basic': {'first_name': 'ANTHONY', 'last_name': 'FAUCI', 'credential': 'M.D.'},
                           'taxonomies': [{'desc': 'Internal Medicine, Infectious Disease', 'license': 'D0004034', 'state': 'MD', 'code': '207KI0005X'}],
                           'addresses': [{'address_purpose': 'LOCATION', 'address_1': '9000 ROCKVILLE PIKE', 'city': 'BETHESDA',
                                          'state': 'MD', 'postal_code': '208920001', 'telephone_number': '301-555-0100'}]},
                          {'number': '1', 'enumeration_type': 'NPI-1', 'basic': {'first_name': 'ANTHONY', 'last_name': 'FAUSTI'}, 'taxonomies': [], 'addresses': []}]}
NPI_ORG = {'results': [{'number': '1881018208', 'enumeration_type': 'NPI-2',
                        'basic': {'organization_name': 'MAYO CLINIC', 'authorized_official_first_name': 'DENNIS',
                                  'authorized_official_last_name': 'DAHLEN', 'authorized_official_title_or_position': 'Chief Financial Officer'},
                        'taxonomies': [{'desc': 'Clinic/Center, Multi-Specialty', 'license': None, 'state': None, 'code': '261QM1300X'}],
                        'addresses': [{'address_purpose': 'LOCATION', 'address_1': '200 1ST ST SW', 'city': 'ROCHESTER', 'state': 'MN',
                                       'postal_code': '559050001', 'telephone_number': '507-284-2511'}]},
                       {'number': '2', 'enumeration_type': 'NPI-2', 'basic': {'organization_name': 'UNRELATED CARE'}, 'taxonomies': [], 'addresses': []}]}


class TestNpiRegistry(Base):
    cls = sfp_npiregistry

    def test_person_licence(self):
        with self.serve([('npiregistry', NPI_PERSON)]) as f:
            self.feed('HUMAN_NAME', 'Anthony S. Fauci')
        self.assertIn('first_name=anthony', f.call_args[0][0])
        lic = self.by_type('PROFESSIONAL_LICENSE')
        self.assertEqual(len(lic), 1)
        self.assertIn('state licence D0004034 (MD)', lic[0])
        self.assertIn('NPI 1972813608 (individual)', lic[0])
        self.assertEqual(self.by_type('PHONE_NUMBER'), ['301-555-0100'])
        self.assertIn('9000 ROCKVILLE PIKE, BETHESDA, MD, 20892', self.by_type('PHYSICAL_ADDRESS'))

    def test_organisation_with_authorised_official(self):
        with self.serve([('npiregistry', NPI_ORG)]):
            self.feed('COMPANY_NAME', 'Mayo Clinic')
        lic = self.by_type('PROFESSIONAL_LICENSE')
        self.assertEqual(len(lic), 1)
        self.assertIn('MAYO CLINIC', lic[0])
        self.assertIn('no state licence listed', lic[0])
        self.assertEqual(self.by_type('HUMAN_NAME'), ['DENNIS DAHLEN'])

    def test_state_filter_and_errors(self):
        self.module.opts['state'] = 'md'
        with self.serve([('npiregistry', {'Errors': [{'description': 'bad'}]})]) as f:
            self.feed('HUMAN_NAME', 'Anthony Fauci')
        self.assertIn('state=MD', f.call_args[0][0])
        self.assertEqual(self.out, [])


BC_PERSON = {'hits': {'hits': [
    {'_source': {'ind_source_id': '7116887', 'ind_firstname': 'Charles', 'ind_middlename': 'Wayan', 'ind_lastname': 'Schwab',
                 'ind_other_names': ['Charles  Schwab'], 'ind_bc_scope': 'NotInScope', 'ind_ia_scope': 'Active',
                 'ind_bc_disclosure_fl': 'N', 'ind_ia_disclosure_fl': 'Y',
                 'ind_current_employments': [{'firm_id': '286648', 'firm_name': 'DEFINE FINANCIAL, LLC', 'branch_city': 'SAN DIEGO',
                                              'branch_state': 'CA', 'branch_zip': '92130'}]}},
    {'_source': {'ind_source_id': '1', 'ind_firstname': 'Chuck', 'ind_lastname': 'Other', 'ind_other_names': []}}]}}
BC_FIRM = {'hits': {'hits': [
    {'_source': {'firm_source_id': '5393', 'firm_name': 'CHARLES SCHWAB & CO., INC.', 'firm_other_names': ['CHARLES SCHWAB & CO., INC.'],
                 'firm_bd_full_sec_number': '8-16514', 'firm_ia_full_sec_number': '801-29938', 'firm_scope': 'ACTIVE',
                 'firm_ia_scope': 'ACTIVE', 'firm_disclosure_fl': 'Y', 'firm_branches_count': 1166,
                 'firm_address_details': json.dumps({'officeAddress': {'street1': '3000 SCHWAB WAY', 'city': 'WESTLAKE', 'state': 'TX', 'postalCode': '76262-8104'}})}}]}}


class TestBrokerCheck(Base):
    cls = sfp_brokercheck
    opts = {'use_iapd': False}

    def test_person_registration_and_employer(self):
        with self.serve([('brokercheck.finra.org/search/individual', BC_PERSON)]):
            self.feed('HUMAN_NAME', 'Charles Schwab')
        lic = self.by_type('PROFESSIONAL_LICENSE')
        self.assertEqual(len(lic), 1)
        self.assertIn('FINRA BrokerCheck CRD 7116887', lic[0])
        self.assertIn('investment adviser representative (active)', lic[0])
        self.assertIn('HAS DISCLOSURES', lic[0])
        self.assertIn('https://brokercheck.finra.org/individual/summary/7116887', lic[0])
        self.assertEqual(self.by_type('COMPANY_NAME'), ['Define Financial, Llc'])
        self.assertIn('SAN DIEGO, CA, 92130', self.by_type('PHYSICAL_ADDRESS'))

    def test_firm_registration(self):
        with self.serve([('search/firm', BC_FIRM)]):
            self.feed('COMPANY_NAME', 'Charles Schwab & Co., Inc.')
        lic = self.by_type('PROFESSIONAL_LICENSE')
        self.assertEqual(len(lic), 1)
        self.assertIn('broker-dealer SEC 8-16514 (active)', lic[0])
        self.assertIn('investment adviser SEC 801-29938', lic[0])
        self.assertIn('1166 branches', lic[0])
        self.assertIn('3000 SCHWAB WAY, WESTLAKE, TX, 76262-8104', self.by_type('PHYSICAL_ADDRESS'))

    def test_both_sources_are_searched_when_enabled(self):
        self.module.opts['use_iapd'] = True
        with self.serve([('search/individual', {'hits': {'hits': []}})]) as f:
            self.feed('HUMAN_NAME', 'Nobody Atall')
        urls = [c[0][0] for c in f.call_args_list]
        self.assertTrue(any(urlparse(u).hostname == 'api.brokercheck.finra.org' for u in urls))
        self.assertTrue(any(urlparse(u).hostname == 'api.adviserinfo.sec.gov' for u in urls))

    def test_blocked_request_sets_error_state(self):
        with mock.patch.object(self.sf, 'fetchUrl', return_value={'code': '429', 'content': ''}), \
                mock.patch.object(self.module, 'error'):
            self.feed('HUMAN_NAME', 'Charles Schwab')
        self.assertTrue(self.module.errorState)
