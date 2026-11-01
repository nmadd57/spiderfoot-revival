import unittest

from spiderfoot.blueprints.fragments import _build_api_card_data


def _mod(opts, meta=None, descs=None):
    return {'opts': opts, 'optdescs': descs or {k: k for k in opts},
            'meta': {'name': 'Svc', 'categories': ['Search Engines'], **(meta or {})}}


class TestApiCardData(unittest.TestCase):

    def cards(self, mods):
        return {c['mod_name']: c for g in _build_api_card_data({'__modules__': mods}, 'flat') for c in g['cards']}

    def test_api_key_card(self):
        c = self.cards({'sfp_k': _mod({'api_key': 'x', 'pages': 3})})['sfp_k']
        self.assertEqual([('api_key', 'secret', True)], [(f['opt_key'], f['kind'], f['required']) for f in c['fields']])
        self.assertTrue(c['configured'])

    def test_connection_opts_card(self):
        mods = {'sfp_s': _mod({'instance_url': '', 'auth_header': 'X: y', 'verify_ssl': True, 'pages': 2},
                              {'connectionOpts': ['instance_url', 'auth_header', 'verify_ssl', 'missing']})}
        c = self.cards(mods)['sfp_s']
        self.assertEqual([('instance_url', 'text', True), ('auth_header', 'secret', False), ('verify_ssl', 'bool', False)],
                         [(f['opt_key'], f['kind'], f['required']) for f in c['fields']])
        self.assertEqual('1', c['fields'][2]['value'])
        self.assertFalse(c['configured'])  # instance_url is required and empty

        mods['sfp_s']['opts']['instance_url'] = 'http://searxng:8080'
        mods['sfp_s']['opts']['auth_header'] = ''
        self.assertTrue(self.cards(mods)['sfp_s']['configured'])  # optional fields don't count

    def test_modules_without_credentials_have_no_card(self):
        self.assertEqual({}, self.cards({'sfp_none': _mod({'pages': 3})}))


if __name__ == '__main__':
    unittest.main()
