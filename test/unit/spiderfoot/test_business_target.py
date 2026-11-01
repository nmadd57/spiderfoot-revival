import unittest

from spiderfoot import SpiderFootHelpers, SpiderFootTarget


class TestBusinessTargetDetection(unittest.TestCase):

    def test_prefix_is_company(self):
        for t in ['business: Acme', 'company:Acme Widgets', '"business: Acme Co"', 'Business:"Foo Bar"']:
            self.assertEqual('COMPANY_NAME', SpiderFootHelpers.targetTypeFromString(t), t)

    def test_quoted_name_with_legal_form_is_company(self):
        for t in ['"Acme Widgets, Inc."', '"Acme Holdings LLC"', '"Siemens AG"', '"Acme Holdings"']:
            self.assertEqual('COMPANY_NAME', SpiderFootHelpers.targetTypeFromString(t), t)

    def test_people_and_usernames_unchanged(self):
        self.assertEqual('HUMAN_NAME', SpiderFootHelpers.targetTypeFromString('"John Smith"'))
        self.assertEqual('USERNAME', SpiderFootHelpers.targetTypeFromString('"inc"'))
        self.assertEqual('INTERNET_NAME', SpiderFootHelpers.targetTypeFromString('acme.com'))

    def test_empty_prefix_is_not_a_target(self):
        self.assertIsNone(SpiderFootHelpers.targetTypeFromString('business:'))

    def test_strip_prefix(self):
        self.assertEqual('Acme', SpiderFootHelpers.stripTargetPrefix('business: Acme'))
        self.assertEqual('Foo Bar', SpiderFootHelpers.stripTargetPrefix('company:"Foo Bar"'))
        self.assertEqual('Acme Inc', SpiderFootHelpers.stripTargetPrefix('Acme Inc'))

    def test_normalize_company_name(self):
        n = SpiderFootHelpers.normalizeCompanyName
        self.assertEqual(n('The Acme Widgets, Inc.'), n('ACME WIDGETS INC'))
        self.assertEqual(n('A&B L.L.C.'), n('A and B LLC'))
        self.assertEqual(n('Acme United Corporation'), n('ACME UNITED CORP'))
        # "Holdings"/"Foundation" are part of the name, not a legal form
        self.assertNotEqual(n('Tesla, Inc.'), n('Tesla Holdings LLC'))
        self.assertNotEqual(n('Tesla'), n('Tesla Foundation'))

    def test_facility_name_matches(self):
        wanted = SpiderFootHelpers.normalizeCompanyName("Acme United Corporation")
        m = SpiderFootHelpers.facilityNameMatches
        for name in ["ACME UNITED CORP., WESTCOTT PLANT", "ACME UNITED CORPORATION - MED NAP DIVISION",
                     "ACME UNITED, BRIDGEPORT", "Acme United"]:
            self.assertTrue(m(name, wanted), name)
        for name in ["ACME UNITED HOLDINGS", "ACME UNITED HOLDINGS, LLC", "ACME UNITEDWAY"]:
            self.assertFalse(m(name, wanted), name)
        self.assertFalse(m("ACME UNITED CORP - PLANT 2", wanted, prefix=False))

    def test_company_target_accepts_aliases(self):
        target = SpiderFootTarget('Acme Widgets', 'COMPANY_NAME')
        self.assertTrue(target.setAlias('Acme Widgets Inc', 'COMPANY_NAME') is not False)


if __name__ == '__main__':
    unittest.main()
