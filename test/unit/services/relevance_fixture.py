"""A small synthetic scan that has the shape of a person-name scan with namesakes (made-up people and companies).

Rows are (hash, type, module, data, source_event_hash, generated, false_positive). Hashes are readable keys.
"""

TARGET = 'Marcus Elias Thornwood'


def namesake_events():
    rows = []

    def add(h, etype, module, data, parent):
        rows.append((h, etype, module, data, parent, 1.0 + len(rows), 0))

    add('root', 'ROOT', '', TARGET, 'ROOT')
    add('seed', 'HUMAN_NAME', 'SpiderFoot UI', TARGET, 'root')

    # the target's own handles
    add('user_exact', 'USERNAME', 'sfp_accounts', 'marcus.elias.thornwood', 'seed')
    add('acct_exact', 'ACCOUNT_EXTERNAL_OWNED', 'sfp_accounts',
        'ExampleSite (Category: social)\n<SFURL>https://example-social.test/@marcus.elias.thornwood</SFURL>', 'user_exact')
    add('fb_initial', 'SOCIAL_MEDIA', 'sfp_socialprofiles', 'Facebook: <SFURL>https://www.facebook.com/marcus.e.thornwood/</SFURL>', 'seed')
    add('fb_nameonly', 'SOCIAL_MEDIA', 'sfp_socialprofiles', 'Facebook: <SFURL>https://www.facebook.com/marcus.thornwood.12/</SFURL>', 'seed')
    add('fb_other_mid', 'SOCIAL_MEDIA', 'sfp_socialprofiles', 'Facebook: <SFURL>https://www.facebook.com/marcus.k.thornwood/</SFURL>', 'seed')
    add('fb_nothing', 'SOCIAL_MEDIA', 'sfp_socialprofiles', 'Facebook: <SFURL>https://www.facebook.com/SkyFan0042/</SFURL>', 'seed')

    # a physician with another middle name (NPI registry): record = license + raw + address + phone
    add('npi_lic', 'PROFESSIONAL_LICENSE', 'sfp_npiregistry',
        'MARCUS ADRIAN THORNWOOD, MD · 2085R0001X · state licence 12345 (MO) · NPI 1000000001 (individual) · https://npi.test/provider-view/1000000001', 'seed')
    add('npi_raw', 'RAW_RIR_DATA', 'sfp_npiregistry',
        '{"number": 1000000001, "basic": {"first_name": "MARCUS", "middle_name": "ADRIAN", "last_name": "THORNWOOD"}, '
        '"addresses": [{"address_1": "1 TEST ST", "city": "SPRINGFIELD", "state": "MO", "telephone_number": "555-010-0001"}]}', 'seed')
    add('npi_addr', 'PHYSICAL_ADDRESS', 'sfp_npiregistry', '1 TEST ST, SPRINGFIELD, MO, 65800', 'seed')
    add('npi_phone', 'PHONE_NUMBER', 'sfp_npiregistry', '555-010-0001', 'seed')

    # a broker whose summary has no middle name, but whose raw record lists an alias with another middle initial
    add('bc_lic', 'PROFESSIONAL_LICENSE', 'sfp_brokercheck',
        'Marcus Thornwood · FINRA BrokerCheck CRD 9000001 · broker (active) · current firm: EXAMPLE SECURITIES LLC · https://bc.test/individual/summary/9000001', 'seed')
    add('bc_raw', 'RAW_RIR_DATA', 'sfp_brokercheck',
        '{"ind_source_id": "9000001", "ind_firstname": "Marcus", "ind_lastname": "Thornwood", "ind_other_names": ["MARCUS K THORNWOOD"]}', 'seed')
    add('bc_firm', 'COMPANY_NAME', 'sfp_brokercheck', 'Example Securities Llc', 'seed')
    # ... and what hangs off that firm
    add('firm_lei', 'LEI', 'sfp_gleif', '5493000TESTLEI0000X1', 'bc_firm')
    add('firm_addr', 'PHYSICAL_ADDRESS', 'sfp_gleif', '9 Example Plaza, Metropolis, NY, 10001', 'bc_firm')
    add('firm_coord', 'PHYSICAL_COORDINATES', 'sfp_openstreetmap', '40.0000000,-74.0000000', 'firm_addr')
    for i in range(5):
        add(f'firm_wifi{i}', 'WIFI_ACCESS_POINT', 'sfp_wigle', f'Net{i} (Net ID: 00:00:00:00:00:0{i})', 'firm_coord')
    add('firm_mail', 'EMAILADDR', 'sfp_email', 'records@example-securities.test', 'firm_addr')

    # a broker with the same first and last name and no middle name anywhere: unclear
    add('bc2_lic', 'PROFESSIONAL_LICENSE', 'sfp_brokercheck',
        'Marcus Thornwood · FINRA BrokerCheck CRD 9000002 · broker (inactive) · https://bc.test/individual/summary/9000002', 'seed')
    add('bc2_raw', 'RAW_RIR_DATA', 'sfp_brokercheck',
        '{"ind_source_id": "9000002", "ind_firstname": "Marcus", "ind_lastname": "Thornwood", "ind_other_names": []}', 'seed')

    # a full-text name hit in a company's filings, and the fan-out through its officers
    add('edgar_raw', 'RAW_RIR_DATA', 'sfp_sec_edgar',
        '{"source": "SEC EDGAR full-text search", "person": "marcus thornwood", "company": "Acme Widgets Inc.", "cik": "0001234567", '
        '"note": "Matched on name only: check the filing."}', 'seed')
    add('acme', 'COMPANY_NAME', 'sfp_sec_edgar', 'Acme Widgets Inc.', 'seed')
    add('acme_filing', 'COMPANY_FILING', 'sfp_sec_edgar',
        'Acme Widgets Inc. · Form 10-K · 2020-01-01 · https://www.sec.gov/Archives/edgar/data/1234567/000000000020000001/a10k.htm', 'seed')
    add('officer', 'HUMAN_NAME', 'sfp_us_state_registries', 'Dana Q Pellham', 'acme')
    add('officer_co', 'COMPANY_NAME', 'sfp_sec_edgar', 'Globex Corporation', 'officer')
    add('officer_addr', 'PHYSICAL_ADDRESS', 'sfp_epa_echo', '1 INDUSTRIAL WAY, DAYTON, OH 45400', 'officer_co')
    add('officer_mail', 'EMAILADDR', 'sfp_email', 'legal@globex.test', 'officer_co')
    add('acme_addr', 'PHYSICAL_ADDRESS', 'sfp_gleif', '5 Widget Rd, Atlanta, GA, 30301', 'acme')
    add('acme_wifi', 'WIFI_ACCESS_POINT', 'sfp_wigle', 'Lobby (Net ID: 00:00:00:00:00:99)', 'acme_addr')
    return rows
