#!/usr/bin/env python3
"""Tests for dns_lookup's pure parsing logic.

Deliberately network-free: every case here is a function that takes a record
(or a response code) and returns a verdict. Those are exactly where the bugs
have been — a substring match that fired on the wrong record, a TXT join that
corrupted long keys, an RBL code read as a listing — and they need no resolver
to catch.

Run with:  python3 -m unittest discover  (or: python3 test_dns_lookup.py)
"""

import unittest

import dns_lookup as dl


class FakeTXT:
    """Stands in for dnspython's TXT rdata, which exposes .strings as bytes."""

    def __init__(self, *chunks):
        self.strings = [c.encode() if isinstance(c, str) else c for c in chunks]


class DecodeTxtTests(unittest.TestCase):
    def test_single_string_is_returned_as_is(self):
        self.assertEqual(dl.decode_txt(FakeTXT("v=spf1 -all")), "v=spf1 -all")

    def test_chunks_concatenate_with_no_separator(self):
        # RFC 7208 3.3 / RFC 6376 3.6.2.2. Joining with a space used to splice
        # one into the middle of every record over 255 bytes.
        self.assertEqual(dl.decode_txt(FakeTXT("abc", "def")), "abcdef")

    def test_split_dkim_key_stays_intact(self):
        key = "M" * 255
        rest = "IIBIjANBg"
        self.assertEqual(dl.decode_txt(FakeTXT("v=DKIM1; p=" + key, rest)),
                         "v=DKIM1; p=" + key + rest)

    def test_split_spf_mechanism_is_not_broken_in_two(self):
        rec = dl.decode_txt(FakeTXT("v=spf1 ip4:62.253.2", "27.114 ~all"))
        self.assertIn("ip4:62.253.227.114", rec)

    def test_undecodable_bytes_do_not_raise(self):
        self.assertIn("�", dl.decode_txt(FakeTXT(b"\xff\xfe")))


class ClassifyDkimTests(unittest.TestCase):
    def test_full_record(self):
        self.assertEqual(dl.classify_dkim_txt("v=DKIM1; k=rsa; p=MIIBIjANBg"), "ok")

    def test_record_without_version_tag(self):
        # Common in the wild (Cloudflare's s1 selector, for one).
        self.assertEqual(dl.classify_dkim_txt("k=rsa; t=s; p=MIGfMA0GCS"), "ok")

    def test_empty_p_tag_is_revoked(self):
        # RFC 6376 3.6.1: an empty p= means the key was revoked.
        self.assertEqual(dl.classify_dkim_txt("v=DKIM1; k=rsa; p="), "revoked")
        self.assertEqual(dl.classify_dkim_txt("v=DKIM1; k=rsa; p=;"), "revoked")

    def test_whitespace_only_p_tag_is_revoked(self):
        self.assertEqual(dl.classify_dkim_txt("v=DKIM1; p=   "), "revoked")

    def test_version_without_key(self):
        self.assertEqual(dl.classify_dkim_txt("v=DKIM1; k=rsa"), "malformed")

    def test_unrelated_txt_records_are_not_keys(self):
        # The old check was `"p=" in txt`, which fired on anything containing
        # those two characters — a wildcard TXT under _domainkey included.
        for txt in ("v=spf1 include:_spf.google.com -all",
                    "google-site-verification=abc123",
                    "note=set p= later",
                    "some-verification=x"):
            with self.subTest(txt=txt):
                self.assertIsNone(dl.classify_dkim_txt(txt))

    def test_folded_key_is_still_ok(self):
        self.assertEqual(dl.classify_dkim_txt("v=DKIM1; p=MIIB abcd"), "ok")


class ParseSpfTests(unittest.TestCase):
    def levels(self, txt):
        return [level for level, _ in dl.parse_spf(txt)]

    def test_hard_fail_passes(self):
        self.assertIn("ok", self.levels("v=spf1 ip4:1.2.3.4 -all"))

    def test_soft_fail_warns(self):
        levels = self.levels("v=spf1 ip4:1.2.3.4 ~all")
        self.assertIn("warn", levels)
        self.assertNotIn("ok", levels)

    def test_plus_all_is_a_failure(self):
        self.assertIn("fail", self.levels("v=spf1 +all"))

    def test_includes_are_reported(self):
        msgs = [m for level, m in dl.parse_spf("v=spf1 include:a.test -all")
                if level == "info"]
        self.assertTrue(any("a.test" in m for m in msgs))

    def test_more_than_ten_lookups_is_flagged(self):
        txt = "v=spf1 " + " ".join(f"include:h{i}.test" for i in range(11)) + " -all"
        msgs = [m for level, m in dl.parse_spf(txt) if level == "warn"]
        self.assertTrue(any("limit is 10" in m for m in msgs), msgs)

    def test_ten_lookups_is_within_the_limit(self):
        txt = "v=spf1 " + " ".join(f"include:h{i}.test" for i in range(10)) + " -all"
        self.assertFalse([m for level, m in dl.parse_spf(txt)
                          if level == "warn" and "limit is 10" in m])


class ParseDmarcTests(unittest.TestCase):
    def levels(self, txt):
        return [level for level, _ in dl.parse_dmarc(txt)]

    def test_reject_passes(self):
        self.assertIn("ok", self.levels("v=DMARC1; p=reject; rua=mailto:a@b.test"))

    def test_none_is_monitoring_only(self):
        levels = self.levels("v=DMARC1; p=none; rua=mailto:a@b.test")
        self.assertIn("warn", levels)
        self.assertNotIn("ok", levels)

    def test_policy_is_read_up_to_the_delimiter(self):
        # `p=(\S+)` used to swallow the semicolon and fail to match "reject".
        msgs = [m for level, m in dl.parse_dmarc("v=DMARC1;p=reject;pct=100")
                if level == "ok"]
        self.assertTrue(any("reject" in m for m in msgs))

    def test_pct_and_sp_tags_do_not_shadow_the_policy(self):
        # `p=` must not match inside "sp=" or "pct=".
        msgs = [m for level, m in dl.parse_dmarc("v=DMARC1; sp=none; pct=100; p=reject")
                if level == "ok"]
        self.assertTrue(any("reject" in m for m in msgs))

    def test_missing_rua_is_flagged(self):
        self.assertIn("warn", self.levels("v=DMARC1; p=reject"))


class RblResponseTests(unittest.TestCase):
    """127.0.0.x means listed; anything else is the list refusing the query."""

    def test_genuine_listing(self):
        self.assertTrue(any(a.startswith("127.0.0.") for a in ["127.0.0.2"]))

    def test_public_resolver_refusal_is_not_a_listing(self):
        # Spamhaus answers 127.255.255.x when it refuses a query. Treating that
        # as a hit reported every IP on the internet as blacklisted.
        for code in ("127.255.255.252", "127.255.255.254", "127.255.255.255"):
            with self.subTest(code=code):
                self.assertFalse(code.startswith("127.0.0."))


class ReverseIpTests(unittest.TestCase):
    def test_octets_are_reversed(self):
        self.assertEqual(dl.reverse_ip("1.2.3.4"), "4.3.2.1")


class DkimSelectorListTests(unittest.TestCase):
    def test_provider_selectors_are_present(self):
        for sel in ("cf2024-1", "fm1", "pm", "protonmail", "selector1", "google"):
            with self.subTest(sel=sel):
                self.assertIn(sel, dl.COMMON_DKIM_SELECTORS)

    def test_list_has_no_duplicates(self):
        self.assertEqual(len(dl.COMMON_DKIM_SELECTORS),
                         len(set(dl.COMMON_DKIM_SELECTORS)))

    def test_every_hinted_selector_is_in_the_common_list(self):
        # A provider hint that names a selector absent from the common list
        # would only ever be probed for domains matching that provider.
        for _pattern, name, sels in dl.PROVIDER_DKIM_HINTS:
            for sel in sels:
                with self.subTest(provider=name, sel=sel):
                    self.assertIn(sel, dl.COMMON_DKIM_SELECTORS)


class StructureRecordTests(unittest.TestCase):
    """--json must emit the parts, not the padded display string."""

    def test_mx_is_decomposed(self):
        rdata = type("MX", (), {"preference": 10, "exchange": "mail.a.test."})()
        self.assertEqual(dl.structure_record("MX", rdata),
                         {"preference": 10, "exchange": "mail.a.test"})

    def test_srv_is_decomposed(self):
        rdata = type("SRV", (), {"priority": 1, "weight": 5, "port": 443,
                                 "target": "svc.a.test."})()
        self.assertEqual(dl.structure_record("SRV", rdata),
                         {"priority": 1, "weight": 5, "port": 443,
                          "target": "svc.a.test"})

    def test_caa_decodes_its_bytes_fields(self):
        rdata = type("CAA", (), {"flags": 0, "tag": b"issue",
                                 "value": b"letsencrypt.org"})()
        self.assertEqual(dl.structure_record("CAA", rdata),
                         {"flags": 0, "tag": "issue", "value": "letsencrypt.org"})

    def test_txt_keeps_the_plain_value_key(self):
        self.assertEqual(dl.structure_record("TXT", FakeTXT("abc", "def")),
                         {"value": "abcdef"})

    def test_simple_types_keep_the_plain_value_key(self):
        self.assertEqual(dl.structure_record("A", "104.16.132.229"),
                         {"value": "104.16.132.229"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
