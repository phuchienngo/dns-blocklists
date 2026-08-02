import textwrap
import unittest

import blocklist_builder.builder as build_module
import blocklist_builder.parsing as parsing
from blocklist_builder.parsing import parse_content


class ParseContentTest(unittest.TestCase):
    def test_progress_quantity_pluralizes_domain(self) -> None:
        self.assertEqual(build_module._quantity(2, "domain"), "2 domains")

    def test_stream_parser_accepts_one_shot_line_iterable(self) -> None:
        class OneShotLines:
            def __init__(self) -> None:
                self.iterated = False

            def __iter__(self):
                if self.iterated:
                    raise AssertionError("source was iterated more than once")
                self.iterated = True
                yield "ads.example.com\n"
                yield "allowed.example.com\n"

        entries: list[str] = []
        parsing.parse_lines(
            OneShotLines(),
            emit=entries.append,
        )

        self.assertEqual(entries, ["ads.example.com", "allowed.example.com"])

    def test_domains_are_normalized(self) -> None:
        content = """
        # comment
        Example.COM
        *.example.com
        exact.example.com.
        not_a_domain
        """

        self.assertEqual(
            parse_content(content),
            {"example.com", "exact.example.com"},
        )

    def test_adblock_extracts_domain_rules(self) -> None:
        content = """
        [Adblock Plus 2.0]
        ! comment
        ||ads.example.com^
        @@||allowed.example.com^
        ||metrics.example.com^$third-party
        ||disabled.example.com^$third-party
        ||disabled.example.com^$third-party,badfilter
        example.com##.advertisement
        /regular-expression/
        """

        try:
            domains = parse_content(content, "adblock")
        except Exception as error:
            self.fail(f"adblock format was rejected: {error}")
        self.assertEqual(
            domains,
            {"ads.example.com", "metrics.example.com"},
        )

    def test_rpz_extracts_cname_root_records(self) -> None:
        content = """
        $TTL 30
        @ IN SOA rpz.example. hostmaster.example. (
            1 3600 900 604800 30
        )
        @ IN NS localhost.
        blocked.example.com 60 IN CNAME .
        *.blocked.example.com 120 CNAME .
        exact.example.com IN CNAME .
        passthrough.example.com CNAME rpz-passthru.
        """

        try:
            domains = parse_content(textwrap.dedent(content), "rpz")
        except Exception as error:
            self.fail(f"RPZ format was rejected: {error}")
        self.assertEqual(
            domains,
            {"blocked.example.com", "exact.example.com"},
        )

