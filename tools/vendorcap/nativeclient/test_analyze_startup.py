import unittest

from analyze_startup import parse, summarize


SAMPLE = ('SPIDER_PROFILE fd=6 base=100000 logged=500 allocated=520 transferred=530 '
          'handoff=540 fetch=560 create=580 created=700 entry=650 request_entry=710 '
          'wake=0 opening=570 request=900')


class StartupTests(unittest.TestCase):
    def test_intervals(self):
        result = summarize(parse(SAMPLE), 1)
        self.assertEqual(result['intervals']['refusal_logging']['median_us'], 0.5)
        self.assertEqual(result['intervals']['session_allocation']['median_us'], 0.02)
        self.assertEqual(result['intervals']['handoff_to_first_headers']['median_us'], 0.36)
        self.assertFalse(result['G2Closed'])

    def test_bad_samples(self):
        for changed in (SAMPLE + '\n' + SAMPLE,
                        SAMPLE.replace('logged=500', 'logged=521'),
                        SAMPLE.replace('entry=650', 'entry=0'),
                        SAMPLE.replace('request_entry=710', 'request_entry=999'),
                        SAMPLE.replace('wake=0', 'wake=901'),
                        SAMPLE.replace('opening=570', 'opening=539'),
                        SAMPLE.replace('base=100000', 'base=0'),
                        SAMPLE.replace('logged=500', 'logged=-1'),
                        SAMPLE.replace(' allocated=520', '')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                parse(changed)

    def test_count(self):
        for expected in (0, 2):
            with self.assertRaises(ValueError):
                summarize(parse(SAMPLE), expected)
        with self.assertRaises(ValueError):
            summarize(parse('ordinary log only'), 1)


if __name__ == '__main__':
    unittest.main()
