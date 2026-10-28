import unittest
from revision.src.run_benchmark_stable import guard_deterministic, sanitize_decision

def mock_route(strategy, t1_res, t2_res, t3_res):
    # Simulation of Option A: Rejection Cascade
    if strategy == "FullCascade":
        if t1_res == "FAIL": return "FAIL", "Tier1"
        if t1_res == "PASS":
            if t2_res == "FAIL": return "FAIL", "Tier2"
            if t2_res in ["PASS", "UNSURE"]:
                return t3_res, "Tier3"
    return "ERROR", "unknown"

class TestRouting(unittest.TestCase):
    def test_t1_fail_skips_all(self):
        # T1 FAIL -> Final FAIL (Tier 1)
        res, route = mock_route("FullCascade", "FAIL", "PASS", "PASS")
        self.assertEqual(res, "FAIL")
        self.assertEqual(route, "Tier1")

    def test_t2_fail_skips_t3(self):
        # T1 PASS -> T2 FAIL -> Final FAIL (Tier 2)
        res, route = mock_route("FullCascade", "PASS", "FAIL", "PASS")
        self.assertEqual(res, "FAIL")
        self.assertEqual(route, "Tier2")

    def test_t2_pass_invokes_t3(self):
        # T1 PASS -> T2 PASS -> T3 FAIL -> Final FAIL (Tier 3)
        res, route = mock_route("FullCascade", "PASS", "PASS", "FAIL")
        self.assertEqual(res, "FAIL")
        self.assertEqual(route, "Tier3")

    def test_t2_unsure_invokes_t3(self):
        # T1 PASS -> T2 UNSURE -> T3 PASS -> Final PASS (Tier 3)
        res, route = mock_route("FullCascade", "PASS", "UNSURE", "PASS")
        self.assertEqual(res, "PASS")
        self.assertEqual(route, "Tier3")

    def test_t3_pass_allows(self):
        # T1 PASS -> T2 PASS -> T3 PASS -> Final PASS (Tier 3)
        res, route = mock_route("FullCascade", "PASS", "PASS", "PASS")
        self.assertEqual(res, "PASS")
        self.assertEqual(route, "Tier3")

if __name__ == "__main__":
    unittest.main()
