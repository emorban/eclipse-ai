import unittest

from samples.verification_gate import CompletionClaim, verify_completion


class VerificationGateTests(unittest.TestCase):
    def test_claim_passes_when_all_outputs_are_observed(self) -> None:
        claim = CompletionClaim(task="build report", claimed_outputs=("report.md", "tests:pass"))
        result = verify_completion(claim, ["report.md", "tests:pass", "extra.log"])

        self.assertTrue(result.ok)
        self.assertEqual(result.missing_outputs, ())

    def test_claim_fails_when_required_output_is_missing(self) -> None:
        claim = CompletionClaim(task="build report", claimed_outputs=("report.md", "tests:pass"))
        result = verify_completion(claim, ["report.md"])

        self.assertFalse(result.ok)
        self.assertEqual(result.missing_outputs, ("tests:pass",))


if __name__ == "__main__":
    unittest.main()
