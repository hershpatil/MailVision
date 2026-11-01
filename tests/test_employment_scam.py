"""
Regression tests for fake job and internship scam detection.

Verifies:
  1. The exact user-reported employment scam message is classified as SPAM.
  2. Fake job offers demanding upfront fees, security deposits, or direct placement without interviews are SPAM.
  3. Legitimate recruitment emails with salary, selection, and deadlines remain HAM.
  4. Legitimate internship postings mentioning stipends and deadlines remain HAM.
  5. Isolated signals (salary alone, deadlines alone) do not trigger false positives.
"""
import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.spam_rules import SpamRuleEngine
from detection.analyzer import MessageAnalyzer


class TestEmploymentScamDetection(unittest.TestCase):
    def setUp(self):
        self.engine = SpamRuleEngine()
        self.analyzer = MessageAnalyzer()

    # ------------------------------------------------------------------
    # 1. User-reported test message: must be classified as SPAM
    # ------------------------------------------------------------------
    def test_user_reported_job_scam_classified_as_spam(self):
        """User test message demanding refundable registration fee for ₹15 LPA job must be SPAM."""
        msg = (
            "Congratulations! You have been selected for a high-paying software engineering position "
            "with a salary of ₹15 LPA. No interview or technical assessment is required. "
            "Pay a refundable registration fee of ₹2,500 today to secure your position. "
            "Limited vacancies available. Apply immediately!"
        )
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res["status"], "success")
        self.assertEqual(
            res["prediction"], "SPAM",
            f"Expected SPAM but got {res['prediction']} (spam_prob={res['spam_probability']}%)"
        )
        # Check that the employment scam indicator fired
        types = [i["type"] for i in res["indicators"]]
        self.assertIn("EMPLOYMENT_SCAM_PATTERN", types)

    def test_rule_engine_identifies_user_job_scam_signals(self):
        """Rule engine must flag is_employment_scam as True for the user test message."""
        msg = (
            "Congratulations! You have been selected for a high-paying software engineering position "
            "with a salary of ₹15 LPA. No interview or technical assessment is required. "
            "Pay a refundable registration fee of ₹2,500 today to secure your position. "
            "Limited vacancies available. Apply immediately!"
        )
        res = self.engine.analyze_rules(msg)
        self.assertTrue(res["rule_stats"]["is_employment_scam"])
        types = [i["type"] for i in res["indicators"]]
        self.assertIn("EMPLOYMENT_SCAM_PATTERN", types)

    # ------------------------------------------------------------------
    # 2. Additional fake job and internship scams: must be SPAM
    # ------------------------------------------------------------------
    def test_fake_internship_with_processing_fee_is_spam(self):
        """Fake internship requiring refundable processing fee to secure seat must be SPAM."""
        msg = (
            "Congratulations! You are selected for a Python Development Internship with a stipend of ₹20,000/month. "
            "No interview needed. Pay a refundable processing fee of ₹1,000 to confirm your seat."
        )
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["prediction"], "SPAM")
        types = [i["type"] for i in res["indicators"]]
        self.assertIn("EMPLOYMENT_SCAM_PATTERN", types)

    def test_direct_appointment_without_interview_is_scam(self):
        """Direct appointment claiming guaranteed placement without any interview or assessment."""
        msg = (
            "Direct selection for Assistant Manager vacancy! You have been selected for this position. "
            "No interview or technical assessment required. Pay a security deposit of ₹3,000 to secure your role."
        )
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res["prediction"], "SPAM")

    def test_pay_to_secure_position_phrasing(self):
        """Explicit pay-to-secure requirement for employment must be flagged."""
        msg = (
            "You have been selected for a remote data entry job. "
            "Deposit ₹1,500 today to secure your position and receive your onboarding kit."
        )
        rule_res = self.engine.analyze_rules(msg)
        self.assertTrue(rule_res["rule_stats"]["is_employment_scam"])

    # ------------------------------------------------------------------
    # 3. Legitimate recruitment emails: must remain HAM
    # ------------------------------------------------------------------
    def test_legitimate_job_offer_remains_ham(self):
        """Legitimate corporate job offer mentioning salary, benefits, and start date must remain HAM."""
        msg = (
            "Dear Alex, We are pleased to offer you the position of Senior Software Engineer at TechCorp. "
            "Your annual starting salary will be ₹18 LPA. The formal offer letter is attached. "
            "Please review, sign, and return the document by next Monday to confirm your acceptance."
        )
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res["status"], "success")
        self.assertEqual(
            res["prediction"], "HAM",
            f"Expected HAM but got {res['prediction']} (spam_prob={res['spam_probability']}%)"
        )
        types = [i["type"] for i in res["indicators"]]
        self.assertNotIn("EMPLOYMENT_SCAM_PATTERN", types)

    def test_legitimate_interview_invitation_remains_ham(self):
        """Legitimate interview invitation with assessment round must remain HAM."""
        msg = (
            "Hi Priya, Thank you for applying for the Backend Developer opening. "
            "We would like to invite you for a technical assessment and coding interview this Thursday at 2 PM. "
            "Please confirm if this time works for you."
        )
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res["prediction"], "HAM")
        types = [i["type"] for i in res["indicators"]]
        self.assertNotIn("EMPLOYMENT_SCAM_PATTERN", types)

    def test_legitimate_internship_announcement_remains_ham(self):
        """Legitimate internship notice with stipend and deadline must remain HAM."""
        msg = (
            "Dear students, applications are now open for the summer research internship in computer science. "
            "The position offers a monthly stipend of ₹25,000 and hands-on laboratory experience. "
            "Please submit your resume to the department portal https://university.edu/internships before Friday."
        )
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(
            res["prediction"], "HAM",
            f"Expected HAM for legitimate internship posting but got {res['prediction']}"
        )
        rule_res = self.engine.analyze_rules(msg)
        self.assertFalse(rule_res["rule_stats"]["is_employment_scam"])

    def test_legitimate_campus_placement_remains_ham(self):
        """Legitimate campus recruitment drive email must remain HAM."""
        msg = (
            "Dear students, Infosys will conduct a campus recruitment drive on campus next Tuesday "
            "for Graduate Trainee positions. The selection process consists of an aptitude test "
            "followed by technical and HR interviews. Register through the placement portal."
        )
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res["prediction"], "HAM")
        rule_res = self.engine.analyze_rules(msg)
        self.assertFalse(rule_res["rule_stats"]["is_employment_scam"])

    # ------------------------------------------------------------------
    # 4. Isolated signals: must NOT trigger employment scam
    # ------------------------------------------------------------------
    def test_salary_mention_alone_not_scam(self):
        """Salary mention in ordinary conversation or news must not trigger scam rule."""
        msg = "The average salary of a software engineer in Bangalore is around ₹15 LPA according to recent surveys."
        rule_res = self.engine.analyze_rules(msg)
        self.assertFalse(rule_res["rule_stats"]["is_employment_scam"])

    def test_registration_fee_for_non_employment_conference(self):
        """Registration fee for an academic conference or workshop must not trigger employment scam."""
        msg = "The Annual AI Research Conference registration is open. Pay the registration fee of ₹1,000 to attend."
        rule_res = self.engine.analyze_rules(msg)
        self.assertFalse(rule_res["rule_stats"]["is_employment_scam"])


if __name__ == "__main__":
    unittest.main()
