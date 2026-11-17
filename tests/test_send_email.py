"""
Tests for the email retry and plain-language failure messages (no network: smtplib is faked).
    python3 -m unittest discover -s tests -v
"""

import os
import smtplib
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "scripts"))

import network_intel_report as nir  # noqa: E402

CFG = {"GMAIL_FROM": "a@gmail.com", "GMAIL_TO": "a@gmail.com, b@gmail.com", "GMAIL_APP_PASSWORD": "pw"}


def fake_smtp(script):
    """script: list of outcomes, one per connection attempt: None (works), or (stage, exception)."""
    calls = {"n": 0, "sent": []}

    class Fake:
        def __init__(self, host, port, timeout=None):
            self.outcome = script[min(calls["n"], len(script) - 1)]
            calls["n"] += 1
            if self.outcome and self.outcome[0] == "connect":
                raise self.outcome[1]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def login(self, user, pw):
            if self.outcome and self.outcome[0] == "login":
                raise self.outcome[1]

        def sendmail(self, frm, to, body):
            if self.outcome and self.outcome[0] == "send":
                raise self.outcome[1]
            calls["sent"].append(to)

    return Fake, calls


def run(script, **kw):
    Fake, calls = fake_smtp(script)
    sleeps = []
    with mock.patch.object(nir.smtplib, "SMTP_SSL", Fake):
        try:
            nir.send_email(CFG, "<b>x</b>", "x", "subj", _sleep=sleeps.append, **kw)
            err = None
        except SystemExit as exc:
            err = str(exc.code)
    return calls, sleeps, err


class SendEmailTest(unittest.TestCase):
    def test_success_first_try(self):
        calls, sleeps, err = run([None])
        self.assertIsNone(err)
        self.assertEqual((calls["n"], sleeps), (1, []))
        self.assertEqual(calls["sent"], [["a@gmail.com", "b@gmail.com"]])

    def test_transient_disconnects_are_retried(self):
        gone = ("login", smtplib.SMTPServerDisconnected("Connection unexpectedly closed"))
        calls, sleeps, err = run([gone, gone, None])
        self.assertIsNone(err)
        self.assertEqual(calls["n"], 3)
        self.assertEqual(sleeps, [20, 20])
        self.assertEqual(len(calls["sent"]), 1)

    def test_login_disconnect_every_time_explains_revoked_password(self):
        gone = ("login", smtplib.SMTPServerDisconnected("Connection unexpectedly closed"))
        calls, sleeps, err = run([gone])
        self.assertEqual(calls["n"], 3)
        self.assertEqual(len(sleeps), 2)                       # no pointless wait after the last try
        self.assertIn("app password", err)
        self.assertIn("myaccount.google.com/apppasswords", err)
        self.assertIn("still saved", err)
        self.assertNotIn("Traceback", err)

    def test_rejected_password_is_not_retried(self):
        bad = ("login", smtplib.SMTPAuthenticationError(535, b"bad credentials"))
        calls, sleeps, err = run([bad])
        self.assertEqual((calls["n"], sleeps), (1, []))
        self.assertIn("rejected the login", err)
        self.assertIn("535", err)

    def test_network_failure_gives_connection_advice(self):
        down = ("connect", OSError("Network is unreachable"))
        calls, _s, err = run([down])
        self.assertEqual(calls["n"], 3)
        self.assertIn("internet connection", err)
        self.assertIn("Network is unreachable", err)

    def test_missing_settings_exit_before_connecting(self):
        Fake, calls = fake_smtp([None])
        with mock.patch.object(nir.smtplib, "SMTP_SSL", Fake):
            with self.assertRaises(SystemExit) as cm:
                nir.send_email(dict(CFG, GMAIL_APP_PASSWORD=""), "h", "t", "s")
        self.assertIn("GMAIL_APP_PASSWORD", str(cm.exception.code))
        self.assertEqual(calls["n"], 0)

    def test_attempt_count_is_configurable(self):
        gone = ("login", smtplib.SMTPServerDisconnected("x"))
        calls, sleeps, _err = run([gone], attempts=1)
        self.assertEqual((calls["n"], sleeps), (1, []))


if __name__ == "__main__":
    unittest.main()
