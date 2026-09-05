from __future__ import annotations

import os
import unittest
from unittest import mock

from flask import Flask

import floraos_turnstile
from floraos_turnstile import init_turnstile, verify_turnstile_token


class TurnstileTests(unittest.TestCase):
    def make_app(self):
        app = Flask(__name__)
        app.secret_key = "test"
        return app

    def test_disabled_is_fail_open_only_when_not_required(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            app = self.make_app()
            init_turnstile(app)
            with app.test_request_context("/"):
                result = verify_turnstile_token("", expected_action="login")
                self.assertTrue(result.ok)
                self.assertEqual(result.code, "captcha_disabled")

    def test_required_without_keys_refuses_startup(self):
        with mock.patch.dict(
            os.environ,
            {"TURNSTILE_REQUIRED": "1"},
            clear=True,
        ):
            app = self.make_app()
            with self.assertRaises(RuntimeError):
                init_turnstile(app)

    def test_success_requires_matching_action_and_hostname(self):
        env = {
            "TURNSTILE_SITE_KEY": "site",
            "TURNSTILE_SECRET_KEY": "secret",
            "TURNSTILE_HOSTNAMES": "floraos.life",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            app = self.make_app()
            init_turnstile(app)

            with mock.patch.object(
                floraos_turnstile,
                "_siteverify",
                return_value={
                    "success": True,
                    "hostname": "floraos.life",
                    "action": "login",
                },
            ):
                with app.test_request_context(
                    "/",
                    headers={"CF-Connecting-IP": "203.0.113.50"},
                ):
                    result = verify_turnstile_token("abc", expected_action="login")
                    self.assertTrue(result.ok)

    def test_wrong_action_is_rejected(self):
        env = {
            "TURNSTILE_SITE_KEY": "site",
            "TURNSTILE_SECRET_KEY": "secret",
            "TURNSTILE_HOSTNAMES": "floraos.life",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            app = self.make_app()
            init_turnstile(app)

            with mock.patch.object(
                floraos_turnstile,
                "_siteverify",
                return_value={
                    "success": True,
                    "hostname": "floraos.life",
                    "action": "signup",
                },
            ):
                with app.test_request_context("/"):
                    result = verify_turnstile_token("abc", expected_action="login")
                    self.assertFalse(result.ok)
                    self.assertEqual(result.code, "captcha_failed")

    def test_wrong_hostname_is_rejected(self):
        env = {
            "TURNSTILE_SITE_KEY": "site",
            "TURNSTILE_SECRET_KEY": "secret",
            "TURNSTILE_HOSTNAMES": "floraos.life",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            app = self.make_app()
            init_turnstile(app)

            with mock.patch.object(
                floraos_turnstile,
                "_siteverify",
                return_value={
                    "success": True,
                    "hostname": "evil.example",
                    "action": "login",
                },
            ):
                with app.test_request_context("/"):
                    result = verify_turnstile_token("abc", expected_action="login")
                    self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
