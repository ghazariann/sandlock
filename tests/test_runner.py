# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock._runner."""

import json
import os

import pytest

from sandlock._runner import Result


class TestResult:
    def test_success(self):
        r = Result(success=True, value=42)
        assert r.success
        assert r.value == 42
        assert r.error is None

    def test_failure(self):
        r = Result(success=False, error="boom")
        assert not r.success
        assert r.error == "boom"

    def test_with_output(self):
        r = Result(success=True, stdout=b"hello\n", stderr=b"")
        assert r.stdout == b"hello\n"
