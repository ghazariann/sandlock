# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.sandbox.Sandbox."""

import os
from unittest.mock import patch, MagicMock

import pytest

from sandlock.policy import Policy
from sandlock.sandbox import Sandbox
from sandlock.exceptions import SandboxError


class TestSandboxInit:
    def test_default_id(self):
        sb = Sandbox(Policy())
        assert len(sb.id) == 12

    def test_custom_id(self):
        sb = Sandbox(Policy(), sandbox_id="test-123")
        assert sb.id == "test-123"

    def test_policy_stored(self):
        p = Policy(max_memory="512M")
        sb = Sandbox(p)
        assert sb.policy is p

    def test_not_alive_initially(self):
        sb = Sandbox(Policy())
        assert not sb.alive

    def test_from_profile_name(self, tmp_path, monkeypatch):
        import sandlock._profile as mod
        monkeypatch.setattr(mod, "_PROFILES_DIR", tmp_path)
        (tmp_path / "test.toml").write_text(
            'max_memory = "256M"\nclean_env = true\n'
        )
        sb = Sandbox("test")
        assert sb.policy.max_memory == "256M"
        assert sb.policy.clean_env is True
        assert sb.pid is None


class TestSandboxCall:
    def test_simple_callable(self):
        result = Sandbox(Policy()).call(lambda: 42)
        assert result.success
        assert result.value == 42

    def test_callable_with_args(self):
        result = Sandbox(Policy()).call(lambda x, y: x + y, args=(3, 4))
        assert result.success
        assert result.value == 7

    def test_callable_exception(self):
        def bad():
            raise ValueError("boom")

        result = Sandbox(Policy()).call(bad)
        assert not result.success
        assert "ValueError" in result.error

    def test_callable_returns_string(self):
        result = Sandbox(Policy()).call(lambda: "hello")
        assert result.success
        assert result.value == "hello"

    def test_callable_returns_dict(self):
        result = Sandbox(Policy()).call(lambda: {"key": "value"})
        assert result.success
        assert result.value == {"key": "value"}

    def test_callable_returns_list(self):
        result = Sandbox(Policy()).call(lambda: [1, 2, 3])
        assert result.success
        assert result.value == [1, 2, 3]


class TestSandboxRun:
    def test_simple_command(self):
        result = Sandbox(Policy()).run(["echo", "hello"])
        assert result.success
        assert b"hello" in result.stdout

    def test_command_failure(self):
        result = Sandbox(Policy()).run(["false"])
        assert not result.success
        assert result.exit_code != 0

    def test_command_not_found(self):
        result = Sandbox(Policy()).run(["nonexistent_command_xyz"])
        assert not result.success

    def test_stderr_captured(self):
        result = Sandbox(Policy()).run(
            ["python3", "-c", "import sys; sys.stderr.write('err\\n')"]
        )
        assert b"err" in result.stderr


class TestSandboxContextManager:
    def test_enter_exit(self):
        with Sandbox(Policy()) as sb:
            assert sb.id
        assert not sb.alive

    def test_exec_requires_context(self):
        sb = Sandbox(Policy())
        with pytest.raises(SandboxError, match="context manager"):
            sb.exec(["echo", "hello"])

    def test_pause_without_running_process(self):
        with Sandbox(Policy()) as sb:
            with pytest.raises(SandboxError, match="No running process"):
                sb.pause()

    def test_resume_without_running_process(self):
        with Sandbox(Policy()) as sb:
            with pytest.raises(SandboxError, match="No running process"):
                sb.resume()


class TestSandboxNested:
    def test_nested_returns_sandbox(self):
        sb = Sandbox(Policy())
        inner = sb.sandbox(Policy(max_memory="256M"))
        assert isinstance(inner, Sandbox)
        assert inner.policy.max_memory == "256M"


class TestCpuThrottle:
    """Test SIGSTOP/SIGCONT CPU throttling."""

    @staticmethod
    def _burn_cpu():
        """Fixed CPU workload (not wall-clock dependent)."""
        total = 0
        for _ in range(20_000_000):
            total += 1
        return total

    def test_throttle_slows_execution(self):
        """50% throttle should take roughly 2x wall time."""
        import time

        # Baseline without throttle
        t0 = time.monotonic()
        Sandbox(Policy()).call(self._burn_cpu)
        base = time.monotonic() - t0

        # 50% throttle
        t0 = time.monotonic()
        result = Sandbox(Policy(max_cpu=50)).call(self._burn_cpu)
        throttled = time.monotonic() - t0

        assert result.success
        ratio = throttled / base
        # Allow generous range: 1.5x–3.0x (signal jitter, CI variance)
        assert 1.5 <= ratio <= 3.0, f"ratio={ratio:.1f}, expected ~2.0"

    def test_throttle_100_is_noop(self):
        """max_cpu=100 should not start a throttle thread."""
        result = Sandbox(Policy(max_cpu=100)).call(self._burn_cpu)
        assert result.success

    def test_throttle_result_correct(self):
        """Throttled process should still return correct results."""
        result = Sandbox(Policy(max_cpu=50)).call(self._burn_cpu)
        assert result.success
        assert result.value == 20_000_000
