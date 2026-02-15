#!/usr/bin/env python3

import os
import tempfile
import unittest
import ipaddress
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

import switchstash


class TestIsReachable(unittest.TestCase):
    @patch("switchstash.subprocess.run")
    def test_is_reachable_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        self.assertTrue(switchstash.is_reachable("127.0.0.1"))

    @patch("switchstash.subprocess.run")
    def test_is_reachable_failure(self, mock_run):
        from subprocess import CalledProcessError

        mock_run.side_effect = CalledProcessError(1, "ping")
        self.assertFalse(switchstash.is_reachable("192.0.2.1"))


class TestParseNetworks(unittest.TestCase):
    def test_parse_single_network(self):
        result = switchstash.parse_networks("192.168.1.0/24")
        self.assertEqual(result, ["192.168.1.0/24"])

    def test_parse_multiple_networks(self):
        result = switchstash.parse_networks("192.168.1.0/24,10.0.0.0/8")
        self.assertEqual(result, ["192.168.1.0/24", "10.0.0.0/8"])

    def test_parse_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("192.168.1.0/24\n")
            f.write("# comment\n")
            f.write("10.0.0.0/8\n")
            f.flush()

            result = switchstash.parse_networks(f"@{f.name}")
            os.unlink(f.name)

        self.assertEqual(result, ["192.168.1.0/24", "10.0.0.0/8"])


class TestRenderTemplate(unittest.TestCase):
    def test_render_hostname(self):
        result = switchstash.render_template(
            "show run | include {{hostname}}", "Router1", "192.168.1.1"
        )
        self.assertEqual(result, "show run | include Router1")

    def test_render_ip(self):
        result = switchstash.render_template("ping {{ip}}", "Router1", "192.168.1.1")
        self.assertEqual(result, "ping 192.168.1.1")

    def test_render_no_template(self):
        result = switchstash.render_template(
            "show running-config", "Router1", "192.168.1.1"
        )
        self.assertEqual(result, "show running-config")


class TestRunHook(unittest.TestCase):
    @patch("switchstash.subprocess.run")
    def test_run_hook_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="ok")
        result = switchstash.run_hook("./test.sh", "192.168.1.1", "Router1", "pre")
        self.assertTrue(result)

    @patch("switchstash.subprocess.run")
    def test_run_hook_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        result = switchstash.run_hook("./test.sh", "192.168.1.1", "Router1", "post")
        self.assertFalse(result)

    @patch("switchstash.subprocess.run")
    def test_run_hook_timeout(self, mock_run):
        from subprocess import TimeoutExpired

        mock_run.side_effect = TimeoutExpired("cmd", 1)
        result = switchstash.run_hook("./test.sh", "192.168.1.1", "Router1", "pre")
        self.assertFalse(result)


class TestDiscoverHosts(unittest.TestCase):
    @patch("switchstash.is_reachable")
    def test_discover_hosts_all_reachable(self, mock_reachable):
        mock_reachable.return_value = True
        result = switchstash.discover_hosts(["192.168.1.0/30"])
        self.assertEqual(len(result), 2)  # /30 has 2 hosts

    @patch("switchstash.is_reachable")
    def test_discover_hosts_none_reachable(self, mock_reachable):
        mock_reachable.return_value = False
        result = switchstash.discover_hosts(["192.168.1.0/30"])
        self.assertEqual(len(result), 0)


class TestProcessHost(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    @patch("switchstash.is_reachable")
    @patch("switchstash.ConnectHandler")
    @patch("switchstash.run_hook")
    def test_process_host_success(self, mock_hook, mock_connect, mock_reachable):
        mock_reachable.return_value = True
        mock_connection = MagicMock()
        mock_connection.send_command.return_value = "hostname Router1\n"
        mock_connect.return_value = mock_connection

        result = switchstash.process_host(
            "192.168.1.1",
            "admin",
            "pass",
            None,
            "cisco_ios",
            Path(self.temp_dir),
            ["show running-config"],
            1,
            1,
            1,
            False,
            False,
        )

        self.assertEqual(result[0], "192.168.1.1")
        self.assertTrue(result[1])
        self.assertEqual(result[2], "success")

    @patch("switchstash.is_reachable")
    def test_process_host_unreachable(self, mock_reachable):
        mock_reachable.return_value = False

        result = switchstash.process_host(
            "192.168.1.1",
            "admin",
            "pass",
            None,
            "cisco_ios",
            Path(self.temp_dir),
            ["show running-config"],
            1,
            1,
            1,
            False,
            False,
        )

        self.assertEqual(result, ("192.168.1.1", False, "unreachable"))

    @patch("switchstash.is_reachable")
    def test_process_host_dry_run(self, mock_reachable):
        mock_reachable.return_value = True

        result = switchstash.process_host(
            "192.168.1.1",
            "admin",
            "pass",
            None,
            "cisco_ios",
            Path(self.temp_dir),
            ["show running-config"],
            1,
            1,
            1,
            True,  # dry_run
            False,  # auto_detect
        )

        self.assertEqual(result, ("192.168.1.1", True, "dry_run_192.168.1.1"))

    @patch("switchstash.is_reachable")
    @patch("switchstash.ConnectHandler")
    @patch("switchstash.run_hook")
    def test_process_host_with_hooks(self, mock_hook, mock_connect, mock_reachable):
        mock_reachable.return_value = True
        mock_connection = MagicMock()
        mock_connection.send_command.return_value = "hostname Router1\n"
        mock_connect.return_value = mock_connection
        mock_hook.return_value = True

        result = switchstash.process_host(
            "192.168.1.1",
            "admin",
            "pass",
            None,
            "cisco_ios",
            Path(self.temp_dir),
            ["show running-config"],
            1,
            1,
            1,
            False,  # dry_run
            False,  # auto_detect
            pre_hook="./pre.sh",
            post_hook="./post.sh",
        )

        self.assertGreaterEqual(mock_hook.call_count, 2)

    @patch("switchstash.is_reachable")
    @patch("switchstash.ConnectHandler")
    def test_process_host_auth_error(self, mock_connect, mock_reachable):
        mock_reachable.return_value = True
        from netmiko import NetmikoAuthenticationException

        mock_connect.side_effect = NetmikoAuthenticationException("Auth failed")

        result = switchstash.process_host(
            "192.168.1.1",
            "admin",
            "wrongpass",
            None,
            "cisco_ios",
            Path(self.temp_dir),
            ["show running-config"],
            1,
            1,
            1,
            False,
            False,
        )

        self.assertFalse(result[1])
        self.assertIn("Auth failed", result[2])

    @patch("switchstash.is_reachable")
    @patch("switchstash.ConnectHandler")
    def test_process_host_timeout(self, mock_connect, mock_reachable):
        mock_reachable.return_value = True
        from netmiko import NetmikoTimeoutException

        mock_connect.side_effect = NetmikoTimeoutException("Connection timed out")

        result = switchstash.process_host(
            "192.168.1.1",
            "admin",
            "pass",
            None,
            "cisco_ios",
            Path(self.temp_dir),
            ["show running-config"],
            1,
            1,
            1,
            False,
            False,
        )

        self.assertFalse(result[1])


class TestDiff(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def test_diff_configs_identical(self):
        content = "hostname Router1\ninterface GigabitEthernet0/0\n"

        path1 = Path(self.temp_dir) / "router1a.cfg"
        path2 = Path(self.temp_dir) / "router1b.cfg"

        path1.write_text(content)
        path2.write_text(content)

        same, diff = switchstash.diff_configs(path1, path2)

        self.assertTrue(same)
        self.assertEqual(diff, [])

    def test_diff_configs_different(self):
        content1 = "hostname Router1\ninterface GigabitEthernet0/0\n"
        content2 = "hostname Router2\ninterface GigabitEthernet0/0\n"

        path1 = Path(self.temp_dir) / "router1.cfg"
        path2 = Path(self.temp_dir) / "router2.cfg"

        path1.write_text(content1)
        path2.write_text(content2)

        same, diff = switchstash.diff_configs(path1, path2)

        self.assertFalse(same)
        self.assertTrue(len(diff) > 0)

    def test_has_config_changed(self):
        path1 = Path(self.temp_dir) / "router1.cfg"
        path2 = Path(self.temp_dir) / "router2.cfg"

        path1.write_text("hostname Router1\n")
        path2.write_text("hostname Router2\n")

        self.assertTrue(switchstash.has_config_changed(path1, path2))

        path2.write_text("hostname Router1\n")
        self.assertFalse(switchstash.has_config_changed(path1, path2))


class TestGenerateHtmlReport(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def test_generate_html_report(self):
        output_path = Path(self.temp_dir) / "report.html"
        output_dir = Path(self.temp_dir)

        # Create some dummy config files
        (output_dir / "router1.cfg").write_text("hostname router1")
        (output_dir / "router2.cfg").write_text("hostname router2")

        switchstash.generate_html_report(
            output_path,
            ["router1", "router2"],
            [("router3", "timeout")],
            output_dir,
            "192.168.1.0/24",
        )

        self.assertTrue(output_path.exists())
        content = output_path.read_text()

        self.assertIn("HostHoover Backup Report", content)
        self.assertIn("2", content)  # successful
        self.assertIn("1", content)  # failed
        self.assertIn("192.168.1.0/24", content)


class TestDeviceTimeouts(unittest.TestCase):
    def test_device_timeouts_defined(self):
        self.assertIn("cisco_ios", switchstash.DEVICE_TIMEOUTS)
        self.assertIn("juniper_junos", switchstash.DEVICE_TIMEOUTS)
        self.assertIn("cisco_nxos", switchstash.DEVICE_TIMEOUTS)

    def test_device_timeout_structure(self):
        for device_type, timeouts in switchstash.DEVICE_TIMEOUTS.items():
            self.assertIn("connect", timeouts)
            self.assertIn("command", timeouts)


class TestGetJitter(unittest.TestCase):
    def test_get_jitter_increases_with_attempt(self):
        jitter0 = switchstash.get_jitter(0)
        jitter1 = switchstash.get_jitter(1)
        jitter2 = switchstash.get_jitter(2)

        # Base increases, but jitter adds randomness
        self.assertGreater(jitter1, 0)
        self.assertGreater(jitter2, 0)

    def test_get_jitter_capped(self):
        jitter10 = switchstash.get_jitter(10)
        # Should be capped at ~30 + jitter
        self.assertLess(jitter10, 35)


class TestLoadConfig(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def test_load_config(self):
        config_file = Path(self.temp_dir) / "config.yaml"
        config_file.write_text("""
username: admin
password: secret
device_type: cisco_ios
max_retries: 5
""")

        cfg = switchstash.load_config(config_file)

        self.assertEqual(cfg["username"], "admin")
        self.assertEqual(cfg["password"], "secret")
        self.assertEqual(cfg["device_type"], "cisco_ios")
        self.assertEqual(cfg["max_retries"], 5)


class TestValidateConfig(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def test_validate_valid_config(self):
        config_file = Path(self.temp_dir) / "config.yaml"
        config_file.write_text("""
username: admin
password: secret
device_type: cisco_ios
""")

        result = switchstash.validate_config(config_file)

        self.assertTrue(result["valid"])
        self.assertEqual(len(result["errors"]), 0)

    def test_validate_missing_username(self):
        config_file = Path(self.temp_dir) / "config.yaml"
        config_file.write_text("""
password: secret
""")

        result = switchstash.validate_config(config_file)

        # Missing username is now a warning when no groups defined
        self.assertTrue(result["valid"])
        self.assertTrue(any("username" in w for w in result["warnings"]))

    def test_validate_missing_auth(self):
        config_file = Path(self.temp_dir) / "config.yaml"
        config_file.write_text("""
username: admin
""")

        result = switchstash.validate_config(config_file)

        # Missing auth is now a warning when no groups defined
        self.assertTrue(result["valid"])
        self.assertTrue(any("auth" in w for w in result["warnings"]))

    def test_validate_with_key_file(self):
        config_file = Path(self.temp_dir) / "config.yaml"
        config_file.write_text("""
username: admin
key_file: ~/.ssh/id_rsa
""")

        result = switchstash.validate_config(config_file)

        self.assertTrue(result["valid"])

    def test_validate_invalid_timeout(self):
        config_file = Path(self.temp_dir) / "config.yaml"
        config_file.write_text("""
username: admin
password: secret
connect_timeout: 0
""")

        result = switchstash.validate_config(config_file)

        self.assertFalse(result["valid"])
        self.assertIn("connect_timeout", result["errors"][0])

    def test_validate_warnings(self):
        config_file = Path(self.temp_dir) / "config.yaml"
        config_file.write_text("""
username: admin
password: secret
auto_detect: true
""")

        result = switchstash.validate_config(config_file)

        self.assertTrue(result["valid"])
        self.assertTrue(any("auto_detect" in w for w in result["warnings"]))


if __name__ == "__main__":
    unittest.main()
