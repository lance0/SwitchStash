#!/usr/bin/env python3

import os
import tempfile
import unittest
from pathlib import Path

from inventory import InventoryDB


class TestInventoryDB(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test.db"
        self.db = InventoryDB(self.db_path)

    def tearDown(self):
        self.db_path.unlink(missing_ok=True)

    def test_upsert_device(self):
        device_id = self.db.upsert_device("router1", "192.168.1.1", "cisco_ios")
        self.assertIsNotNone(device_id)

        device = self.db.get_device("router1")
        self.assertEqual(device["hostname"], "router1")
        self.assertEqual(device["ip_address"], "192.168.1.1")
        self.assertEqual(device["device_type"], "cisco_ios")

    def test_upsert_device_update(self):
        self.db.upsert_device("router1", "192.168.1.1", "cisco_ios")
        self.db.upsert_device("router1", "192.168.1.2", "cisco_nxos")

        device = self.db.get_device("router1")
        self.assertEqual(device["ip_address"], "192.168.1.2")
        self.assertEqual(device["device_type"], "cisco_nxos")

    def test_get_all_devices(self):
        self.db.upsert_device("router1", "192.168.1.1", "cisco_ios")
        self.db.upsert_device("router2", "192.168.1.2", "juniper_junos")

        devices = self.db.get_all_devices()
        self.assertEqual(len(devices), 2)

    def test_record_backup(self):
        config_file = Path(self.temp_dir) / "router1.cfg"
        config_file.write_text("hostname router1\n")

        self.db.record_backup(
            hostname="router1",
            ip_address="192.168.1.1",
            device_type="cisco_ios",
            command="show running-config",
            config_file=config_file,
            status="success",
        )

        history = self.db.get_backup_history("router1")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], "success")

    def test_record_backup_with_error(self):
        self.db.record_backup(
            hostname="router1",
            ip_address="192.168.1.1",
            device_type="cisco_ios",
            command="show running-config",
            config_file=Path("nonexistent.cfg"),
            status="failed",
            error_message="Connection refused",
        )

        history = self.db.get_backup_history("router1")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], "failed")
        self.assertEqual(history[0]["error_message"], "Connection refused")

    def test_get_latest_backup(self):
        config_file = Path(self.temp_dir) / "router1.cfg"
        config_file.write_text("hostname router1\nversion 1.0\n")

        self.db.record_backup(
            hostname="router1",
            ip_address="192.168.1.1",
            device_type="cisco_ios",
            command="show running-config",
            config_file=config_file,
            status="success",
        )

        latest = self.db.get_latest_backup("router1")
        self.assertIsNotNone(latest)
        self.assertEqual(latest["status"], "success")

    def test_get_stats(self):
        self.db.upsert_device("router1", "192.168.1.1", "cisco_ios")
        self.db.upsert_device("router2", "192.168.1.2", "cisco_ios")

        config_file = Path(self.temp_dir) / "router1.cfg"
        config_file.write_text("hostname router1\n")

        self.db.record_backup(
            hostname="router1",
            ip_address="192.168.1.1",
            device_type="cisco_ios",
            command="show running-config",
            config_file=config_file,
            status="success",
        )

        stats = self.db.get_stats()
        self.assertEqual(stats["total_devices"], 2)
        self.assertEqual(stats["successful"], 2)


if __name__ == "__main__":
    unittest.main()
