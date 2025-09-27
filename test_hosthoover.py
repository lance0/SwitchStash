#!/usr/bin/env python3

import unittest
import ipaddress
from unittest.mock import patch, MagicMock
import hosthoover


class TestHostHoover(unittest.TestCase):

    def test_is_reachable_success(self):
        # Mock subprocess.run to simulate successful ping
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock()
            mock_run.return_value.returncode = 0
            self.assertTrue(hosthoover.is_reachable('127.0.0.1'))

    def test_is_reachable_failure(self):
        # Mock subprocess.run to simulate failed ping
        with patch('subprocess.run') as mock_run:
            from subprocess import CalledProcessError
            mock_run.side_effect = CalledProcessError(1, 'ping')
            self.assertFalse(hosthoover.is_reachable('192.0.2.1'))  # Non-routable IP

    @patch('hosthoover.is_reachable')
    @patch('hosthoover.ConnectHandler')
    def test_process_host_success(self, mock_connect, mock_reachable):
        mock_reachable.return_value = True
        mock_connection = MagicMock()
        mock_connection.send_command.return_value = 'hostname Router1\ninterface GigabitEthernet0/0\n'
        mock_connect.return_value = mock_connection

        result = hosthoover.process_host('192.168.1.1', 'user', 'pass', 'cisco_ios', '/tmp', None, 1, 1, 1, False)
        self.assertEqual(result[0], '192.168.1.1')
        self.assertTrue(result[1])
        self.assertIn('Router1.cfg', result[2])

    @patch('hosthoover.is_reachable')
    def test_process_host_unreachable(self, mock_reachable):
        mock_reachable.return_value = False
        result = hosthoover.process_host('192.168.1.1', 'user', 'pass', 'cisco_ios', '/tmp', None, 1, 1, 1, False)
        self.assertEqual(result, ('192.168.1.1', False, 'unreachable'))

    @patch('hosthoover.is_reachable')
    def test_process_host_dry_run(self, mock_reachable):
        mock_reachable.return_value = True
        result = hosthoover.process_host('192.168.1.1', 'user', 'pass', 'cisco_ios', '/tmp', None, 1, 1, 1, True)
        self.assertEqual(result, ('192.168.1.1', True, 'dry_run_192.168.1.1'))


if __name__ == '__main__':
    unittest.main()