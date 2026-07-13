from __future__ import annotations

import unittest

from edgewatch.parsers import (
    cpu_percent,
    memory_percent,
    parse_meminfo,
    parse_proc_net_dev,
    parse_ss_established,
    parse_ss_listeners,
    parse_wg_dump,
    summarize_ssh_journal,
)


class ParserTests(unittest.TestCase):
    def test_proc_net_dev(self) -> None:
        text = """Inter-| Receive | Transmit
 face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed
  eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0
"""
        counters = parse_proc_net_dev(text)["eth0"]
        self.assertEqual(counters.rx_bytes, 1000)
        self.assertEqual(counters.tx_bytes, 2000)
        self.assertEqual(counters.rx_errors, 1)
        self.assertEqual(counters.tx_drops, 4)

    def test_cpu_percent(self) -> None:
        self.assertEqual(cpu_percent((100, 40), (200, 60)), 80.0)
        self.assertEqual(cpu_percent(None, (200, 60)), 0.0)

    def test_meminfo(self) -> None:
        values = parse_meminfo("MemTotal: 1000 kB\nMemAvailable: 250 kB\n")
        self.assertEqual(memory_percent(values), 75.0)

    def test_ss_listeners(self) -> None:
        text = """tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*
udp UNCONN 0 0 [::]:51820 [::]:*
tcp LISTEN 0 128 127.0.0.1:8765 0.0.0.0:*
"""
        rows = parse_ss_listeners(text)
        self.assertEqual(len(rows), 3)
        self.assertTrue(rows[0].public_bind)
        self.assertTrue(rows[1].public_bind)
        self.assertFalse(rows[2].public_bind)

    def test_ss_established(self) -> None:
        text = """0 0 203.0.113.10:443 198.51.100.20:50123
0 0 10.200.0.1:40000 10.200.0.2:32400
"""
        total, remote_ips, local_ports, remote_ports = parse_ss_established(text)
        self.assertEqual(total, 2)
        self.assertEqual(remote_ips["198.51.100.20"], 1)
        self.assertEqual(local_ports[443], 1)
        self.assertEqual(remote_ports[32400], 1)

    def test_wireguard_dump(self) -> None:
        text = """private\tpublic\t51820\toff
peerkey\t(none)\t198.51.100.9:51820\t10.200.0.2/32\t1700000000\t100\t200\t25
"""
        peers = parse_wg_dump(text, "wg0")
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0].allowed_ips, ("10.200.0.2/32",))
        self.assertEqual(peers[0].transfer_tx, 200)

    def test_wireguard_dump_accepts_off_keepalive(self) -> None:
        text = """private\tpublic\t51820\toff
peerkey\t(none)\t198.51.100.9:51820\t10.200.0.2/32\t1700000000\t100\t200\toff
"""
        peers = parse_wg_dump(text, "wg0")
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0].persistent_keepalive, 0)

    def test_ssh_summary(self) -> None:
        lines = [
            "Failed password for invalid user admin from 198.51.100.8 port 50000 ssh2",
            "Invalid user test from 198.51.100.8 port 50001",
            "Accepted publickey for adminuser from 192.0.2.5 port 54321 ssh2",
        ]
        summary = summarize_ssh_journal(lines)
        self.assertEqual(summary["failed_total"], 2)
        self.assertEqual(summary["accepted_total"], 1)
        self.assertEqual(summary["failed_by_ip"][0], ("198.51.100.8", 2))

    def test_ss_connection_process_and_ipv6(self) -> None:
        from edgewatch.parsers import parse_ss_connections
        text = '0 0 [2001:db8::10]:443 [2001:db8::20]:50123 users:(("caddy",pid=123,fd=7))'
        rows = parse_ss_connections(text)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].local_host, "2001:db8::10")
        self.assertEqual(rows[0].remote_port, 50123)
        self.assertEqual(rows[0].process, "caddy")
        self.assertEqual(rows[0].pid, 123)


if __name__ == "__main__":
    unittest.main()
