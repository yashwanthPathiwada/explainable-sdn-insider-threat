#!/usr/bin/env python3
"""
=============================================================================
SDN Traffic & Insider Threat Scenario Generator
Project: Explainable AI-Based Insider Threat Detection in SDN using SHAP/LIME
File: traffic_generator.py
=============================================================================
Description:
    Generates realistic benign traffic and 4 weaponized insider threat scenarios:
      Scenario 1: Massive Data Exfiltration (Off-hours bulk upload to external server)
      Scenario 2: Internal Reconnaissance & Port Scanning (Horizontal & Vertical scans)
      Scenario 3: Privilege Abuse & Database Probing (HR workstation accessing DB port 5432)
      Scenario 4: Stealth Periodic C2 Beaconing (Low-frequency automated beaconing)

    Can operate in two modes:
      - Live Mininet Mode: Dispatches socket/curl/hping3 traffic across virtual hosts.
      - Database Streaming Mode: Injects flow telemetry directly into 'flow_records.db'
        to test detection and explainability in real time.
"""

import os
import sys
import time
import random
import sqlite3
import requests
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DATA_DIR, 'flow_records.db')


def insert_flow_record(flow):
    """Inserts a single flow record into SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO flow_records (
            timestamp, datetime_str, switch_id, eth_src, eth_dst,
            ip_src, ip_dst, src_port, dst_port, protocol,
            packet_count, byte_count, duration_sec,
            delta_packets, delta_bytes, byte_rate, packet_rate
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        flow['timestamp'],
        datetime.fromtimestamp(flow['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
        flow.get('switch_id', 1),
        flow.get('eth_src', '00:00:00:00:01:10'),
        flow.get('eth_dst', '00:00:00:00:02:10'),
        flow['ip_src'],
        flow['ip_dst'],
        flow['src_port'],
        flow['dst_port'],
        flow.get('protocol', 'TCP'),
        flow['packet_count'],
        flow['byte_count'],
        flow['duration_sec'],
        flow['packet_count'],
        flow['byte_count'],
        flow['byte_count'] / max(0.1, flow['duration_sec']),
        flow['packet_count'] / max(0.1, flow['duration_sec'])
    ))
    conn.commit()
    conn.close()


def stream_benign_traffic(duration_sec=30, sleep_interval=1.0):
    """Streams continuous benign background traffic."""
    print(f"[TrafficGenerator] Streaming benign background traffic for {duration_sec}s...")
    workstations = ['10.0.1.10', '10.0.1.11', '10.0.1.12']
    destinations = [
        ('10.0.2.20', 8080),  # File server WebDAV
        ('10.0.2.20', 445),   # SMB File share
        ('10.0.3.100', 80),   # Web traffic
        ('10.0.3.100', 443)   # Secure HTTPS
    ]

    t_end = time.time() + duration_sec
    count = 0
    while time.time() < t_end:
        now = time.time()
        src = random.choice(workstations)
        dst_ip, dst_port = random.choice(destinations)
        pkts = random.randint(8, 45)
        bytes_cnt = pkts * random.randint(350, 950)
        dur = random.uniform(0.2, 2.5)

        flow = {
            'timestamp': now,
            'ip_src': src,
            'ip_dst': dst_ip,
            'src_port': random.randint(49152, 65535),
            'dst_port': dst_port,
            'packet_count': pkts,
            'byte_count': bytes_cnt,
            'duration_sec': dur
        }
        insert_flow_record(flow)
        count += 1
        time.sleep(sleep_interval)
    print(f"[TrafficGenerator] Streamed {count} benign flows.")


def inject_data_exfiltration(attacker_ip='10.0.1.11', ext_target='10.0.3.100', bursts=20):
    """
    Scenario 1: Data Exfiltration
    Massive bulk transfer of confidential corporate databases to an external server.
    High volume, high byte rate, off-hours profile.
    """
    print(f"[ATTACK INJECTION] Launching Data Exfiltration from {attacker_ip} -> {ext_target}...")
    for i in range(bursts):
        now = time.time()
        pkts = random.randint(600, 1800)
        bytes_cnt = pkts * random.randint(1200, 1480)
        dur = random.uniform(0.5, 2.0)

        flow = {
            'timestamp': now,
            'ip_src': attacker_ip,
            'ip_dst': ext_target,
            'src_port': random.randint(49152, 65535),
            'dst_port': 443,
            'packet_count': pkts,
            'byte_count': bytes_cnt,
            'duration_sec': dur
        }
        insert_flow_record(flow)
        print(f"  [+] Burst {i+1}/{bursts}: Transferred {bytes_cnt / 1024 / 1024:.2f} MB in {dur:.2f}s")
        time.sleep(0.3)
    print("[ATTACK INJECTION] Data Exfiltration completed.")


def inject_port_scan(attacker_ip='10.0.1.10', target_ip='10.0.2.10', num_ports=35):
    """
    Scenario 2: Internal Reconnaissance
    Rapid port scan across critical server ports. High port entropy, low packet counts.
    """
    print(f"[ATTACK INJECTION] Launching Port Scanning from {attacker_ip} -> {target_ip}...")
    target_ports = list(range(21, 21 + num_ports)) + [445, 1433, 3306, 5432, 8080]
    for port in target_ports:
        now = time.time()
        flow = {
            'timestamp': now,
            'ip_src': attacker_ip,
            'ip_dst': target_ip,
            'src_port': random.randint(49152, 65535),
            'dst_port': port,
            'packet_count': random.randint(1, 2),  # SYN probe
            'byte_count': 64,
            'duration_sec': 0.02
        }
        insert_flow_record(flow)
        time.sleep(0.08)
    print(f"[ATTACK INJECTION] Scanned {len(target_ports)} ports on {target_ip}.")


def inject_privilege_abuse(attacker_ip='10.0.1.10', db_server='10.0.2.10', queries=15):
    """
    Scenario 3: Privilege Abuse
    Unprivileged HR workstation repeatedly querying PostgreSQL (port 5432).
    """
    print(f"[ATTACK INJECTION] Launching Privilege Abuse: {attacker_ip} accessing DB {db_server}:5432...")
    for i in range(queries):
        now = time.time()
        pkts = random.randint(30, 80)
        bytes_cnt = pkts * random.randint(400, 1100)
        dur = random.uniform(0.3, 1.2)

        flow = {
            'timestamp': now,
            'ip_src': attacker_ip,
            'ip_dst': db_server,
            'src_port': random.randint(49152, 65535),
            'dst_port': 5432,
            'packet_count': pkts,
            'byte_count': bytes_cnt,
            'duration_sec': dur
        }
        insert_flow_record(flow)
        print(f"  [+] Query {i+1}/{queries}: DB extraction flow recorded.")
        time.sleep(0.4)
    print("[ATTACK INJECTION] Privilege abuse simulation completed.")


if __name__ == '__main__':
    print("=" * 70)
    print("Traffic & Insider Threat Scenario Generator")
    print("=" * 70)
    print("Options:")
    print("  1. Stream Benign Background Traffic")
    print("  2. Inject Data Exfiltration Attack (ws2 -> Ext Srv)")
    print("  3. Inject Reconnaissance Port Scan (ws1 -> DB Srv)")
    print("  4. Inject Privilege Abuse Attack (ws1 -> DB:5432)")
    print("  5. Run Complete Sequence (Benign + All Attacks)")

    choice = sys.argv[1] if len(sys.argv) > 1 else '5'

    if choice == '1':
        stream_benign_traffic(duration_sec=20)
    elif choice == '2':
        inject_data_exfiltration()
    elif choice == '3':
        inject_port_scan()
    elif choice == '4':
        inject_privilege_abuse()
    elif choice == '5':
        print("\n--- Running Multi-Scenario Demonstration ---")
        stream_benign_traffic(duration_sec=10, sleep_interval=0.5)
        time.sleep(1)
        inject_data_exfiltration()
        time.sleep(1)
        inject_port_scan()
        time.sleep(1)
        inject_privilege_abuse()
        print("\nAll attack flows successfully recorded in database.")
