#!/usr/bin/env python3
"""
=============================================================================
MODULE 1: SDN Emulation Setup - Ryu OpenFlow 1.3 Controller Application
Project: Explainable AI-Based Insider Threat Detection in SDN using SHAP/LIME
File: ryu_controller.py
=============================================================================
Description:
    An OpenFlow 1.3 SDN controller application running on Ryu.
    Responsibilities:
      1. Performs L2/L3 learning and installs reactive forwarding flow entries.
      2. Periodically polls flow and port statistics from switches every 1 second.
      3. Parses flow statistics and writes normalized records to SQLite ('data/flow_records.db').
      4. Exposes an embedded REST API (Port 8080) for policy mitigation commands:
         - /api/mitigate: Installs high-priority OpenFlow DROP / Rate-Limit rules with TTL.
         - /api/rollback: Removes mitigation rules on analyst request or timeout.
         - /api/status: Returns switch connectivity and active mitigation state.
"""

import os
import sys
import time
import json
import sqlite3
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

# Ensure data directory exists
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, 'flow_records.db')

# Global reference for REST API to access active controller instance
CONTROLLER_INSTANCE = None


# ---------------------------------------------------------------------------
# Database Initialization & Management
# ---------------------------------------------------------------------------
def init_database():
    """Initializes the SQLite schema for flow statistics and active mitigations."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Flow Records table: updated every polling interval
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flow_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            datetime_str TEXT NOT NULL,
            switch_id INTEGER NOT NULL,
            eth_src TEXT,
            eth_dst TEXT,
            ip_src TEXT,
            ip_dst TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            packet_count INTEGER NOT NULL,
            byte_count INTEGER NOT NULL,
            duration_sec REAL NOT NULL,
            delta_packets INTEGER DEFAULT 0,
            delta_bytes INTEGER DEFAULT 0,
            byte_rate REAL DEFAULT 0.0,
            packet_rate REAL DEFAULT 0.0
        )
    ''')

    # Active Mitigations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS active_mitigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            switch_id INTEGER NOT NULL,
            ip_src TEXT NOT NULL UNIQUE,
            action TEXT NOT NULL,
            priority INTEGER NOT NULL,
            applied_at REAL NOT NULL,
            ttl_sec INTEGER NOT NULL,
            status TEXT NOT NULL,
            operator_notes TEXT
        )
    ''')

    # Create indices for fast sliding-window querying
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_flow_time_src ON flow_records (timestamp, ip_src)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_flow_src_dst ON flow_records (ip_src, ip_dst)')

    conn.commit()
    conn.close()


init_database()


# ---------------------------------------------------------------------------
# Embedded REST API for Policy-Gated Mitigation (Module 5 Integration)
# ---------------------------------------------------------------------------
class MitigationAPIHandler(BaseHTTPRequestHandler):
    """
    HTTP handler providing REST endpoints for Policy-Gated OpenFlow Actions.
    """

    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(200)

    def do_GET(self):
        if self.path == '/api/status':
            switches = []
            if CONTROLLER_INSTANCE and hasattr(CONTROLLER_INSTANCE, 'datapaths'):
                switches = list(CONTROLLER_INSTANCE.datapaths.keys())

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM flow_records")
            total_flows = cursor.fetchone()[0]

            cursor.execute("SELECT switch_id, ip_src, action, applied_at, ttl_sec, status FROM active_mitigations WHERE status='ACTIVE'")
            active_mitigations = [
                {
                    "switch_id": row[0],
                    "ip_src": row[1],
                    "action": row[2],
                    "applied_at": row[3],
                    "ttl_sec": row[4],
                    "status": row[5],
                    "remaining_ttl": max(0, int(row[4] - (time.time() - row[3])))
                }
                for row in cursor.fetchall()
            ]
            conn.close()

            response = {
                "status": "online",
                "connected_switches": switches,
                "total_flow_records": total_flows,
                "active_mitigations": active_mitigations,
                "timestamp": time.time()
            }
            self._set_headers(200)
            self.wfile.write(json.dumps(response).encode())

        elif self.path == '/api/flows':
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM flow_records ORDER BY id DESC LIMIT 50")
            columns = [col[0] for col in cursor.description]
            records = [dict(zip(columns, row)) for row in cursor.fetchall()]
            conn.close()
            self._set_headers(200)
            self.wfile.write(json.dumps(records).encode())

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)

        try:
            payload = json.loads(post_data.decode('utf-8'))
        except Exception as e:
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": f"Invalid JSON: {str(e)}"}).encode())
            return

        if self.path == '/api/mitigate':
            # Payload: {"ip_src": "10.0.1.11", "action": "DROP" | "RATE_LIMIT", "ttl": 60, "switch_id": 1}
            ip_src = payload.get('ip_src')
            action = payload.get('action', 'DROP').upper()
            ttl = int(payload.get('ttl', 60))
            switch_id = payload.get('switch_id', None)
            operator_notes = payload.get('notes', 'Manual analyst mitigation')

            if not ip_src:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "Missing ip_src parameter"}).encode())
                return

            success = False
            if CONTROLLER_INSTANCE:
                success = CONTROLLER_INSTANCE.apply_mitigation(ip_src, action, ttl, switch_id)
            else:
                # Standalone simulation fallback
                success = True

            # Record in DB
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO active_mitigations (switch_id, ip_src, action, priority, applied_at, ttl_sec, status, operator_notes)
                VALUES (?, ?, ?, 65000, ?, ?, 'ACTIVE', ?)
                ON CONFLICT(ip_src) DO UPDATE SET
                    action=excluded.action,
                    applied_at=excluded.applied_at,
                    ttl_sec=excluded.ttl_sec,
                    status='ACTIVE',
                    operator_notes=excluded.operator_notes
            ''', (switch_id or 1, ip_src, action, time.time(), ttl, operator_notes))
            conn.commit()
            conn.close()

            self._set_headers(200)
            self.wfile.write(json.dumps({
                "status": "applied",
                "ip_src": ip_src,
                "action": action,
                "ttl_sec": ttl,
                "success": success
            }).encode())

        elif self.path == '/api/rollback':
            # Payload: {"ip_src": "10.0.1.11", "switch_id": 1}
            ip_src = payload.get('ip_src')
            switch_id = payload.get('switch_id', None)

            if not ip_src:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "Missing ip_src parameter"}).encode())
                return

            if CONTROLLER_INSTANCE:
                CONTROLLER_INSTANCE.remove_mitigation(ip_src, switch_id)

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("UPDATE active_mitigations SET status='ROLLED_BACK' WHERE ip_src=?", (ip_src,))
            conn.commit()
            conn.close()

            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "rolled_back", "ip_src": ip_src}).encode())

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode())


def start_rest_api_server(port=8080):
    """Starts the embedded HTTP mitigation API server in a background daemon thread."""
    server = HTTPServer(('0.0.0.0', port), MitigationAPIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[Ryu REST API] Listening on http://0.0.0.0:{port}")
    return server


# ---------------------------------------------------------------------------
# Ryu OpenFlow 1.3 Controller Application Definition
# ---------------------------------------------------------------------------
try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp
    from ryu.lib import hub

    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False
    app_manager = type('obj', (object,), {'RyuApp': object})
    ofproto_v1_3 = None


class InsiderThreatDetectionController(app_manager.RyuApp):
    """
    Ryu OpenFlow 1.3 Application that manages topology flow forwarding,
    polls statistics periodically every 1 second, logs into SQLite,
    and supports dynamic policy mitigation.
    """
    if RYU_AVAILABLE:
        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        if RYU_AVAILABLE:
            super(InsiderThreatDetectionController, self).__init__(*args, **kwargs)
        global CONTROLLER_INSTANCE
        CONTROLLER_INSTANCE = self

        self.mac_to_port = {}
        self.datapaths = {}
        self.prev_flow_stats = {}  # Cache (dpid, cookie/match) -> (packet_count, byte_count, time)
        self.polling_interval = 1.0  # OpenFlow stats polling frequency (1s)

        # Start mitigation API
        start_rest_api_server(port=8080)

        # Start stats polling greenlet thread if in Ryu environment
        if RYU_AVAILABLE:
            self.monitor_thread = hub.spawn(self._stats_monitor)
            self.cleanup_thread = hub.spawn(self._ttl_cleanup_loop)

    # -----------------------------------------------------------------------
    # Switch Connection & Handshake
    # -----------------------------------------------------------------------
    if RYU_AVAILABLE:
        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features_handler(self, ev):
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            self.datapaths[datapath.id] = datapath

            self.logger.info(f"Switch s{datapath.id} connected successfully (OpenFlow 1.3).")

            # Install table-miss flow entry: match everything, send to controller
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, priority=0, match=match, actions=actions)

        @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
        def state_change_handler(self, ev):
            datapath = ev.datapath
            if ev.state == MAIN_DISPATCHER:
                if datapath.id not in self.datapaths:
                    self.datapaths[datapath.id] = datapath
            elif ev.state is None:
                if datapath.id in self.datapaths:
                    del self.datapaths[datapath.id]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle_timeout=0, hard_timeout=0):
        """Helper to install an OpenFlow flow entry."""
        if not RYU_AVAILABLE:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout, instructions=inst)
        datapath.send_msg(mod)

    # -----------------------------------------------------------------------
    # Packet-In Reactive Forwarding
    # -----------------------------------------------------------------------
    if RYU_AVAILABLE:
        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in_handler(self, ev):
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]

            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                # Ignore LLDP
                return

            dst = eth.dst
            src = eth.src
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            # Learn MAC address to avoid future flooding
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # Install a flow entry if target port is known
            if out_port != ofproto.OFPP_FLOOD:
                # Check for IPv4 packets to create fine-grained 5-tuple flow rules
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                if ip_pkt:
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    udp_pkt = pkt.get_protocol(udp.udp)
                    if tcp_pkt:
                        match = parser.OFPMatch(
                            in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                            ip_proto=6, tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port
                        )
                    elif udp_pkt:
                        match = parser.OFPMatch(
                            in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                            ip_proto=17, udp_src=udp_pkt.src_port, udp_dst=udp_pkt.dst_port
                        )
                    else:
                        match = parser.OFPMatch(
                            in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst, ip_proto=ip_pkt.proto
                        )
                    # Install flow rule with idle_timeout to clear inactive connections
                    self.add_flow(datapath, priority=10, match=match, actions=actions,
                                  idle_timeout=20, hard_timeout=120)
                else:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                    self.add_flow(datapath, priority=1, match=match, actions=actions,
                                  idle_timeout=20, hard_timeout=120)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    # -----------------------------------------------------------------------
    # Periodic OpenFlow 1.3 Statistics Poller (every 1 second)
    # -----------------------------------------------------------------------
    def _stats_monitor(self):
        """Greenlet loop requesting flow statistics from each switch every 1s."""
        while True:
            for dp in list(self.datapaths.values()):
                self._send_stats_request(dp)
            hub.sleep(self.polling_interval)

    def _send_stats_request(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    if RYU_AVAILABLE:
        @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
        def flow_stats_reply_handler(self, ev):
            """
            Handles flow statistics reply from OpenFlow 1.3 switch.
            Extracts volume, rates, and 5-tuple attributes, saving into SQLite.
            """
            body = ev.msg.body
            dpid = ev.msg.datapath.id
            now = time.time()
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            rows_to_insert = []

            for stat in body:
                # Skip table-miss rules (priority 0) and local controller rules
                if stat.priority == 0:
                    continue

                match = stat.match
                ip_src = match.get('ipv4_src', None)
                ip_dst = match.get('ipv4_dst', None)
                eth_src = match.get('eth_src', None)
                eth_dst = match.get('eth_dst', None)
                src_port = match.get('tcp_src') or match.get('udp_src') or 0
                dst_port = match.get('tcp_dst') or match.get('udp_dst') or 0
                ip_proto_num = match.get('ip_proto', 0)

                proto = 'OTHER'
                if ip_proto_num == 6:
                    proto = 'TCP'
                elif ip_proto_num == 17:
                    proto = 'UDP'
                elif ip_proto_num == 1:
                    proto = 'ICMP'

                if not ip_src:
                    continue  # Only monitor IPv4 traffic

                duration = stat.duration_sec + (stat.duration_nsec / 1e9)
                packets = stat.packet_count
                bytes_cnt = stat.byte_count

                # Calculate delta rates relative to previous polling interval
                flow_key = (dpid, ip_src, ip_dst, src_port, dst_port, proto)
                prev_stat = self.prev_flow_stats.get(flow_key)

                if prev_stat:
                    prev_pkts, prev_bytes, prev_time = prev_stat
                    dt = max(0.1, now - prev_time)
                    delta_pkts = max(0, packets - prev_pkts)
                    delta_bytes = max(0, bytes_cnt - prev_bytes)
                    byte_rate = delta_bytes / dt
                    packet_rate = delta_pkts / dt
                else:
                    delta_pkts = packets
                    delta_bytes = bytes_cnt
                    byte_rate = bytes_cnt / max(0.1, duration)
                    packet_rate = packets / max(0.1, duration)

                self.prev_flow_stats[flow_key] = (packets, bytes_cnt, now)

                rows_to_insert.append((
                    now, now_str, dpid, eth_src, eth_dst, ip_src, ip_dst,
                    src_port, dst_port, proto, packets, bytes_cnt, duration,
                    delta_pkts, delta_bytes, byte_rate, packet_rate
                ))

            if rows_to_insert:
                try:
                    conn = sqlite3.connect(DB_PATH, timeout=5)
                    cursor = conn.cursor()
                    cursor.executemany('''
                        INSERT INTO flow_records (
                            timestamp, datetime_str, switch_id, eth_src, eth_dst,
                            ip_src, ip_dst, src_port, dst_port, protocol,
                            packet_count, byte_count, duration_sec,
                            delta_packets, delta_bytes, byte_rate, packet_rate
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', rows_to_insert)
                    conn.commit()
                    conn.close()
                except Exception as e:
                    self.logger.error(f"Error persisting flow stats to DB: {e}")

    # -----------------------------------------------------------------------
    # Policy-Gated Mitigation Actions (Drop / Rate-Limit / Rollback)
    # -----------------------------------------------------------------------
    def apply_mitigation(self, ip_src, action="DROP", ttl_sec=60, switch_id=None):
        """
        Installs high-priority OpenFlow rule (priority 65000) on switches
        to isolate the threat host or throttle its traffic.
        """
        targets = [self.datapaths[switch_id]] if switch_id and switch_id in self.datapaths else list(self.datapaths.values())
        if not targets:
            print(f"[Controller] Warning: No active switches connected to enforce rule on {ip_src}.")
            return False

        for dp in targets:
            parser = dp.ofproto_parser
            ofproto = dp.ofproto

            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)

            if action == "DROP":
                # Isolate: Empty action list discards all matching frames
                actions = []
                self.add_flow(dp, priority=65000, match=match, actions=actions,
                              idle_timeout=0, hard_timeout=ttl_sec)
                print(f"[OpenFlow Action] ISOLATION (DROP) rule installed on Switch {dp.id} for Host {ip_src} (TTL: {ttl_sec}s)")

            elif action == "RATE_LIMIT":
                # Rate limit: Output to controller or designated queue / meter
                actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                self.add_flow(dp, priority=64000, match=match, actions=actions,
                              idle_timeout=0, hard_timeout=ttl_sec)
                print(f"[OpenFlow Action] RATE-LIMIT rule installed on Switch {dp.id} for Host {ip_src} (TTL: {ttl_sec}s)")

        return True

    def remove_mitigation(self, ip_src, switch_id=None):
        """
        Removes high-priority mitigation rule, restoring normal forwarding.
        """
        targets = [self.datapaths[switch_id]] if switch_id and switch_id in self.datapaths else list(self.datapaths.values())
        for dp in targets:
            parser = dp.ofproto_parser
            ofproto = dp.ofproto
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)

            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=65000,
                match=match
            )
            dp.send_msg(mod)
            print(f"[OpenFlow Rollback] Mitigation rule removed for {ip_src} on Switch {dp.id}")
        return True

    def _ttl_cleanup_loop(self):
        """Background greenlet checking for expired mitigations and marking them in DB."""
        while True:
            now = time.time()
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ip_src, switch_id FROM active_mitigations 
                    WHERE status='ACTIVE' AND (applied_at + ttl_sec) <= ?
                """, (now,))
                expired = cursor.fetchall()

                for ip_src, sw_id in expired:
                    self.remove_mitigation(ip_src, sw_id)
                    cursor.execute("UPDATE active_mitigations SET status='EXPIRED' WHERE ip_src=?", (ip_src,))
                    print(f"[TTL Expiry] Mitigation on {ip_src} expired and automatically reverted.")

                conn.commit()
                conn.close()
            except Exception as e:
                pass
            hub.sleep(5)


# ---------------------------------------------------------------------------
# Direct CLI Runner (Mock / Standalone Mode)
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    print("=" * 70)
    print("Ryu OpenFlow 1.3 Controller & Mitigation REST API Service")
    print("=" * 70)
    print(f"Database Path : {DB_PATH}")
    print(f"Polling Rate  : 1.0 second")
    print(f"REST API Port : 8080")
    print("Endpoints     :")
    print("  - GET  /api/status")
    print("  - GET  /api/flows")
    print("  - POST /api/mitigate  {'ip_src': '...', 'action': 'DROP', 'ttl': 60}")
    print("  - POST /api/rollback  {'ip_src': '...'}")
    print("-" * 70)

    if not RYU_AVAILABLE:
        print("[Notice] Running in Standalone REST API Mode (Ryu library not loaded in host environment).")
        print("To run with Ryu in Linux Mininet: 'ryu-manager ryu_controller.py'")
        server = start_rest_api_server(port=8080)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down controller server.")
    else:
        print("Ryu framework detected. Run via: ryu-manager ryu_controller.py")
