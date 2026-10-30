#!/usr/bin/env python3
"""
=============================================================================
MODULE 1: SDN Emulation Setup - Mininet Custom Topology
Project: Explainable AI-Based Insider Threat Detection in SDN using SHAP/LIME
File: mininet_topo.py
=============================================================================
Description:
    Constructs a segmented enterprise network topology using OpenFlow 1.3 switches
    and Open vSwitch (OVS). Simulates enterprise domains:
      - Subnet 1 (10.0.1.0/24): Employee Workstations (HR, Finance, Engineering)
      - Subnet 2 (10.0.2.0/24): Internal Mission-Critical Servers (DB, File Repo)
      - Subnet 3 (10.0.3.0/24): Perimeter Gateway & External Untrusted Endpoints
    Connects to an external Ryu OpenFlow 1.3 SDN controller.
"""

import sys
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo


class EnterpriseSDNTopo(Topo):
    """
    Custom SDN Topology simulating an enterprise environment prone to insider threats.
    
    Structure:
                 [Ryu Controller (c0)]
                           |
                     [Core Switch c1]
                     /      |       \
           [Switch s1]  [Switch s2]  [Switch s3]
            (Workstations) (Servers)  (Gateway)
              /   |   \      |    \      |     \
            ws1  ws2  ws3   db   file   gw    ext_srv
    """

    def build(self):
        info('*** Building Enterprise SDN Topology...\n')

        # 1. Create OpenFlow 1.3 Switches
        # Core distribution switch
        c1 = self.addSwitch('c1', cls=OVSSwitch, protocols='OpenFlow13')

        # Edge access switches
        s1 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')  # Workstations Edge
        s2 = self.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')  # Server Edge
        s3 = self.addSwitch('s3', cls=OVSSwitch, protocols='OpenFlow13')  # Perimeter Edge

        # Inter-switch backbone links (high capacity trunk links)
        self.addLink(s1, c1, bw=1000, delay='1ms')
        self.addLink(s2, c1, bw=1000, delay='1ms')
        self.addLink(s3, c1, bw=1000, delay='1ms')

        # 2. Add Segmented Hosts
        # Subnet 1: Workstations (10.0.1.0/24)
        ws1 = self.addHost('ws1', ip='10.0.1.10/24', mac='00:00:00:00:01:10',
                           defaultRoute='via 10.0.1.1')
        ws2 = self.addHost('ws2', ip='10.0.1.11/24', mac='00:00:00:00:01:11',
                           defaultRoute='via 10.0.1.1')
        ws3 = self.addHost('ws3', ip='10.0.1.12/24', mac='00:00:00:00:01:12',
                           defaultRoute='via 10.0.1.1')

        self.addLink(ws1, s1, bw=100, delay='2ms')
        self.addLink(ws2, s1, bw=100, delay='2ms')
        self.addLink(ws3, s1, bw=100, delay='2ms')

        # Subnet 2: Sensitive Enterprise Servers (10.0.2.0/24)
        db_server = self.addHost('db_server', ip='10.0.2.10/24', mac='00:00:00:00:02:10',
                                 defaultRoute='via 10.0.2.1')
        file_server = self.addHost('file_server', ip='10.0.2.20/24', mac='00:00:00:00:02:20',
                                  defaultRoute='via 10.0.2.1')

        self.addLink(db_server, s2, bw=1000, delay='1ms')
        self.addLink(file_server, s2, bw=1000, delay='1ms')

        # Subnet 3: Perimeter Gateway & External Endpoints (10.0.3.0/24)
        gateway = self.addHost('gw', ip='10.0.3.1/24', mac='00:00:00:00:03:01')
        ext_srv = self.addHost('ext_srv', ip='10.0.3.100/24', mac='00:00:00:00:03:64',
                               defaultRoute='via 10.0.3.1')

        self.addLink(gateway, s3, bw=1000, delay='2ms')
        self.addLink(ext_srv, s3, bw=100, delay='15ms')  # Simulated WAN delay


def run_sdn_testbed(controller_ip='127.0.0.1', controller_port=6653):
    """
    Initializes and starts the Mininet network with Ryu controller connection.
    """
    topo = EnterpriseSDNTopo()
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=None,  # Attach RemoteController explicitly
        autoSetMacs=False,
        autoStaticArp=True
    )

    info(f'*** Connecting to remote Ryu Controller at {controller_ip}:{controller_port}...\n')
    controller = net.addController(
        'c0',
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port
    )

    info('*** Starting network...\n')
    net.start()

    info('*** Initializing server daemons...\n')
    db_server = net.get('db_server')
    file_server = net.get('file_server')
    ext_srv = net.get('ext_srv')

    # Start simulated services
    # DB Server simulated with Python HTTP on port 5432 (Postgres mock API)
    db_server.cmd('python3 -m http.server 5432 &')
    # File Server simulated with HTTP on port 8080 (WebDAV mock)
    file_server.cmd('python3 -m http.server 8080 &')
    # External Server on port 443
    ext_srv.cmd('python3 -m http.server 443 &')

    info('*** Network is live and ready for traffic injection / behavioral analysis.\n')
    info('*** Type "exit" or Ctrl+D in the CLI to tear down the topology.\n')

    CLI(net)

    info('*** Stopping network...\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    ctrl_ip = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    ctrl_port = int(sys.argv[2]) if len(sys.argv) > 2 else 6653
    run_sdn_testbed(ctrl_ip, ctrl_port)
