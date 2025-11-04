#!/usr/bin/env python3
"""
Core Scanner Module for Omni-Hack Terminal
"""

import socket
import subprocess
import threading
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.results = {}
        self.open_ports = []
    
    def port_scan(self, target, ports=None):
        """Basic port scanner"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        print(f"Scanning {target}...")
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    self.open_ports.append(port)
                    print(f"Port {port}: OPEN")
                sock.close()
            except:
                pass
        
        return self.open_ports

    def service_detection(self, target, port):
        """Detect service running on port"""
        try:
            service = socket.getservbyport(port)
            return service
        except:
            return "unknown"
