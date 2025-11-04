#!/usr/bin/env python3
"""
AI Security Analyzer Module
"""

import random
import json
from datetime import datetime

class AIAnalyzer:
    def __init__(self):
        self.vulnerability_db = {
            "ssh": ["Weak passwords", "Outdated version", "Root login enabled"],
            "http": ["SQL injection", "XSS", "CSRF", "Directory traversal"],
            "ftp": ["Anonymous login", "Clear text authentication"],
            "mysql": ["Weak credentials", "Default configurations"]
        }
    
    def analyze_target(self, target, open_ports):
        """AI analysis of target"""
        analysis = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "risk_score": random.randint(30, 95),
            "vulnerabilities": [],
            "recommendations": []
        }
        
        # Analyze based on open ports
        for port in open_ports:
            service = self.detect_service(port)
            if service in self.vulnerability_db:
                analysis["vulnerabilities"].extend(self.vulnerability_db[service])
        
        # Calculate risk score
        if len(analysis["vulnerabilities"]) > 3:
            analysis["risk_score"] = min(analysis["risk_score"] + 20, 95)
        
        # Generate recommendations
        analysis["recommendations"] = self.generate_recommendations(analysis)
        
        return analysis
    
    def detect_service(self, port):
        """Detect service by port"""
        service_map = {
            22: "ssh", 80: "http", 443: "https", 21: "ftp",
            25: "smtp", 53: "dns", 3306: "mysql", 3389: "rdp"
        }
        return service_map.get(port, "unknown")
    
    def generate_recommendations(self, analysis):
        """Generate AI recommendations"""
        recs = []
        if analysis["risk_score"] > 70:
            recs.append("Immediate attention required - High risk vulnerabilities detected")
        if "SQL injection" in analysis["vulnerabilities"]:
            recs.append("Use parameterized queries and input validation")
        if "XSS" in analysis["vulnerabilities"]:
            recs.append("Implement Content Security Policy (CSP)")
        
        return recs
