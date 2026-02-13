import random
import time
from datetime import datetime
from collections import defaultdict

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.statistics = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'ports': defaultdict(int),
            'alerts': []
        }
        
        # Known malicious patterns
        self.suspicious_ports = [22, 23, 3389, 4444, 5555, 6666, 7777, 8888, 9999, 31337]
        self.suspicious_ips = [
            "45.155.205.142", "103.15.55.220", "89.34.96.7",
            "185.142.53.100", "197.45.132.88", "212.47.229.150"
        ]
        
    def generate_packet(self, is_malicious=False):
        """Generate a simulated network packet"""
        packet = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': '',
            'dst_ip': '192.168.1.100',
            'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            'src_port': random.randint(1024, 65535),
            'dst_port': 0,
            'size': random.randint(64, 1500),
            'flags': random.choice(['S', 'A', 'P', 'R', 'F']),
            'ttl': random.randint(64, 255),
            'is_malicious': is_malicious
        }
        
        if is_malicious:
            # Malicious packet characteristics
            packet['src_ip'] = random.choice(self.suspicious_ips)
            packet['dst_port'] = random.choice(self.suspicious_ports)
            packet['size'] = random.randint(32, 100)  # Small packets for scanning
            packet['flags'] = 'S'  # SYN flag for port scans
        else:
            # Normal packet characteristics
            packet['src_ip'] = f"192.168.1.{random.randint(2, 50)}"
            packet['dst_port'] = random.choice([80, 443, 53, 25, 110])
            packet['flags'] = random.choice(['A', 'P'])
            
        return packet
    
    def analyze_packet(self, packet):
        """Analyze a single packet for suspicious patterns"""
        alerts = []
        
        # Update statistics
        self.statistics['total_packets'] += 1
        self.statistics['protocols'][packet['protocol']] += 1
        self.statistics['src_ips'][packet['src_ip']] += 1
        self.statistics['dst_ips'][packet['dst_ip']] += 1
        self.statistics['ports'][packet['dst_port']] += 1
        
        # Check for suspicious source IP
        if packet['src_ip'] in self.suspicious_ips:
            alerts.append(f"⚠️ Known malicious IP: {packet['src_ip']}")
            
        # Check for suspicious destination port
        if packet['dst_port'] in self.suspicious_ports:
            alerts.append(f"⚠️ Suspicious port: {packet['dst_port']}")
            
        # Check for port scan pattern (SYN packets)
        if packet['flags'] == 'S' and packet['size'] < 100:
            count = self.statistics['src_ips'][packet['src_ip']]
            if count > 10:  # Multiple SYN packets from same IP
                alerts.append(f"⚠️ Possible port scan from {packet['src_ip']} ({count} SYN packets)")
                
        # Check for DoS pattern (many packets from same IP)
        if self.statistics['src_ips'][packet['src_ip']] > 50:
            alerts.append(f"⚠️ High traffic from {packet['src_ip']} - possible DoS")
            
        # Check for unusual packet size
        if packet['size'] < 50:
            alerts.append(f"⚠️ Unusually small packet: {packet['size']} bytes")
        elif packet['size'] > 1400:
            alerts.append(f"⚠️ Unusually large packet: {packet['size']} bytes")
            
        return alerts
    
    def simulate_traffic(self, num_packets=1000, attack_ratio=0.1):
        """Simulate network traffic with some malicious packets"""
        print(f"\n📡 Simulating {num_packets} packets ({attack_ratio*100:.0f}% malicious)...")
        
        self.packets = []
        self.statistics = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'ports': defaultdict(int),
            'alerts': []
        }
        
        for i in range(num_packets):
            is_malicious = random.random() < attack_ratio
            packet = self.generate_packet(is_malicious)
            self.packets.append(packet)
            
            alerts = self.analyze_packet(packet)
            if alerts:
                self.statistics['alerts'].extend(alerts)
                
        print(f"✅ Simulation complete!")
        print(f"   Total alerts generated: {len(self.statistics['alerts'])}")
        
        return self.packets
    
    def get_statistics(self):
        """Get traffic statistics"""
        stats = self.statistics.copy()
        
        # Convert defaultdicts to dicts for display
        stats['protocols'] = dict(stats['protocols'])
        stats['src_ips'] = dict(sorted(stats['src_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
        stats['ports'] = dict(sorted(stats['ports'].items(), key=lambda x: x[1], reverse=True)[:10])
        
        return stats

def main():
    analyzer = PacketAnalyzer()
    
    print("="*60)
    print("📦 PACKET ANALYZER")
    print("="*60)
    
    # Simulate traffic
    packets = analyzer.simulate_traffic(num_packets=500, attack_ratio=0.15)
    
    # Show statistics
    stats = analyzer.get_statistics()
    
    print("\n📊 TRAFFIC STATISTICS:")
    print(f"   Total packets: {stats['total_packets']}")
    print(f"   Total alerts: {len(stats['alerts'])}")
    
    print("\n📊 PROTOCOLS:")
    for protocol, count in stats['protocols'].items():
        print(f"   {protocol}: {count} packets")
    
    print("\n📊 TOP SOURCE IPS:")
    for ip, count in list(stats['src_ips'].items())[:5]:
        print(f"   {ip}: {count} packets")
    
    print("\n📊 TOP PORTS:")
    for port, count in list(stats['ports'].items())[:5]:
        print(f"   {port}: {count} packets")
    
    if stats['alerts']:
        print("\n⚠️ SAMPLE ALERTS (first 5):")
        for alert in stats['alerts'][:5]:
            print(f"   • {alert}")

if __name__ == "__main__":
    main()