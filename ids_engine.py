from packet_analyzer import PacketAnalyzer
from alert_manager import AlertManager
import time
from datetime import datetime

class IDSEngine:
    def __init__(self):
        self.analyzer = PacketAnalyzer()
        self.alert_manager = AlertManager()
        self.running = False
        self.detection_rules = {
            'port_scan': {
                'threshold': 20,
                'time_window': 60,
                'severity': 'medium'
            },
            'brute_force': {
                'threshold': 10,
                'time_window': 300,
                'severity': 'high'
            },
            'dos_attack': {
                'threshold': 100,
                'time_window': 60,
                'severity': 'critical'
            }
        }
        self.detection_stats = {
            'port_scan': {'count': 0, 'last_reset': time.time()},
            'brute_force': {'count': 0, 'last_reset': time.time()},
            'dos_attack': {'count': 0, 'last_reset': time.time()}
        }
        
    def start(self):
        """Start the IDS engine"""
        self.running = True
        print("\n🚀 IDS Engine started...")
        
    def stop(self):
        """Stop the IDS engine"""
        self.running = False
        print("\n🛑 IDS Engine stopped.")
        
    def process_packet(self, packet):
        """Process a single packet and generate alerts if needed"""
        # Analyze packet
        alerts = self.analyzer.analyze_packet(packet)
        
        # Check for patterns
        self.check_port_scan_patterns(packet)
        self.check_brute_force_patterns(packet)
        self.check_dos_patterns(packet)
        
        # Generate alerts from analyzer
        for alert_msg in alerts:
            self.alert_manager.generate_alert(
                message=alert_msg,
                severity="medium",
                source=packet.get('src_ip'),
                details=packet
            )
            
    def check_port_scan_patterns(self, packet):
        """Detect port scanning activity"""
        rule = self.detection_rules['port_scan']
        stats = self.detection_stats['port_scan']
        
        # Reset counter if time window passed
        if time.time() - stats['last_reset'] > rule['time_window']:
            stats['count'] = 0
            stats['last_reset'] = time.time()
            
        # Check for SYN packets (port scan indicator)
        if packet.get('flags') == 'S':
            stats['count'] += 1
            
            if stats['count'] >= rule['threshold']:
                self.alert_manager.generate_alert(
                    message=f"Port scan detected: {stats['count']} SYN packets in {rule['time_window']}s",
                    severity=rule['severity'],
                    source=packet.get('src_ip'),
                    details={'packet': packet, 'count': stats['count']}
                )
                stats['count'] = 0  # Reset after alert
                
    def check_brute_force_patterns(self, packet):
        """Detect brute force attempts"""
        rule = self.detection_rules['brute_force']
        stats = self.detection_stats['brute_force']
        
        if time.time() - stats['last_reset'] > rule['time_window']:
            stats['count'] = 0
            stats['last_reset'] = time.time()
            
        # Check for SSH/RDP attempts
        if packet.get('dst_port') in [22, 3389]:
            stats['count'] += 1
            
            if stats['count'] >= rule['threshold']:
                self.alert_manager.generate_alert(
                    message=f"Possible brute force attack: {stats['count']} attempts on port {packet['dst_port']}",
                    severity=rule['severity'],
                    source=packet.get('src_ip'),
                    details={'port': packet['dst_port'], 'attempts': stats['count']}
                )
                
    def check_dos_patterns(self, packet):
        """Detect DoS/DDoS attacks"""
        rule = self.detection_rules['dos_attack']
        stats = self.detection_stats['dos_attack']
        
        if time.time() - stats['last_reset'] > rule['time_window']:
            stats['count'] = 0
            stats['last_reset'] = time.time()
            
        # Count all packets
        stats['count'] += 1
        
        if stats['count'] >= rule['threshold']:
            self.alert_manager.generate_alert(
                message=f"Possible DoS attack: {stats['count']} packets in {rule['time_window']}s",
                severity=rule['severity'],
                details={'packet_count': stats['count']}
            )
            
    def run_simulation(self, duration=60, packets_per_second=10):
        """Run a live simulation"""
        self.start()
        
        print(f"\n⏱️  Running simulation for {duration} seconds...")
        start_time = time.time()
        packet_count = 0
        
        try:
            while time.time() - start_time < duration and self.running:
                # Generate packets with some malicious ones
                for _ in range(packets_per_second):
                    is_malicious = (packet_count % 10 == 0)  # 10% malicious
                    packet = self.analyzer.generate_packet(is_malicious)
                    self.process_packet(packet)
                    packet_count += 1
                    
                # Show progress
                elapsed = int(time.time() - start_time)
                print(f"\r⏳ Elapsed: {elapsed}s | Packets: {packet_count} | Alerts: {len(self.alert_manager.alerts)}", end="")
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n\n⚠️ Simulation interrupted")
            
        finally:
            self.stop()
            
        print(f"\n\n📊 FINAL STATISTICS:")
        print(f"   Total packets: {packet_count}")
        print(f"   Total alerts: {len(self.alert_manager.alerts)}")
        
        # Show recent alerts
        self.alert_manager.print_alerts(limit=5)

def main():
    ids = IDSEngine()
    
    print("="*60)
    print("🔐 AI INTRUSION DETECTION SYSTEM")
    print("="*60)
    
    while True:
        print("\n📌 MENU:")
        print("1. Run live simulation")
        print("2. Generate test alerts")
        print("3. View statistics")
        print("4. View alerts")
        print("5. Exit")
        
        choice = input("\nEnter choice (1-5): ").strip()
        
        if choice == "1":
            duration = input("Simulation duration (seconds, default 30): ").strip()
            duration = int(duration) if duration else 30
            ids.run_simulation(duration=duration)
            
        elif choice == "2":
            print("\n🔄 Generating test alerts...")
            manager = AlertManager()
            manager.generate_alert("Test alert 1", "low")
            manager.generate_alert("Test alert 2", "medium")
            manager.generate_alert("Test alert 3", "high")
            manager.generate_alert("Test alert 4", "critical")
            manager.print_alerts()
            
        elif choice == "3":
            stats = ids.analyzer.get_statistics()
            alert_stats = ids.alert_manager.get_statistics()
            
            print("\n📊 SYSTEM STATISTICS:")
            print(f"   Total packets: {stats['total_packets']}")
            print(f"   Total alerts: {alert_stats['total']}")
            print(f"   Active alerts: {alert_stats['recent']}")
            
        elif choice == "4":
            ids.alert_manager.print_alerts(limit=10)
            
        elif choice == "5":
            print("\n👋 Stay secure!")
            break
            
        else:
            print("❌ Invalid choice")

if __name__ == "__main__":
    main()