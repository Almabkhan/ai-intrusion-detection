from datetime import datetime
from collections import defaultdict

class AlertManager:
    def __init__(self):
        self.alerts = []
        self.severity_levels = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        
    def generate_alert(self, message, severity='medium', source=None, details=None):
        """Generate a new alert"""
        alert = {
            'id': len(self.alerts) + 1,
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'severity': severity,
            'severity_level': self.severity_levels.get(severity, 2),
            'source': source,
            'details': details or {},
            'status': 'new',
            'acknowledged': False
        }
        
        self.alerts.append(alert)
        return alert
    
    def get_alerts(self, severity=None, status=None, limit=None):
        """Get alerts with optional filters"""
        filtered = self.alerts.copy()
        
        if severity:
            filtered = [a for a in filtered if a['severity'] == severity]
            
        if status:
            filtered = [a for a in filtered if a['status'] == status]
            
        if limit:
            filtered = filtered[-limit:]
            
        return filtered
    
    def acknowledge_alert(self, alert_id):
        """Mark alert as acknowledged"""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['status'] = 'acknowledged'
                alert['acknowledged'] = True
                return True
        return False
    
    def resolve_alert(self, alert_id):
        """Mark alert as resolved"""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['status'] = 'resolved'
                return True
        return False
    
    def get_statistics(self):
        """Get alert statistics"""
        stats = {
            'total': len(self.alerts),
            'by_severity': defaultdict(int),
            'by_status': defaultdict(int),
            'recent': len([a for a in self.alerts if a['status'] == 'new'])
        }
        
        for alert in self.alerts:
            stats['by_severity'][alert['severity']] += 1
            stats['by_status'][alert['status']] += 1
            
        return stats
    
    def print_alerts(self, limit=10):
        """Print recent alerts"""
        recent = self.get_alerts(limit=limit)
        
        print("\n" + "="*60)
        print("🚨 RECENT ALERTS")
        print("="*60)
        
        for alert in reversed(recent):
            severity_color = {
                'low': 'ℹ️',
                'medium': '⚠️',
                'high': '🔴',
                'critical': '💀'
            }.get(alert['severity'], '⚠️')
            
            print(f"\n{severity_color} [{alert['severity'].upper()}] Alert #{alert['id']}")
            print(f"   Time: {alert['timestamp']}")
            print(f"   Message: {alert['message']}")
            print(f"   Status: {alert['status']}")
            if alert['source']:
                print(f"   Source: {alert['source']}")

def main():
    manager = AlertManager()
    
    # Generate sample alerts
    manager.generate_alert(
        message="Multiple failed SSH login attempts",
        severity="high",
        source="192.168.1.100",
        details={"attempts": 15, "user": "root"}
    )
    
    manager.generate_alert(
        message="Port scan detected",
        severity="medium",
        source="45.155.205.142",
        details={"ports": [22, 23, 3389], "duration": "30s"}
    )
    
    manager.generate_alert(
        message="Suspicious outbound traffic",
        severity="critical",
        source="192.168.1.50",
        details={"destination": "185.142.53.100", "bytes": 50000}
    )
    
    # Print statistics
    stats = manager.get_statistics()
    print("\n📊 ALERT STATISTICS:")
    print(f"   Total alerts: {stats['total']}")
    print(f"   By severity: {dict(stats['by_severity'])}")
    print(f"   By status: {dict(stats['by_status'])}")
    
    # Print alerts
    manager.print_alerts()

if __name__ == "__main__":
    main()