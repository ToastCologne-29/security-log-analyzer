class CorrelationEngine:

    def __init__(self):
        self.failed_by_ip = {}

    def process(self, event):

        alerts = []

        if event.event_type == "login_failed":

            self.failed_by_ip[event.ip] = \
                self.failed_by_ip.get(event.ip, 0) + 1

            count = self.failed_by_ip[event.ip]

            severity = "LOW"

            if count >= 3:
                severity = "MEDIUM"

            if count >= 5:
                severity = "HIGH"

            alerts.append({
                "rule": "FAILED_LOGIN",
                "ip": event.ip,
                "count": count,
                "severity": severity
            })

        return alerts