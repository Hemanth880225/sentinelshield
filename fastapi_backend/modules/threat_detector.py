import random
import datetime


def detect_threats():

    threats = []

    for _ in range(5):

        threats.append({

            "time": datetime.datetime.now().strftime("%H:%M:%S"),

            "ip": f"192.168.1.{random.randint(2,200)}",

            "type": random.choice([
                "Port Scan",
                "Brute Force",
                "Malware Attempt",
                "Suspicious Login"
            ]),

            "target": random.choice([
                "Smart Camera",
                "Smart Bulb",
                "Router",
                "Smart Speaker"
            ]),

            "severity": random.choice([
                "Low",
                "Medium",
                "High"
            ])

        })

    return threats