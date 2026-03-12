import random
import datetime


def capture_packets():

    packets = []

    for _ in range(10):

        packets.append({

            "time": datetime.datetime.now().strftime("%H:%M:%S"),

            "source": f"192.168.1.{random.randint(2,200)}",

            "destination": f"192.168.1.{random.randint(2,200)}",

            "protocol": random.choice([
                "TCP",
                "UDP",
                "HTTP",
                "HTTPS"
            ]),

            "size": random.randint(60,1500)

        })

    return packets