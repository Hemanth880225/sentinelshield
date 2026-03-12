import random
import datetime


def get_honeypots():

    honeypots = []

    for i in range(3):

        honeypots.append({

            "id": f"HP-{i+1}",

            "service": random.choice([
                "Fake SSH",
                "Fake FTP",
                "Fake Telnet"
            ]),

            "status": random.choice([
                "Active",
                "Triggered"
            ]),

            "interactions": random.randint(0,20),

            "last_trigger": datetime.datetime.now().strftime("%H:%M:%S")

        })

    return honeypots