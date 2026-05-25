import json
import random
import time
from datetime import datetime
from confluent_kafka import Producer 

import generators as gen

"""
kafka-console-consumer   --topic auth-topic   --fr
om-beginning   --bootstrap-server kafka:29092
"""


"""
consumer docker exec -it kafka bash
kafka-console-consumer \
   --topic test-topic \
   --from-beginning \
   --bootstrap-server kafka:29092
"""



EVENT_GENERATORS = {
    "privileges_logs": gen.privilege,
    "system_install_logs": gen.system_install,
    "login_logs": gen.login,
    "user_create_logs": gen.user_creation,
    "process_creation_logs": gen.process_gen,
    "registry_key_logs": gen.reg_change
}



def main():
    """
        conf = {
        'bootstrap.servers': 'localhost:9092',
        'security.protocol': 'ssl',
        'ssl.ca.location': '/path/to/ca.pem',
        'ssl.certificate.location': '/path/to/client.pem',
        'ssl.key.location': '/path/to/client.key',
    }

        producer = Producer(conf)
    """
    producer = Producer({"bootstrap.servers": "localhost:9092"})

    with producer as producer:
        while True:
            bruteforce = False
            #bruteforce = random.choices([True, False], weights=[0.05,0.95])[0]
            lateral_attack = random.choices([True, False], weights=[0.05,0.95])[0]

            key, value = random.choices(
                list(EVENT_GENERATORS.items()),
                weights=[0.05,0.2,0.2,0.08,0.25,0.07],
                k = 1
                )[0]

            if bruteforce:
                log = gen.brute_force()
                print(log)
                for _ in range(random.randint(5, 10)):  
                    print(log)
                    producer.produce(
                        "login_logs", value=json.dumps(log).encode("utf-8")
                    )
                    producer.poll(0)

                    print("Produced attack. Sleeping")
                    time.sleep(5)

            if lateral_attack:
                compName = f"DESKTOP{random.randint(1,100)}"
                log = gen.lateral_attack(True, compName)
                producer.produce(
                        "login_logs", value=json.dumps(log).encode("utf-8")
                    )
                producer.poll(0)
                log = gen.lateral_attack(False, compName)
                producer.produce(
                        "privileges_logs", value=json.dumps(log).encode("utf-8")
                    )

                print("Produced lateral attack. Sleeping")
                time.sleep(5)


            topic = key
            log = value()

            producer.produce(
        topic, value=json.dumps(log).encode("utf-8")
    )
            print(f"Produced to {topic}.. Sleeping")
            time.sleep(5)



if __name__ == "__main__":
    main()


