import json
import random
import time
from datetime import datetime


def generate_random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

# run all the time #

geo = [["USA", "Germany", "Netherlands", "India", "Singapore", "Egypt"
       ], ["China", "Russia"]]

country_ips = {
    "USA": ["8.8.8.8", "3.101.12.1", "52.23.45.67"],
    "Germany": ["18.196.0.1", "35.156.0.5", "52.58.12.34"],
    "Netherlands": ["52.174.0.1", "13.69.0.10", "40.68.123.45"],
    "India": ["13.232.0.1", "65.0.0.5", "15.206.78.90"],
    "Singapore": ["13.228.0.1", "54.254.0.5", "18.138.55.66"],
    "Egypt": ["41.32.0.1", "156.200.0.1", "196.219.12.34"],
    "China": ["36.0.0.1", "101.0.0.5", "123.125.67.89"],
    "Russia": ["5.255.255.1", "77.88.0.1", "95.163.45.67"]
}


familiar = geo[0]
unfamiliar = geo[1]


def login():
    success = random.choices([True, False],
            weights=[0.5, 0.5]
        )[0]
    
    if success == True:
        eventcode = 4624
    else:
        eventcode = 4625

    location = random.choices([familiar, unfamiliar], weights=[0.7,0.3])[0]
    final_loc = random.choice(location)
    ip = random.choice(country_ips[final_loc])

    if final_loc in unfamiliar:
        logontype = 10
    else:
        logontype = random.choice([2, 3])
    
    return {
        "EventCode": eventcode,
        "timestamp": datetime.now().isoformat(),
        "event_type": "login_attempt",
        "ComputerName": f"DESKTOP{random.randint(1,100)}", #same as host
        "src_ip": ip,
        "geo": final_loc,
        "success": success,
        "LogonType": logontype #2 is safe , 3 for network smb, 10 for rdp from unknown loc
    }

def logoff():
    return {
    "EventCode": 4634,
    "timestamp": datetime.now().isoformat(),
    "event_type": "logoff",
    "ComputerName": f"DESKTOP{random.randint(1,100)}", #same as host
    }

def brute_force():
    success = False
    
    if success == True:
        eventcode = 4624
    else:
        eventcode = 4625
    
    location = random.choices([familiar, unfamiliar], weights=[0.7,0.3])[0]
    final_loc = random.choice(location)
    ip = random.choice(country_ips[final_loc])

    if final_loc in unfamiliar:
        logontype = 10
    else:
        logontype = random.choice([2, 3])

        return {
        "EventCode": eventcode,
        "timestamp": datetime.now().isoformat(),
        "event_type": "login_attempt",
        "ComputerName": f"DESKTOP{random.randint(1,100)}", #same as host
        "src_ip": ip,
        "geo": final_loc,
        "success": success,
        "LogonType": logontype #2 is safe , 3 for network smb, 10 for rdp from unknown loc
    }
    

def user_creation():
    attack = random.choices([True, False], weights=[0.1,0.9])[0]
    return {
        "EventCode": 4720,
        "timestamp": datetime.now().isoformat(),
        "event_type": "new_user_creation",
        "ComputerName": f"DESKTOP{random.randint(1,100)}",
        "new_account_name": f"user{random.randint(1,50)}",
        "Privileges": "Local Admin" if attack else " "
    }


# phishing , macro, payload exec
def process_gen():

    attack = random.choices([True, False],
            weights=[0.5, 0.5]
        )[0]
    
    # parent and process
    proc = {
        "services.exe": r"C:\Windows\System32\svchost.exe",
        "explorer.exe": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "explorer.exe": r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    }

    notproc = {
        # fileless malware run from office
        "winword.exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "excel.exe": r"C:\Windows\System32\cmd.exe",
        "chrome.exe": r"C:\Windows\System32\psexec.exe",
        # run from temp
        "explorer.exe": r"C:\Users\User\AppData\Local\Temp\update.exe"
    }

    if attack == False:
        processType = proc
    else:
        processType = notproc
    

    commandline = ["psexec", "wmic", "lsass.exe", "schtasks", "-enc"]

    creator, process = random.choice(list(processType.items()))

    return {
        "EventCode": 4688,
        "timestamp": datetime.now().isoformat(),
        "event_type": "process_exec",
        "ComputerName": f"DESKTOP{random.randint(1,100)}",
        "NewProcessName": process,
        "ProcessCreator": creator,
        "ProcessCommandLine": random.choice(commandline) if attack else " ",
    }


# run some of the time #
def privilege():
    return {
      "EventCode": 4672,
      "timestamp": datetime.now().isoformat(),
      "event_type": "privilege_assigned",
      "ComputerName": f"DESKTOP-{random.randint(1,100)}",
      "AccountName": random.choices(["Administrator", f"DESKTOP{random.randint(1,100)}"], weights=[0.5, 0.5]),
      "Privilege": random.choice(["SeRestorePrivilege","SeDebugPrivilege","SeSystemEnvironmentPrivilege","SeImpersonatePrivilege"])
    }

# successful out of geo login then priv
def lateral_attack(first, ComputerName):
    if first:
        final_loc = random.choice(unfamiliar)
        print(f"lateral: {final_loc}")
        ip = random.choice(country_ips[final_loc])
        return {
            "EventCode": 4624,
            "timestamp": datetime.now().isoformat(),
            "event_type": "login_attempt",
            "ComputerName": ComputerName, #same as host
            "src_ip": ip,
            "geo": final_loc,
            "success": True,
            "LogonType": 10 #2 is safe , 3 for network smb, 10 for rdp from unknown loc
        }
    else:
        return {
      "EventCode": 4672,
      "timestamp": datetime.now().isoformat(),
      "event_type": "privilege_assigned",
      "ComputerName": ComputerName,
      "AccountName": random.choices(["Administrator", f"DESKTOP{random.randint(1,100)}"], weights=[0.5, 0.5]),
      "Privilege": random.choice(["SeRestorePrivilege","SeDebugPrivilege","SeSystemEnvironmentPrivilege","SeImpersonatePrivilege"])
    }


# unknown user isntall, download under SYSTEM
def system_install():
    return {
        "EventCode": 4697,
        "event_type": "system_install",
        "timestamp": datetime.now().isoformat(),
        "Security ID": "SYSTEM",
        "AccountName": f"DESKTOP-{random.randint(1,100)}",
        "ServiceName": "simptcp",
    }

# persistence + escalation
# check if Run is in object name

def reg_change():
    ObjectName = [r"\REGISTRY\MACHINE\SOFTWARE\MTG", r"\REGISTRY\MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System", r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"]
    badObj =r"\REGISTRY\USER\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run"

    return {
        "EventCode": 4657,
        "event_type": "registry_key_modified",
        "Account Name": "SYSTEM",
        "Object Name":  random.choice(ObjectName),
        "Operation Type":  "Existing registry value modified"
    }



