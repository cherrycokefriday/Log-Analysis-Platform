# IMPORTANT:
# event_type
# timestamp
# host
# 
# 
# severity
# id? 
#

import json
import random
from datetime import datetime


# use this ALL scross logs
users = ["user1", "user2", "admin"]
ips = ["192.168.1.1", "10.0.0.5", "172.16.0.3"]
country = ["US", "UK", "FR", "RU"] # use a fucking library

def generate_auth():
    success = random.random() > 0.2
    log = {
        "timestamp": datetime.now().isoformat(),
        "event_type": "login_attempt",
        "user_id": random.choice(users),
        "source": {
            "ip": random.choice(ips),
            "country": random.choice(country),
            },
        "status": "success" if success else "failed"
        }
    logjson = json.dumps(log)
    return logjson

# run all the time #
def login():
  return {
      "EventCode": 4624, #??? failed is 4625
        "timestamp": datetime.now().isoformat(),
        "event_type": "login_attempt",
        "host": random.choice(users),
        "src_ip": random.choice(ips),
        "geo": random.choices(geo, weights=[0.2,0.7,0.1])[0],
        "success": random.choices([True, False],
            weights=[0.9, 0.1]
        )[0],
        "ComputerName": "DESKTOP",
        "LogonType": 3 #3 for network smb, 10 for rdp
    }



# phishing , macro, payload exec
def process_gen():
    normalproc = ["C:\Windows\System32\cmd.exe",":\Windows\System32\psexec.exe", "C:\Windows\System32\wbem\WMIC.exe"] 
    notproc = ["C:\Users\john\AppData\Local\Temp\svchost.exe" ]
    # check for temp dir

    # parent and process
    proc = {
        "services.exe": "svchost.exe",
        "winlogon.exe": "userinit.exe"
    }

    notproc = {
        "winword.exe": "powershell.exe",
        "excel.exe": "cmd.exe",
        "chrome.exe": "powershell.exe"
    }
    commandline = ["psexec", "wmic", "lsass.exe"]

    creator, process = random.choice(list(proc.items()))

    return {
        "EventCode": 4688,
        "New Process Name": process,
        "Process Creator": creator,
        "Process Command Line": ""
    }

#scheduled task creation
def persistence():
    return {
        "EventCode": 4698,
    }
    

# run some of the time #
def gen_privilege():
    return {
      "EventCode": 4672,
      "event_type": "privilege_change",
      "timestamp": datetime.now().isoformat(),
      "ComputerName": #change 
      "DESKTOP-01",
      "AccountName": "Administrator"
    }


# unknown user isntall, download under SYSTEM
def gen_system_install():
    return {
        "EventCode": 4697,
        "event_type": "system_install",
        "Security ID": "SYSTEM",
        "AccountName": f"WIN-{random.randint(1000,9999)}",
        "ServiceName": "simptcp"
    }


# persistence + escalation
# check if Run is in object name
ObjectName = ["\REGISTRY\MACHINE\SOFTWARE\MTG", "\REGISTRY\MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System", "\REGISTRY\MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System"]

def reg_change():
    return {
        "EventCode": 4657,
        "Account Name":  "administrator",
        "Object Name":  random.choice(ObjectName),
        "Operation Type":  "Existing registry value modified"
    }


# escalation already happened, credential dumping
def cred_dump():
    return {
        "EventCode": 4688
    }
    return
  







def role_change():
    {
  "timestamp": datetime.now().isoformat(),
  "event_type": "auth.role_change",
  "actor": {
    "id": "u999",
    "username": "admin1"
  },
  "target": {
    "id": "u12345",
    "username": "jdoe"
  },
  "changes": {
    "old_role": "user",
    "new_role": "admin"
  },
  "source": {
    "ip": "10.0.0.5"
  }
}

    
def process_exec():
    {
  "timestamp": "2026-04-19T13:22:03Z",
  "event_type": "process.start",
  "host": {
    "hostname": "workstation-22",
    "os": "windows"
  },
  "process": {
    "name": "powershell.exe",
    "command_line": "powershell -enc SQBFAFgA...",
    "pid": 4421,
    "parent_process": "winword.exe"
  },
  "user": {
    "username": "jdoe"
  }
}
    
def file_access():
    {
  "timestamp": "2026-04-19T13:30:11Z",
  "event_type": "file.access",
  "user": {
    "username": "jdoe"
  },
  "file": {
    "path": "/finance/payroll_2026.xlsx",
    "classification": "sensitive"
  },
  "action": "read",
  "host": {
    "hostname": "laptop-77"
  }
}
    
def network_tranfer():
    {
  "timestamp": "2026-04-19T13:45:55Z",
  "event_type": "network.transfer",
  "source": {
    "ip": "10.0.0.8"
  },
  "destination": {
    "ip": "91.210.55.12",
    "country": "NL"
  },
  "network": {
    "bytes_sent": 524288000,
    "protocol": "HTTPS"
  },
  "user": {
    "username": "jdoe"
  }
}
    
def config_change():
    {
  "timestamp": "2026-04-19T14:02:19Z",
  "event_type": "system.config_change",
  "actor": {
    "username": "jdoe"
  },
  "change": {
    "setting": "firewall_enabled",
    "old_value": 1,
    "new_value": 0
  },
  "host": {
    "hostname": "server-1"
  }
}
    
    """
     web1.example.com	MSWinEventLog	1	Application	721	Wed Sep 06 17:05:31 2006
4156	MSDTC	Unknown User	N/A	Information	WEB1	Printers		String
message: Session idle timeout over, tearing down the session.	179

web1.example.com	MSWinEventLog	1	Security	722	Wed Sep 06 17:59:08 2006
576	Security	SYSTEM	User	Success Audit	WEB1	Privilege Use
Special privileges assigned to new logon:     User Name:      Domain:      Logon
ID: (0x0,0x4F3C5880)     Assigned: SeBackupPrivilege   SeRestorePrivilege
SeDebugPrivilege   SeChangeNotifyPrivilege   SeAssignPrimaryTokenPrivilege 525
"""


