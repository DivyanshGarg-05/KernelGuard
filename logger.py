import datetime

class ForensicLogger:
    def __init__(self, log_file="/var/log/ebpf_threats.log"):
        self.log_file = log_file

    def log_threat(self, pid, uid, behavior_str):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Format the alert to record the exact system call frequencies
        log_entry = f"[{timestamp}] ALERT | PID: {pid} | UID: {uid} | BEHAVIOR: {behavior_str}\n"
        
        with open(self.log_file, "a") as f:
            f.write(log_entry)