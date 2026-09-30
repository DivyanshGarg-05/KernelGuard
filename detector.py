import pandas as pd
from sklearn.ensemble import IsolationForest
import warnings
from logger import ForensicLogger

warnings.filterwarnings("ignore")

class ThreatDetector:
    def __init__(self, warmup_size=100, contamination=0.05):
        self.baseline_data = []
        self.warmup_size = warmup_size 
        self.is_trained = False 
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.logger = ForensicLogger()

    def extract_and_evaluate(self, pid, exec_c, open_c, read_c, write_c, connect_c):
        vector = {
            "pid": pid,
            "execve": exec_c,
            "openat": open_c,
            "read": read_c,
            "write": write_c,
            "connect": connect_c
        }
        
        # Phase 1: (Collecting the baseline)
        if not self.is_trained:
            self.baseline_data.append(vector)
            
            if len(self.baseline_data) >= self.warmup_size:
                print(f"\n[*] Warm-up threshold reached ({self.warmup_size} events).")
                print("[*] Training global behavioral baseline...")
                
                df = pd.DataFrame(self.baseline_data)
                features = df.drop(columns=['pid'])
                self.model.fit(features)
                
                self.is_trained = True
                print("[+] Model locked. Transitioning to Active Threat Hunting.\n")
                
            return

        # Phase 2: Active Threat Hunting (Prediction Only)
        current_features = pd.DataFrame([vector]).drop(columns=['pid'])
        prediction = self.model.predict(current_features)
        
        if prediction[0] == -1:
            print(f"[!] BEHAVIORAL ANOMALY DETECTED: PID {pid}")
            print(f"    --> Exec:{exec_c} | Open:{open_c} | Read:{read_c} | Write:{write_c} | Connect:{connect_c}")
            
            if hasattr(self.logger, 'log_threat'):
                behavior_str = f"E:{exec_c} O:{open_c} R:{read_c} W:{write_c} C:{connect_c}"
                self.logger.log_threat(pid, 0, behavior_str)