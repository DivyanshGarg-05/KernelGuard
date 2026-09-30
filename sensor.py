from bcc import BPF
import time
from detector import ThreatDetector 

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Define our feature vector structure
struct behavior_t {
    u32 exec_count;
    u32 open_count;
    u32 read_count;
    u32 write_count;
    u32 connect_count;
};

// Create a high-speed Hash Map: Key = PID, Value = behavior_t
BPF_HASH(trackers, u32, struct behavior_t);

// Helper function to safely increment our counters
static inline void increment_counter(u32 pid, int syscall_type) {
    struct behavior_t *b, zero = {};
    b = trackers.lookup_or_try_init(&pid, &zero);
    if (b) {
        if (syscall_type == 1) b->exec_count++;
        else if (syscall_type == 2) b->open_count++;
        else if (syscall_type == 3) b->read_count++;
        else if (syscall_type == 4) b->write_count++;
        else if (syscall_type == 5) b->connect_count++;
    }
}

// 1. Monitor Process Executions
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    increment_counter(pid, 1);
    return 0;
}

// 2. Monitor File Opens
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    increment_counter(pid, 2);
    return 0;
}

// 3. Monitor File Reads
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    increment_counter(pid, 3);
    return 0;
}

// 4. Monitor File Writes
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    increment_counter(pid, 4);
    return 0;
}

// 5. Monitor Network Connections
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    increment_counter(pid, 5);
    return 0;
}
"""

print("Compiling Behavioral eBPF program...")
b = BPF(text=bpf_program)
detector = ThreatDetector()

print("Behavioral Profiling Engine Active.")
print("Polling kernel scoreboard every 5 seconds... (Press Ctrl+C to exit)")

try:
    while True:
        # User-space sleeps, kernel do the heavy counting
        time.sleep(5)
        
        # Iterate through the eBPF Hash Map
        for k, v in b["trackers"].items():
            pid = k.value
            
            # Only evaluate processes that were actually active in this 5-second window
            total_activity = v.exec_count + v.open_count + v.read_count + v.write_count + v.connect_count
            
            if total_activity > 0:
                print(f"[Vector] PID {pid} -> Exec:{v.exec_count} | Open:{v.open_count} | Read:{v.read_count} | Write:{v.write_count} | Connect:{v.connect_count}")
                detector.extract_and_evaluate(pid, v.exec_count, v.open_count, v.read_count, v.write_count, v.connect_count)
        
        # Wipe the kernel map clean for the next sliding window
        b["trackers"].clear()

except KeyboardInterrupt:
    print("\nDetaching from kernel and exiting safely.")