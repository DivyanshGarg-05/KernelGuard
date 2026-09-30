# KernelGuard: eBPF-Powered Behavioral IDS

KernelGuard is a high-performance, zero-trust Intrusion Detection System (IDS) for Linux. By combining kernel-level eBPF tracepoints with unsupervised Machine Learning, KernelGuard autonomously detects the volumetric footprint of zero-day attacks—such as ransomware, container breakouts, and data exfiltration—without relying on static signatures or heavy CPU overhead.

## Architecture & Design Tradeoffs

KernelGuard bridges low-level memory management with high-level data science. It is split into two primary components: a high-speed C sensor in the kernel, and a Python-based ML inference engine in user space.

*   **The "Big Five" Syscalls:** To maximize signal-to-noise ratio, the eBPF program hooks only 5 critical tracepoints: `execve`, `openat`, `read`, `write`, and `connect`. 
*   **Kernel-Space Aggregation:** Instead of sending every system call to user space (which saturates CPU), the eBPF program aggregates activity locally using a `BPF_HASH` map structured around a custom C container (`struct behavior_t`).
*   **The Global Warm-Up Phase:** Maintaining per-PID machine learning models introduces massive overhead for transient processes. KernelGuard solves this by ingesting the first 100 system events across the entire OS to define a global feature space of normal behavior. The `IsolationForest` model trains exactly *once* on this dataset, then locks into O(1) inference mode for all subsequent events, eliminating data leakage and endless retraining loops.
*   **PID-Agnostic Inference:** The ML model evaluates pure mathematical vectors (e.g., `[Exec, Open, Read, Write, Connect]`), dropping the PID prior to inference to prevent biased learning, while maintaining a mapping to the original PID for forensic logging.

## Future Roadmap

*   **User Entity Behavior Analytics (UEBA):** Expanding the C `struct` to capture `UID`, allowing the inference engine to map role-based baselines to detect compromised internal accounts performing abnormal lateral movement or data dumping.
*   **Time-Delay Embedding (Kill Chain Detection):** Introducing trailing sliding windows to concatenate historical events (e.g., `T-1`, `T-2`, `T-3`) into a single feature array, allowing the stateless IsolationForest to recognize sequential state changes and attack timelines.
*   **Dynamic Synthetic Data Generation:** Developing an adversarial ML pipeline to calculate relative system baselines and generate synthetic, multi-stage attack CSVs to train Supervised Learning classifiers (`RandomForest`, `XGBoost`).

## Getting Started

### Prerequisites
This project requires a Linux environment (e.g., Fedora, Ubuntu) with root privileges and the BPF Compiler Collection (BCC) installed.
```bash
sudo dnf install bcc-tools bcc-devel python3-bcc  # Fedora/RHEL
sudo apt install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc # Ubuntu/Debian
pip3 install pandas scikit-learn