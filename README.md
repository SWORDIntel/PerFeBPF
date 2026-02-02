# OOM Protector Daemon

The OOM Protector Daemon is a robust system utility designed to prevent Out-Of-Memory (OOM) kills of critical processes, manage system resources efficiently, and ensure system stability, especially under high memory pressure. It leverages advanced Linux kernel features like eBPF and cgroups, alongside NVIDIA GPU monitoring, to provide comprehensive protection.

## Features

*   **eBPF-based Memory Anomaly Detection:** Utilizes eBPF (extended Berkeley Packet Filter) to monitor memory allocation patterns in real-time. It can detect and alert on processes exhibiting abnormal memory allocation rates, providing early warnings of potential memory exhaustion.
*   **Cgroup Management for Critical Processes:** Automatically moves user-defined critical processes into a dedicated cgroup. This cgroup is configured with specific memory, CPU, and I/O weights (`memory.low`, `cpu.weight`, `io.weight`) to prioritize their resource access, protecting them from aggressive OOM killer actions.
*   **NVIDIA GPU Memory Protection:** Monitors NVIDIA GPU memory usage. If GPU memory exceeds a configurable threshold, the daemon identifies and terminates the largest GPU memory-consuming processes that are *not* explicitly managed (i.e., not in the protected cgroup), thus freeing up GPU resources and preventing system instability due to GPU memory exhaustion.
*   **Dynamic OOM Score Adjustment:** For non-critical processes, the daemon dynamically adjusts their `oom_score_adj` values based on their memory consumption. This helps the Linux OOM killer make more intelligent decisions, prioritizing the termination of less critical, high-memory-consuming processes.
*   **NVIDIA Driver Monitoring:** Periodically checks for new NVIDIA driver updates and can automatically set the GPU power management mode to "Prefer Maximum Performance" for consistent performance.
*   **Configurable:** All protection thresholds, managed processes, and monitoring settings are easily customizable via a `config.yaml` file.
*   **Systemd Service Integration:** Designed to run as a systemd service, ensuring it starts automatically on boot and can be managed with standard systemctl commands.
*   **Machine Learning Data Collection:** Can optionally log detailed eBPF memory anomaly events, process memory usage, and system available memory to a CSV file, facilitating data collection for future machine learning-based OOM prediction or analysis.

## How it Works

The OOM Protector Daemon operates by:

1.  **eBPF Monitoring:** Attaches eBPF programs to kernel functions (like `__x64_sys_mmap`) to track memory allocations by processes. It uses a perf event buffer to send alerts to userspace when allocation thresholds are exceeded.
2.  **Cgroup V2:** Creates and manages a dedicated cgroup (e.g., `oom_protector.slice`). Processes configured in `managed_processes` are moved into this cgroup. The cgroup's `memory.low` ensures that these processes always have a guaranteed minimum amount of memory available, while `cpu.weight` and `io.weight` manage their CPU and I/O priority.
3.  **NVIDIA SMI:** Regularly queries `nvidia-smi` to get GPU memory statistics and process-level GPU memory usage.
4.  **`/proc` Filesystem:** Interacts with the `/proc` filesystem to read process information (PID, command name, memory usage) and modify `oom_score_adj` values.
5.  **Configuration Reloads:** Listens for `SIGHUP` signals to reload its configuration dynamically without requiring a restart.

## Installation

### Requirements

*   **Go:** Go programming language (version 1.18 or newer recommended).
*   **Linux Kernel:** A modern Linux kernel (5.4+) with eBPF support enabled.
*   **libbpf-tools (or similar):** Development headers for `libbpf` might be needed for building eBPF programs. On Debian/Ubuntu: `apt install libbpf-dev`.
*   **NVIDIA Drivers:** If GPU protection is desired, NVIDIA drivers and `nvidia-smi` must be installed and functional.

### Build

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/oom_protector.git
    cd oom_protector
    ```
2.  **Generate eBPF Go bindings:**
    ```bash
    go generate ./bpf
    ```
3.  **Build the Go application:**
    ```bash
    go build -o oom_protector .
    ```

### Systemd Service Setup

1.  **Copy the executable:**
    ```bash
    sudo cp oom_protector /usr/local/bin/
    ```
    (Adjust path as necessary, ensure it matches `ExecStart` in the service file)
2.  **Copy the service file:**
    ```bash
    sudo cp oom_protector.service /etc/systemd/system/
    ```
    **Note:** You might need to edit `oom_protector.service` to adjust the `ExecStart` and `WorkingDirectory` paths if you placed the executable elsewhere or if your username is not `john`.
3.  **Reload systemd, enable, and start the service:**
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable oom_protector.service
    sudo systemctl start oom_protector.service
    ```
4.  **Check status:**
    ```bash
    systemctl status oom_protector.service
    ```

## Configuration

The daemon is configured via `config.yaml`. A sample `config.yaml` is provided:

```yaml
# Configuration for the OOM Protector Daemon

# Settings for the protected cgroup.
cgroup_settings:
  name: "oom_protector.slice"
  memory_low: 209715200 # 200MB
  cpu_weight: 150
  io_weight: 150

# Critical processes to move into the protected cgroup.
managed_processes:
  - windsurf
  - code
  - subl
  - vim
  - nvim
  - go

# GPU memory protection.
gpu_protection:
  enabled: true
  memory_threshold_percent: 90

# NVIDIA driver monitor.
nvidia_monitor:
  enabled: true
  set_performance_mode: true
  check_driver_updates: true

# eBPF-based Anomaly Detection
ebpf_monitor:
  enabled: true
  # Log a CRITICAL warning if a managed process allocates more than this
  # amount of memory within a 1-second window. Value is in MB.
  allocation_threshold_mb_per_sec: 100

# Dynamic OOM score adjustment for non-managed processes.
dynamic_adjustment:
  enabled: true
  count: 3
  score: 700

# Machine Learning Data Collection
machine_learning:
  data_collection: true
  log_path: "/var/log/oom_protector_ml_data.csv"

# Logging configuration
logging:
  json_logs: true
```

You can modify `config.yaml` and then send a `SIGHUP` signal to the running service to apply changes:

```bash
sudo systemctl reload oom_protector.service
# Or directly:
# sudo kill -SIGHUP $(pidof oom_protector)
```

## Usage

Once installed and running as a systemd service:

*   **Start:** `sudo systemctl start oom_protector.service`
*   **Stop:** `sudo systemctl stop oom_protector.service`
*   **Restart:** `sudo systemctl restart oom_protector.service`
*   **Reload Config:** `sudo systemctl reload oom_protector.service` (after modifying `config.yaml`)
*   **Check Logs:** `journalctl -u oom_protector.service` (or `tail -f /var/log/syslog` if JSON logs are disabled)

## Contributing

Contributions are welcome! Please follow these steps:

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/your-feature-name`).
3.  Make your changes.
4.  Commit your changes (`git commit -m 'feat: Add some feature'`).
5.  Push to the branch (`git push origin feature/your-feature-name`).
6.  Open a Pull Request.

## License

This project is licensed under the **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**. See the [LICENSE](LICENSE) file for details.
