package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"gopkg.in/yaml.v3"
)

// --- Struct Definitions ---
type Config struct {
	CgroupSettings    CgroupSettings    `yaml:"cgroup_settings"`
	ManagedProcesses  []string          `yaml:"managed_processes"`
	GPUProtection     GPUProtection     `yaml:"gpu_protection"`
	NvidiaMonitor     NvidiaMonitor     `yaml:"nvidia_monitor"`
	EbpfMonitor       EbpfMonitor       `yaml:"ebpf_monitor"`
	DynamicAdjustment DynamicAdjustment `yaml:"dynamic_adjustment"`
	MachineLearning   MachineLearning   `yaml:"machine_learning"`
	Logging           Logging           `yaml:"logging"`
}
type CgroupSettings struct {
	Name      string `yaml:"name"`
	MemoryLow int    `yaml:"memory_low"`
	CPUWeight int    `yaml:"cpu_weight"`
	IOWeight  int    `yaml:"io_weight"`
}
type GPUProtection struct {
	Enabled              bool `yaml:"enabled"`
	MemoryThresholdPercent int  `yaml:"memory_threshold_percent"`
}
type NvidiaMonitor struct {
	Enabled            bool `yaml:"enabled"`
	SetPerformanceMode bool `yaml:"set_performance_mode"`
	CheckDriverUpdates bool `yaml:"check_driver_updates"`
}
type EbpfMonitor struct {
	Enabled                   bool `yaml:"enabled"`
	AllocationThresholdMBPerSec int  `yaml:"allocation_threshold_mb_per_sec"`
}
type DynamicAdjustment struct {
	Enabled bool `yaml:"enabled"`
	Count   int  `yaml:"count"`
	Score   int  `yaml:"score"`
}
type MachineLearning struct {
	DataCollection bool   `yaml:"data_collection"`
	LogPath        string `yaml:"log_path"`
}
type Logging struct {
	JsonLogs bool `yaml:"json_logs"`
}
type ProcessInfo struct {
	PID   int
	Comm  string
	MemKB int
}
type GPUProcessInfo struct {
	PID          int
	UsedGPUMemKB int
}



// --- Globals ---
var (
	config          Config
	configLock      = &sync.RWMutex{}
	configFile      = "config.yaml"
	cgroupPath      string
	lastDriverCheck time.Time
	bpfObjs         *bpfObjects
)

const cgroupRoot = "/sys/fs/cgroup"
const nvidiaSmiPath = "/usr/bin/nvidia-smi"
const nvidiaSettingsPath = "/usr/bin/nvidia-settings"

// --- Main Application ---
func main() {
	if err := loadConfig(); err != nil { log.Fatalf("Failed to load config: %v", err) }
	setupLogger()
	if err := setupCgroup(); err != nil { log.Fatalf("Failed to set up cgroup: %v", err) }

	if config.EbpfMonitor.Enabled {
		if err := loadAndAttachBPF(); err != nil {
			log.Printf("CRITICAL: Failed to load eBPF program. Anomaly detection will be disabled. Error: %v", err)
		} else {
			log.Println("eBPF monitor loaded and attached successfully.")
			go handleBpfEvents()
		}
	}

	log.Println("Starting OOM Protector Daemon (ULTRA edition)...")
	handleSIGHUP()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		log.Println("Received shutdown signal, cleaning up...")
		if bpfObjs != nil {
			bpfObjs.Close()
			log.Println("BPF objects closed.")
		}
		os.Exit(0)
	}()

	if config.NvidiaMonitor.Enabled && config.NvidiaMonitor.SetPerformanceMode {
		setGpuPerformanceMode()
	}

	for {
		configLock.RLock()
		currentConfig := config
		configLock.RUnlock()

		applyHostPolicy(&currentConfig)
		if currentConfig.GPUProtection.Enabled {
			applyGPUPolicy(&currentConfig)
		}
		if currentConfig.NvidiaMonitor.Enabled {
			applyNvidiaPolicy()
		}
		if currentConfig.EbpfMonitor.Enabled {
			updateBpfMaps(&currentConfig)
		}

		time.Sleep(30 * time.Second)
	}
}

// --- eBPF Functions ---
func loadAndAttachBPF() error {
	objs, err := loadBpf()
	if err != nil {
		return fmt.Errorf("loading bpf objects: %w", err)
	}
	bpfObjs = objs
	kp, err := link.Kprobe("__x64_sys_mmap", bpfObjs.MmapProbe, nil)
	if err != nil {
		bpfObjs.Close()
		return fmt.Errorf("attaching kprobe: %w", err)
	}
	// We don't close the link so it stays active.
	_ = kp
	return nil
}

func handleBpfEvents() {
	reader, err := perf.NewReader(bpfObjs.Events, os.Getpagesize())
	if err != nil {
		log.Printf("ERROR: Failed to create eBPF perf event reader: %v", err)
		return
	}
	defer reader.Close()

	log.Println("Listening for eBPF allocation anomaly events...")
	var event bpfEvent
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("ERROR: Reading from perf event reader: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("ERROR: Parsing perf event: %v", err)
			continue
		}

		comm, err := getProcessComm(int(event.Pid))
		if err != nil {
			comm = "unknown"
		}
		log.Printf("CRITICAL: eBPF anomaly detected! PID %d (%s) allocated %.2f MB in 1s, exceeding threshold of %.2f MB.",
			event.Pid, comm, float64(event.AllocationSize)/1024/1024, float64(event.Threshold)/1024/1024)
		logBpfEventForML(event)
	}
}

func logBpfEventForML(event bpfEvent) {
	if !config.MachineLearning.DataCollection {
		return
	}

	filePath := config.MachineLearning.LogPath
	// Check if file exists to write header
	_, err := os.Stat(filePath)
	needsHeader := os.IsNotExist(err)

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("ERROR: Failed to open ML data log file: %v", err)
		return
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	if needsHeader {
		header := []string{"timestamp", "pid", "comm", "allocation_size_mb", "threshold_mb", "process_rss_mb", "system_available_mem_mb"}
		if err := writer.Write(header); err != nil {
			log.Printf("ERROR: Failed to write header to ML data log file: %v", err)
			return
		}
	}

	comm, _ := getProcessComm(int(event.Pid))
	processRSSKB, _ := getProcessMemory(int(event.Pid))
	systemAvailableMemKB, _ := getSystemAvailableMemoryKB()

	row := []string{
		time.Now().Format(time.RFC3339),
		strconv.Itoa(int(event.Pid)),
		comm,
		fmt.Sprintf("%.2f", float64(event.AllocationSize)/1024/1024),
		fmt.Sprintf("%.2f", float64(event.Threshold)/1024/1024),
		fmt.Sprintf("%.2f", float64(processRSSKB)/1024),
		fmt.Sprintf("%.2f", float64(systemAvailableMemKB)/1024),
	}
	if err := writer.Write(row); err != nil {
		log.Printf("ERROR: Failed to write to ML data log file: %v", err)
	}
}

func updateBpfMaps(currentConfig *Config) {
	thresholdBytes := uint64(currentConfig.EbpfMonitor.AllocationThresholdMBPerSec) * 1024 * 1024
	key := uint32(0)
	if err := bpfObjs.ConfigMap.Put(key, thresholdBytes); err != nil {
		log.Printf("ERROR: Failed to update eBPF config map: %v", err)
	}

	pids := getManagedPIDs(currentConfig)
	var one uint8 = 1
	for pid := range pids {
		if err := bpfObjs.ManagedPids.Put(uint32(pid), one); err != nil {
			log.Printf("WARN: Failed to update eBPF managed_pids map for PID %d: %v", pid, err)
		}
	}
}

// --- NVIDIA Driver & Perf Functions ---
func applyNvidiaPolicy() {
	if config.NvidiaMonitor.CheckDriverUpdates {
		checkDriverUpdate()
	}
}
func setGpuPerformanceMode() {
	log.Println("Setting GPU power mode to 'Prefer Maximum Performance'.")
	cmd := exec.Command(nvidiaSettingsPath, "-a", "[gpu:0]/GpuPowerMizerMode=1")
	cmd.Env = append(os.Environ(), "DISPLAY=:0")
	if err := cmd.Run(); err != nil {
		log.Printf("WARN: Could not set GPU performance mode: %v", err)
	} else {
		log.Println("GPU power mode set.")
	}
}
func checkDriverUpdate() {
	if time.Since(lastDriverCheck).Hours() < 24 {
		return
	}
	log.Println("Checking for NVIDIA driver updates...")
	lastDriverCheck = time.Now()
	out, err := exec.Command(nvidiaSmiPath, "--query-driver=driver_version", "--format=csv,noheader").Output()
	if err != nil {
		log.Printf("WARN: Could not get current NVIDIA driver version: %v", err)
		return
	}
	currentVersion := strings.TrimSpace(string(out))

	client := http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get("https://www.nvidia.com/Download/processFind.aspx?psid=101&pfid=843&osid=57&lid=1&whql=&lang=en-us&ctk=0&dtid=1&qpf=1")
	if err != nil {
		log.Printf("WARN: Could not check for NVIDIA driver updates: %v", err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil { return }

	bodyStr := string(body)
	searchString := "Latest Production Branch Version:"
	idx := strings.Index(bodyStr, searchString)
	if idx == -1 { return }
	sub := bodyStr[idx+len(searchString):]
	sub = sub[:strings.Index(sub, "<")]
	latestVersion := strings.TrimSpace(sub)
	if latestVersion != "" && currentVersion != latestVersion {
		log.Printf("INFO: New NVIDIA driver available. Current: %s, Latest: %s", currentVersion, latestVersion)
	} else if latestVersion != "" {
		log.Println("NVIDIA driver is up to date.")
	}
}

// --- GPU Memory Protection ---
func applyGPUPolicy(currentConfig *Config) {
	out, err := exec.Command(nvidiaSmiPath, "--query-gpu=memory.used,memory.total", "--format=csv,noheader,nounits").Output()
	if err != nil { return }
	reader := csv.NewReader(strings.NewReader(string(out)))
	memRecord, err := reader.Read()
	if err != nil { return }
	usedMem, _ := strconv.Atoi(strings.TrimSpace(memRecord[0]))
	totalMem, _ := strconv.Atoi(strings.TrimSpace(memRecord[1]))
	if totalMem == 0 { return }
	usagePercent := (float64(usedMem) / float64(totalMem)) * 100
	if int(usagePercent) < currentConfig.GPUProtection.MemoryThresholdPercent { return }
	log.Printf("WARN: GPU memory usage critical at %.0f%%.", usagePercent)

	out, err = exec.Command(nvidiaSmiPath, "--query-compute-apps=pid,used_gpu_memory", "--format=csv,noheader,nounits").Output()
	if err != nil { return }
	reader = csv.NewReader(strings.NewReader(string(out)))
	gpuProcsRecords, err := reader.ReadAll()
	if err != nil { return }
	var gpuProcs []GPUProcessInfo
	for _, rec := range gpuProcsRecords { pid, _ := strconv.Atoi(strings.TrimSpace(rec[0])); mem, _ := strconv.Atoi(strings.TrimSpace(rec[1])); gpuProcs = append(gpuProcs, GPUProcessInfo{PID: pid, UsedGPUMemKB: mem}) }
	protectedPIDs := getManagedPIDs(currentConfig)
	var sacrificialProcs []GPUProcessInfo
	for _, p := range gpuProcs { if !protectedPIDs[p.PID] { sacrificialProcs = append(sacrificialProcs, p) } }
	if len(sacrificialProcs) == 0 { return }
	sort.Slice(sacrificialProcs, func(i, j int) bool { return sacrificialProcs[i].UsedGPUMemKB > sacrificialProcs[j].UsedGPUMemKB })
	victim := sacrificialProcs[0]
	proc, err := os.FindProcess(victim.PID)
	if err != nil { return }
	log.Printf("ACTION: Killing process %d using %d MiB of GPU memory.", victim.PID, victim.UsedGPUMemKB)
	if err := proc.Kill(); err != nil { log.Printf("ERROR: Failed to kill PID %d: %v", victim.PID, err) }
}

// --- Host Policy (cgroup & OOM) ---
func applyHostPolicy(currentConfig *Config) {
	procs, err := os.ReadDir("/proc")
	if err != nil { return }
	managedProcsMap := make(map[string]bool)
	for _, pName := range currentConfig.ManagedProcesses { managedProcsMap[pName] = true }
	var allProcs []ProcessInfo
	staticallyManagedPIDs := make(map[int]bool)
	for _, proc := range procs {
		if !proc.IsDir() { continue }
		pid, err := strconv.Atoi(proc.Name())
		if err != nil { continue }
		comm, err := getProcessComm(pid)
		if err != nil { continue }
		if managedProcsMap[comm] { staticallyManagedPIDs[pid] = true; if err := moveProcessToCgroup(pid, currentConfig); err != nil { log.Printf("WARN: Failed to move PID %d to cgroup: %v", pid, err) } }
		if currentConfig.DynamicAdjustment.Enabled { if mem, err := getProcessMemory(pid); err == nil { allProcs = append(allProcs, ProcessInfo{PID: pid, Comm: comm, MemKB: mem}) } }
	}
	if currentConfig.DynamicAdjustment.Enabled { applyDynamicOOMScore(allProcs, staticallyManagedPIDs, currentConfig) }
}
func applyDynamicOOMScore(allProcs []ProcessInfo, staticPIDs map[int]bool, currentConfig *Config) {
	var dynamicCandidates []ProcessInfo
	for _, p := range allProcs { if !staticPIDs[p.PID] && p.MemKB > 0 { dynamicCandidates = append(dynamicCandidates, p) } }
	sort.Slice(dynamicCandidates, func(i, j int) bool { return dynamicCandidates[i].MemKB > dynamicCandidates[j].MemKB })
	count := currentConfig.DynamicAdjustment.Count
	if len(dynamicCandidates) < count { count = len(dynamicCandidates) }
	for i := 0; i < count; i++ {
		proc := dynamicCandidates[i]
		adjustOOMScore(proc.PID, currentConfig.DynamicAdjustment.Score, proc.Comm)
	}
}

// --- Setup & Helper Functions ---
func loadConfig() error {
	log.Println("Loading configuration...")
	data, err := ioutil.ReadFile(configFile)
	if err != nil { return err }
	configLock.Lock()
	defer configLock.Unlock()
	var newConfig Config
	if err := yaml.Unmarshal(data, &newConfig); err != nil { return err }
	config = newConfig
	cgroupPath = filepath.Join(cgroupRoot, config.CgroupSettings.Name)
	log.Printf("Configuration loaded. eBPF monitor enabled: %v", newConfig.EbpfMonitor.Enabled)
	return nil
}
func setupCgroup() error {
	configLock.RLock()
	cgSettings := config.CgroupSettings
	configLock.RUnlock()
	log.Printf("Ensuring cgroup '%s' exists.", cgroupPath)
	if err := os.MkdirAll(cgroupPath, 0755); err != nil { return fmt.Errorf("cgroup dir error: %w", err) }
	controls := map[string]int{"memory.low": cgSettings.MemoryLow, "cpu.weight": cgSettings.CPUWeight, "io.weight": cgSettings.IOWeight}
	for file, value := range controls {
		if err := ioutil.WriteFile(filepath.Join(cgroupPath, file), []byte(strconv.Itoa(value)), 0644); err != nil {
			log.Printf("WARN: Cgroup controller '%s' failed: %v", file, err)
		}
	}
	log.Println("cgroup settings applied.")
	return nil
}
func handleSIGHUP() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	go func() {
		for {
			<-sigs
			log.Println("SIGHUP received, reloading...")
			if err := loadConfig(); err != nil { log.Printf("ERROR: reload failed: %v", err) }
			if err := setupCgroup(); err != nil { log.Printf("ERROR: re-apply cgroup failed: %v", err) }
		}
	}()
}
func moveProcessToCgroup(pid int, currentConfig *Config) error {
	path := filepath.Join("/proc", strconv.Itoa(pid), "cgroup")
	data, err := ioutil.ReadFile(path)
	if err != nil { return err }
	if strings.Contains(string(data), currentConfig.CgroupSettings.Name) { return nil }
	return ioutil.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644)
}
func getManagedPIDs(currentConfig *Config) map[int]bool {
	pids := make(map[int]bool)
	procs, err := os.ReadDir("/proc")
	if err != nil { return pids }
	managedMap := make(map[string]bool)
	for _, name := range currentConfig.ManagedProcesses { managedMap[name] = true }
	for _, proc := range procs {
		if !proc.IsDir() { continue }
		pid, err := strconv.Atoi(proc.Name())
		if err != nil { continue }
		comm, err := getProcessComm(pid)
		if err != nil { continue }
		if managedMap[comm] { pids[pid] = true }
	}
	return pids
}
func getProcessComm(pid int) (string, error) {
	data, err := ioutil.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	return strings.TrimSpace(string(data)), err
}
func getProcessMemory(pid int) (int, error) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil { return 0, err }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			if parts := strings.Fields(line); len(parts) >= 2 {
				if memKB, err := strconv.Atoi(parts[1]); err == nil {
					return memKB, nil
				}
			}
		}
	}
	return 0, scanner.Err()
}
func adjustOOMScore(pid int, score int, comm string) {
	oomScoreAdjPath := filepath.Join("/proc", strconv.Itoa(pid), "oom_score_adj")
	data, err := ioutil.ReadFile(oomScoreAdjPath)
	if err != nil { return }
	currentScore, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	if currentScore != score {
		if err := ioutil.WriteFile(oomScoreAdjPath, []byte(strconv.Itoa(score)), 0644); err == nil {
			log.Printf("Dynamic OOM score for %s (PID: %d) set to %d", comm, pid, score)
		}
	}
}

func getSystemAvailableMemoryKB() (int, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemAvailable:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				memKB, err := strconv.Atoi(parts[1])
				if err == nil {
					return memKB, nil
				}
			}
		}
	}
	return 0, scanner.Err()
}

func setupLogger() {
	if config.Logging.JsonLogs {
		log.SetFlags(0) // Clear default flags to not double timestamp etc.
		log.SetOutput(new(jsonLogWriter))
	} else {
		logwriter, err := syslog.New(syslog.LOG_NOTICE, "oom_protector")
		if err != nil { log.Fatalf("Unable to set up syslog: %v", err) }
		log.SetOutput(logwriter)
	}
}

// jsonLogWriter is an io.Writer that formats log messages as JSON.
type jsonLogWriter struct{}

func (j *jsonLogWriter) Write(p []byte) (n int, err error) {
	entry := make(map[string]interface{})
	entry["timestamp"] = time.Now().Format(time.RFC3339)
	entry["level"] = "INFO" // Default level, actual level would need parsing
	entry["message"] = strings.TrimSpace(string(p))

	// Attempt to parse existing log prefixes if they exist (e.g., "CRITICAL: ")
	msg := strings.TrimSpace(string(p))
	if strings.HasPrefix(msg, "CRITICAL: ") {
		entry["level"] = "CRITICAL"
		entry["message"] = strings.TrimPrefix(msg, "CRITICAL: ")
	} else if strings.HasPrefix(msg, "ERROR: ") {
		entry["level"] = "ERROR"
		entry["message"] = strings.TrimPrefix(msg, "ERROR: ")
	} else if strings.HasPrefix(msg, "WARN: ") {
		entry["level"] = "WARN"
		entry["message"] = strings.TrimPrefix(msg, "WARN: ")
	} else if strings.HasPrefix(msg, "INFO: ") {
		entry["level"] = "INFO"
		entry["message"] = strings.TrimPrefix(msg, "INFO: ")
	}

	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal log entry to JSON: %w", err)
	}

	// Write to stderr or stdout, typically stderr for logs.
	// For this daemon, outputting to syslog (which is often redirected to a file) is already handled
	// for non-JSON, so for JSON, we can write to stderr.
	return os.Stderr.Write(append(jsonBytes, '\n'))
}
