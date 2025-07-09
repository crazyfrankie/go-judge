package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/crazyfrankie/go-judge/pkg/runner/sandbox/cgroup"
	"github.com/crazyfrankie/go-judge/pkg/runner/sandbox/forkexec"
	"github.com/crazyfrankie/go-judge/pkg/types"
)

// SandboxConfig sandbox configuration
type SandboxConfig struct {
	TimeLimit     int    // Time limit (milliseconds)
	MemoryLimit   int    // Memory limit (MB)
	WorkDir       string // Working directory
	Executable    string // Executable file path
	Input         string // Input data
	OutputFile    string // Output file path
	ErrorFile     string // Error output file path
	EnableNetwork bool   // Whether to allow network access (default false)
	UseNamespaces bool   // Whether to use namespace isolation (default true)
}

// SandboxResult sandbox execution result
type SandboxResult struct {
	TimeUsed    int64  // Execution time (milliseconds)
	MemoryUsed  int64  // Memory usage (bytes)
	ExitCode    int    // Exit code
	Output      string // Program output
	ErrorOutput string // Error output
	Status      types.Status
}

// NamespaceConfig namespace configuration
type NamespaceConfig struct {
	UseUTS   bool // UTS namespace (hostname)
	UsePID   bool // PID namespace
	UseMount bool // Mount namespace
	UseNet   bool // Network namespace
	UseIPC   bool // IPC namespace
	UseUser  bool // User namespace
}

func ExecuteWithSandbox(workdir string, timeLimit, memoryLimit int, input string) (*SandboxResult, error) {
	config := &SandboxConfig{
		TimeLimit:   timeLimit,
		MemoryLimit: memoryLimit,
		WorkDir:     workdir,
		Executable:  filepath.Join(workdir, "main"),
		Input:       input,
	}

	sandbox := NewSandbox(config)
	return sandbox.Execute()
}

// Sandbox based on Namespace and Cgroup
type Sandbox struct {
	config        *SandboxConfig
	cgroupManager *cgroup.CgroupManager
}

// NewSandbox creates an enhanced sandbox
func NewSandbox(config *SandboxConfig) *Sandbox {
	cgroupPath := fmt.Sprintf("sandbox-%d-%d", os.Getpid(), time.Now().UnixNano())

	return &Sandbox{
		config:        config,
		cgroupManager: cgroup.NewCgroupManager(cgroupPath),
	}
}

// Execute executes a program in the enhanced sandbox using C-based fork+exec
func (s *Sandbox) Execute() (*SandboxResult, error) {
	result := &SandboxResult{}

	// Prepare execution environment
	if err := s.prepareEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to prepare environment: %v", err)
	}

	// Set cgroup resource limits BEFORE fork+exec
	resource := calculateResourceConfig(s.config.TimeLimit, s.config.MemoryLimit)
	if err := s.cgroupManager.Set(resource); err != nil {
		fmt.Printf("Warning: failed to set cgroup limits: %v\n", err)
	}

	// Get cgroup path for passing to fork+exec
	cgroupPath := s.cgroupManager.GetAbsolutePath()

	// Create forkexec configuration
	forkConfig := &forkexec.ForkExecConfig{
		Executable:    s.config.Executable,
		WorkDir:       s.config.WorkDir,
		Input:         s.config.Input,
		EnableNetwork: s.config.EnableNetwork,
		CgroupPath:    cgroupPath, // Pass cgroup path to fork+exec
	}

	// Record start time
	startTime := time.Now()

	// Use C-based fork+exec to avoid Go runtime stack issues
	// The process will be created directly in the cgroup if clone3 is supported
	// Otherwise, the child process will add itself to the cgroup before exec
	pid, err := forkexec.ForkExec(forkConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to fork and exec process: %v", err)
	}

	fmt.Printf("Started sandbox process with PID: %d\n", pid)

	// Set up timeout and memory monitoring
	timeout := time.Duration(s.config.TimeLimit) * time.Millisecond
	var killedReason string

	// Start memory monitoring
	memoryMonitor := make(chan bool, 1)
	go s.monitorMemory(memoryMonitor)

	// Wait for process completion or timeout/memory limit
	done := make(chan error, 1)
	go func() {
		exitCode, err := forkexec.WaitForProcess(pid, timeout)
		if err != nil {
			done <- err
		} else {
			result.ExitCode = exitCode
			done <- nil
		}
	}()

	select {
	case <-done:
		// Normal completion or process error
	case <-time.After(timeout):
		// Timeout
		forkexec.KillProcess(pid)
		result.Status = types.StatusTimeLimitExceeded
		killedReason = "timeout"
	case <-memoryMonitor:
		// Memory limit exceeded
		forkexec.KillProcess(pid)
		result.Status = types.StatusMemoryLimitExceeded
		killedReason = "memory"
	}

	// Calculate execution time
	elapsed := time.Since(startTime)
	result.TimeUsed = elapsed.Nanoseconds() / 1000000

	// Get final memory usage based on exit status
	isMemoryExceeded := killedReason == "memory" || result.Status == types.StatusMemoryLimitExceeded
	if memUsage, err := s.cgroupManager.GetMemoryUsage(isMemoryExceeded); err == nil {
		result.MemoryUsed = memUsage
		fmt.Printf("Memory usage from cgroup: %d bytes (%.2f MB)\n", memUsage, float64(memUsage)/1024/1024)
	}

	// Read output from files if they exist (since C process handles I/O directly)
	s.readProcessOutput(result)

	// Determine final status
	if result.Status == 0 { // If status hasn't been set yet
		if killedReason == "memory" {
			result.Status = types.StatusMemoryLimitExceeded
		} else if killedReason == "timeout" {
			result.Status = types.StatusTimeLimitExceeded
		} else if result.ExitCode != 0 {
			result.Status = types.StatusRuntimeError
		} else {
			result.Status = types.StatusAccepted
		}
	}

	// Clean up resources
	s.cleanup()

	return result, nil
}

// readProcessOutput reads output from the process execution
func (s *Sandbox) readProcessOutput(result *SandboxResult) {
	// Since the C process handles I/O directly, we need to read from stdout/stderr files
	// or implement a different mechanism to capture output

	// For now, we'll try to read from standard output files if they exist
	stdoutFile := filepath.Join(s.config.WorkDir, "stdout.txt")
	stderrFile := filepath.Join(s.config.WorkDir, "stderr.txt")

	// Read stdout
	if data, err := os.ReadFile(stdoutFile); err == nil {
		result.Output = strings.TrimSpace(string(data))
		os.Remove(stdoutFile) // Clean up
	}

	// Read stderr
	if data, err := os.ReadFile(stderrFile); err == nil {
		result.ErrorOutput = strings.TrimSpace(string(data))
		os.Remove(stderrFile) // Clean up
	}

	fmt.Printf("Program output: '%s'\n", result.Output)
	fmt.Printf("Program stderr: '%s'\n", result.ErrorOutput)
}

// prepareEnvironment prepares the execution environment
func (s *Sandbox) prepareEnvironment() error {
	// Ensure working directory exists
	if err := os.MkdirAll(s.config.WorkDir, 0755); err != nil {
		return fmt.Errorf("failed to create work directory: %v", err)
	}

	// Create input file
	if s.config.Input != "" {
		inputFile := filepath.Join(s.config.WorkDir, "input.txt")
		if err := os.WriteFile(inputFile, []byte(s.config.Input), 0644); err != nil {
			return fmt.Errorf("failed to create input file: %v", err)
		}
	}

	return nil
}

// monitorMemory monitors memory usage using both polling and events
func (s *Sandbox) monitorMemory(exceeded chan<- bool) {
	// Start a goroutine to check memory.events for OOM events
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if oomOccurred, err := s.cgroupManager.CheckMemoryEvents(); err == nil && oomOccurred {
					select {
					case exceeded <- true:
					default:
					}
					return
				}
			}
		}
	}()

	// Also use traditional polling as a backup mechanism
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	memoryLimit := int64(s.config.MemoryLimit * 1024 * 1024) // Convert to bytes

	for {
		select {
		case <-ticker.C:
			// Use false here since we're just checking, not reporting a memory exceeded condition yet
			if usage, err := s.cgroupManager.GetMemoryUsage(false); err == nil {
				if usage > memoryLimit {
					select {
					case exceeded <- true:
					default:
					}
					return
				}
			}
		}
	}
}

// cleanup cleans up resources
func (s *Sandbox) cleanup() {
	// Destroy cgroup
	if err := s.cgroupManager.Destroy(); err != nil {
		fmt.Printf("Warning: failed to destroy cgroup: %v\n", err)
	}
}

// calculateResourceConfig calculates resource configuration based on time and memory limits
func calculateResourceConfig(timeLimit int, memoryLimit int) *cgroup.ResourceConfig {
	// Memory limit: convert MB to bytes with a 5% buffer for system overhead
	bufferFactor := 1.5 // 5% buffer
	memoryBytes := int64(float64(memoryLimit*1024*1024) * bufferFactor)

	// CPU quota calculation:
	// timeLimit is in milliseconds, we need to set a reasonable CPU quota
	// cgroup's cpu.max format is "quota period", both in microseconds
	// Default period is 100000 microseconds (100ms)
	cpuPeriod := "100000" // 100ms = 100000 microseconds

	// Calculate CPU quota based on timeLimit
	// If timeLimit is 1000ms (1 second), we want the program to use a maximum of 1 second of CPU time
	// How many microseconds can be used at most in a 100ms PERIOD?
	// e.g. 1000ms timeLimit -> 100ms CPU can be used in every 100ms period = 100000 microseconds

	var cpuQuota string
	if timeLimit <= 100 {
		// For very short time limits, give more CPU resources to avoid starvation
		cpuQuota = "100000" // 100% CPU
	} else if timeLimit <= 1000 {
		// For programs under 1 second, give appropriate CPU quota
		cpuQuota = "100000" // 100% CPU
	} else {
		// For longer programs, limit CPU usage to prevent infinite loops
		// Dynamically adjust based on time limit
		quotaRatio := float64(timeLimit) / 1000.0 // Convert time limit to seconds
		if quotaRatio > 10 {
			quotaRatio = 10 // Maximum 10x time
		}
		quota := int(quotaRatio * 100000) // Calculate quota
		if quota > 100000 {
			quota = 100000 // Maximum 100% CPU
		}
		cpuQuota = strconv.Itoa(quota)
	}

	// CPU weight: set relative priority based on time limit
	// Programs with shorter time limits get higher weight (higher priority)
	var cpuShare string
	if timeLimit <= 100 {
		cpuShare = "2048" // High priority
	} else if timeLimit <= 1000 {
		cpuShare = "1024" // Normal priority
	} else {
		cpuShare = "512" // Low priority
	}

	memory := strconv.FormatInt(memoryBytes, 10)
	fmt.Println(memory)
	return &cgroup.ResourceConfig{
		MemoryLimit: memory,
		CpuQuota:    cpuQuota,
		CpuPeriod:   cpuPeriod,
		CpuShare:    cpuShare,
		CpuSet:      "", // Don't restrict to specific CPU cores
	}
}
