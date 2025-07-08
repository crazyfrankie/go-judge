package container_judge

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/crazyfrankie/go-judge/pkg/runner/sandbox/cgroup"
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

	// 使用简化沙箱 - 更可靠
	sandbox := NewEnhancedSandbox(config)
	return sandbox.Execute()
}

// NewParentProcess creates an isolated process based on Namespaces
func NewParentProcess(config *SandboxConfig, nsConfig *NamespaceConfig) (*exec.Cmd, *os.File, error) {
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("create pipe error: %v", err)
	}

	// Use current process as init process
	initCmd, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return nil, nil, fmt.Errorf("get init process error: %v", err)
	}

	cmd := exec.Command(initCmd, "sandbox-init")

	// Set namespace flags
	cloneFlags := uintptr(0)
	if nsConfig.UseUTS {
		cloneFlags |= syscall.CLONE_NEWUTS
	}
	if nsConfig.UsePID {
		cloneFlags |= syscall.CLONE_NEWPID
	}
	if nsConfig.UseMount {
		cloneFlags |= syscall.CLONE_NEWNS
	}
	if nsConfig.UseNet {
		cloneFlags |= syscall.CLONE_NEWNET
	}
	if nsConfig.UseIPC {
		cloneFlags |= syscall.CLONE_NEWIPC
	}
	if nsConfig.UseUser {
		cloneFlags |= syscall.CLONE_NEWUSER
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: cloneFlags,
		Setpgid:    true, // Set process group
	}

	// Don't set input/output here, let the child process handle it
	// Pass configuration information to child process
	cmd.ExtraFiles = []*os.File{readPipe}
	cmd.Dir = config.WorkDir

	// Set environment variables
	cmd.Env = []string{
		"PATH=/usr/local/go/bin:/usr/bin:/bin",
		"HOME=" + config.WorkDir,
		"TMPDIR=" + config.WorkDir,
	}

	return cmd, writePipe, nil
}

// ContainerInitProcess container initialization process
func ContainerInitProcess() error {
	// Read command
	cmdArray := readUserCommand()
	if cmdArray == nil || len(cmdArray) == 0 {
		return fmt.Errorf("run container get user command error, cmdArray is nil")
	}

	// Set up mount points
	if err := setUpMount(); err != nil {
		return fmt.Errorf("setup mount error: %v", err)
	}

	// Execute user program
	path, err := exec.LookPath(cmdArray[0])
	if err != nil {
		return fmt.Errorf("exec look path error: %v", err)
	}

	if err := syscall.Exec(path, cmdArray, os.Environ()); err != nil {
		return fmt.Errorf("exec error: %v", err)
	}

	return nil
}

// readUserCommand reads user command
func readUserCommand() []string {
	pipe := os.NewFile(uintptr(3), "pipe")
	if pipe == nil {
		return nil
	}
	defer pipe.Close()

	msg := make([]byte, 1024)
	n, err := pipe.Read(msg)
	if err != nil {
		return nil
	}

	msgStr := string(msg[:n])
	return strings.Split(strings.TrimSpace(msgStr), " ")
}

// setUpMount sets up mount points
func setUpMount() error {
	// Remount root filesystem as private
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("mount root as private error: %v", err)
	}

	// Mount proc
	defaultMountFlags := syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV
	if err := syscall.Mount("proc", "/proc", "proc", uintptr(defaultMountFlags), ""); err != nil {
		return fmt.Errorf("mount proc error: %v", err)
	}

	// Mount tmpfs to /dev
	if err := syscall.Mount("tmpfs", "/dev", "tmpfs", syscall.MS_NOSUID|syscall.MS_STRICTATIME, "mode=755"); err != nil {
		return fmt.Errorf("mount tmpfs error: %v", err)
	}

	return nil
}

// Sandbox based on Namespace and Cgroup
type Sandbox struct {
	config        *SandboxConfig
	cgroupManager *cgroup.CgroupManager
}

// NewEnhancedSandbox creates an enhanced sandbox
func NewEnhancedSandbox(config *SandboxConfig) *Sandbox {
	cgroupPath := fmt.Sprintf("sandbox-%d-%d", os.Getpid(), time.Now().UnixNano())

	return &Sandbox{
		config:        config,
		cgroupManager: cgroup.NewCgroupManager(cgroupPath),
	}
}

// Execute executes a program in the enhanced sandbox
func (s *Sandbox) Execute() (*SandboxResult, error) {
	result := &SandboxResult{}

	// Prepare execution environment
	if err := s.prepareEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to prepare environment: %v", err)
	}

	// Set namespace configuration
	nsConfig := &NamespaceConfig{
		UseUTS:   true,                    // Isolate hostname
		UsePID:   true,                    // Isolate process ID
		UseMount: true,                    // Isolate mount points
		UseNet:   !s.config.EnableNetwork, // Decide whether to isolate network based on config
		UseIPC:   true,                    // Isolate IPC
		UseUser:  false,                   // Don't use user namespace for now to avoid permission issues
	}

	// Create isolated process
	cmd, writePipe, err := NewParentProcess(s.config, nsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create parent process: %v", err)
	}
	defer writePipe.Close()

	// Set input/output redirection to parent process
	if s.config.Input != "" {
		cmd.Stdin = strings.NewReader(s.config.Input)
	}

	var outputBuffer strings.Builder
	var errorBuffer strings.Builder
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &errorBuffer

	// Record start time
	startTime := time.Now()

	// Start process
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start process: %v", err)
	}

	pid := cmd.Process.Pid
	fmt.Printf("Started sandbox process with PID: %d\n", pid)

	// Set cgroup resource limits - use dynamically calculated resource config
	resource := calculateResourceConfig(s.config.TimeLimit, s.config.MemoryLimit)

	if err := s.cgroupManager.Set(resource); err != nil {
		fmt.Printf("Warning: failed to set cgroup limits: %v\n", err)
	}

	// Add process to cgroup
	if err := s.cgroupManager.Apply(pid); err != nil {
		fmt.Printf("Warning: failed to apply cgroup to process: %v\n", err)
	}

	// Send execution command to child process
	command := s.config.Executable
	if _, err := writePipe.Write([]byte(command)); err != nil {
		return nil, fmt.Errorf("failed to write command to pipe: %v", err)
	}
	writePipe.Close()

	// Wait for execution to complete or timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	timeout := time.Duration(s.config.TimeLimit) * time.Millisecond
	var waitErr error
	var killedReason string

	// Start memory monitoring
	memoryMonitor := make(chan bool, 1)
	go s.monitorMemory(memoryMonitor)

	select {
	case waitErr = <-done:
		// Normal completion
	case <-time.After(timeout):
		// Timeout
		s.killProcessGroup(pid)
		result.Status = types.StatusTimeLimitExceeded
		waitErr = fmt.Errorf("execution timeout")
		killedReason = "timeout"
	case <-memoryMonitor:
		// Memory limit exceeded
		s.killProcessGroup(pid)
		result.Status = types.StatusMemoryLimitExceeded
		waitErr = fmt.Errorf("memory limit exceeded")
		killedReason = "memory"
	}

	// Calculate execution time
	elapsed := time.Since(startTime)
	result.TimeUsed = elapsed.Nanoseconds() / 1000000

	// Get final memory usage
	if memUsage, err := s.cgroupManager.GetMemoryUsage(); err == nil {
		result.MemoryUsed = memUsage
		fmt.Printf("Memory usage from cgroup: %d bytes (%.2f MB)\n", memUsage, float64(memUsage)/1024/1024)
	}

	// Get exit code
	if waitErr != nil {
		if exitError, ok := waitErr.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = -1
		}
	} else {
		result.ExitCode = 0
	}

	// Get program output
	result.Output = strings.TrimSpace(outputBuffer.String())
	result.ErrorOutput = strings.TrimSpace(errorBuffer.String())

	fmt.Printf("Program output: '%s'\n", result.Output)
	fmt.Printf("Program stderr: '%s'\n", result.ErrorOutput)

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

// monitorMemory monitors memory usage
func (s *Sandbox) monitorMemory(exceeded chan<- bool) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	memoryLimit := int64(s.config.MemoryLimit) * 1024 * 1024 // Convert to bytes

	for {
		select {
		case <-ticker.C:
			if usage, err := s.cgroupManager.GetMemoryUsage(); err == nil {
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

// killProcessGroup kills the process group
func (s *Sandbox) killProcessGroup(pid int) {
	// Kill the entire process group
	syscall.Kill(-pid, syscall.SIGKILL)
	time.Sleep(10 * time.Millisecond)
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
	// Memory limit: directly convert MB to bytes
	memoryBytes := int64(memoryLimit) * 1024 * 1024

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

	return &cgroup.ResourceConfig{
		MemoryLimit: strconv.FormatInt(memoryBytes, 10),
		CpuQuota:    cpuQuota,
		CpuPeriod:   cpuPeriod,
		CpuShare:    cpuShare,
		CpuSet:      "", // Don't restrict to specific CPU cores
	}
}
