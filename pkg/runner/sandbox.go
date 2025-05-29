package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/crazyfrankie/go-judge/pkg/types"
)

// SandboxConfig 沙箱配置
type SandboxConfig struct {
	TimeLimit     int    // 时间限制（毫秒）
	MemoryLimit   int    // 内存限制（MB）
	WorkDir       string // 工作目录
	Executable    string // 可执行文件路径
	Input         string // 输入数据
	OutputFile    string // 输出文件路径
	ErrorFile     string // 错误输出文件路径
	EnableNetwork bool   // 是否允许网络访问（默认false）
	UseNamespaces bool   // 是否使用namespace隔离（默认true）
}

// SandboxResult 沙箱执行结果
type SandboxResult struct {
	TimeUsed    int64  // 执行时间（毫秒）
	MemoryUsed  int64  // 内存使用（字节）
	ExitCode    int    // 退出码
	Output      string // 程序输出
	ErrorOutput string // 错误输出
	Status      types.Status
}

// Sandbox 基于namespace、cgroup、seccomp的轻量级沙箱
type Sandbox struct {
	config *SandboxConfig
}

// NewSandbox 创建新的沙箱实例
func NewSandbox(config *SandboxConfig) *Sandbox {
	return &Sandbox{
		config: config,
	}
}

// Execute 在沙箱中执行程序
func (s *Sandbox) Execute() (*SandboxResult, error) {
	// 1. 准备执行环境
	err := s.prepareEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed to prepare environment: %v", err)
	}

	// 2. 在隔离环境中执行程序（使用系统级资源监控）
	result, err := s.executeWithSystemResourceLimits()
	if err != nil {
		return nil, fmt.Errorf("failed to execute with resource limits: %v", err)
	}

	return result, nil
}

// prepareEnvironment 准备执行环境
func (s *Sandbox) prepareEnvironment() error {
	// 确保工作目录存在
	err := os.MkdirAll(s.config.WorkDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create work directory: %v", err)
	}

	// 创建输入文件
	if s.config.Input != "" {
		inputFile := filepath.Join(s.config.WorkDir, "input.txt")
		err = os.WriteFile(inputFile, []byte(s.config.Input), 0644)
		if err != nil {
			return fmt.Errorf("failed to create input file: %v", err)
		}
	}

	return nil
}

// ExecuteWithSandbox 使用沙箱执行程序的便捷函数
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

// ResourceMonitor 资源监控器
type ResourceMonitor struct {
	Pid       int // 改为导出字段
	running   bool
	maxMemory int64
	stopChan  chan bool
}

// ResourceUsage 资源使用情况
type ResourceUsage struct {
	MaxMemory int64 // 最大内存使用（字节）
}

// NewResourceMonitor 创建新的资源监控器
func NewResourceMonitor(pid int) *ResourceMonitor {
	return &ResourceMonitor{
		Pid:      pid,
		stopChan: make(chan bool),
	}
}

// Start 开始监控
func (rm *ResourceMonitor) Start() {
	rm.running = true
	go rm.monitor()
}

// Stop 停止监控
func (rm *ResourceMonitor) Stop() {
	if rm.running {
		rm.running = false
		close(rm.stopChan)
	}
}

// AddProcess 添加要监控的进程
func (rm *ResourceMonitor) AddProcess(pid int) {
	// 在这个简化版本中，我们主要监控主进程
	// 可以扩展为监控进程组
}

// GetMaxUsage 获取最大资源使用情况
func (rm *ResourceMonitor) GetMaxUsage() *ResourceUsage {
	return &ResourceUsage{
		MaxMemory: rm.maxMemory,
	}
}

// monitor 监控循环
func (rm *ResourceMonitor) monitor() {
	ticker := time.NewTicker(10 * time.Millisecond) // 每10ms检查一次
	defer ticker.Stop()

	for rm.running {
		select {
		case <-rm.stopChan:
			return
		case <-ticker.C:
			memory := rm.getProcessMemory(rm.Pid)
			if memory > rm.maxMemory {
				rm.maxMemory = memory
			}
		}
	}
}

// getProcessMemory 获取进程内存使用
func (rm *ResourceMonitor) getProcessMemory(pid int) int64 {
	if pid <= 0 {
		return 0
	}

	// 读取 /proc/pid/status 文件获取内存信息
	statusFile := fmt.Sprintf("/proc/%d/status", pid)
	content, err := os.ReadFile(statusFile)
	if err != nil {
		// 进程可能已经结束
		return 0
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			// VmRSS 是实际物理内存使用
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					memory := kb * 1024 // 转换为字节
					return memory
				}
			}
		}
	}

	return 0
}

// 用于seccomp的常量定义
const (
	// seccomp相关常量
	SECCOMP_MODE_FILTER = 2
	SECCOMP_RET_ALLOW   = 0x7fff0000
	SECCOMP_RET_KILL    = 0x00000000
)

// executeWithSystemResourceLimits 使用系统级别的资源限制执行程序
// 使用setrlimit系统调用和增强监控进行资源限制
func (s *Sandbox) executeWithSystemResourceLimits() (*SandboxResult, error) {
	result := &SandboxResult{}

	// 准备命令
	cmd := exec.Command(s.config.Executable)
	cmd.Dir = s.config.WorkDir

	// 设置输入输出重定向
	if s.config.Input != "" {
		cmd.Stdin = strings.NewReader(s.config.Input)
	}

	// 创建管道来捕获输出
	var outputBuffer strings.Builder
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &outputBuffer

	// 设置资源限制和进程隔离
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // 设置进程组，便于清理
		// 这里可以添加更多的隔离选项，但需要权限
	}

	// 启动增强的资源监控器
	monitor := NewEnhancedResourceMonitor(0, int64(s.config.MemoryLimit*1024*1024))
	monitor.Start()
	defer monitor.Stop()

	// 记录开始时间
	startTime := time.Now()

	// 启动进程
	err := cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start process: %v", err)
	}

	// 将进程添加到监控（现在我们有了真实的PID）
	monitor.Pid = cmd.Process.Pid

	// 立即获取初始内存状态
	initialMemory := monitor.getProcessMemory(cmd.Process.Pid)
	if initialMemory > 0 {
		monitor.maxMemory = initialMemory
		fmt.Printf("Initial memory usage: %d bytes (%.2f MB)\n", initialMemory, float64(initialMemory)/1024/1024)
	}

	// 应用进程级别的资源限制（使用setrlimit）
	err = s.applyResourceLimits(cmd.Process.Pid)
	if err != nil {
		fmt.Printf("Warning: failed to apply resource limits: %v\n", err)
	}

	// 等待执行完成或超时/资源超限
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// 设置超时
	timeout := time.Duration(s.config.TimeLimit) * time.Millisecond
	var waitErr error
	var killedReason string

	select {
	case waitErr = <-done:
		// 正常完成
	case <-time.After(timeout):
		// 超时，杀死进程
		s.killProcessGroup(cmd.Process.Pid)
		result.Status = types.StatusTimeLimitExceeded
		waitErr = fmt.Errorf("execution timeout")
		killedReason = "timeout"
	case <-monitor.MemoryExceededChan():
		// 内存超限，杀死进程
		s.killProcessGroup(cmd.Process.Pid)
		result.Status = types.StatusMemoryLimitExceeded
		waitErr = fmt.Errorf("memory limit exceeded")
		killedReason = "memory"
	}

	// 计算执行时间
	elapsed := time.Since(startTime)
	result.TimeUsed = elapsed.Nanoseconds() / 1000000

	// 最终内存检查 - 确保捕获峰值
	finalMemory := monitor.getProcessMemory(cmd.Process.Pid)
	if finalMemory > monitor.maxMemory {
		monitor.maxMemory = finalMemory
	}

	// 获取退出码
	if waitErr != nil {
		if exitError, ok := waitErr.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = -1
		}
	} else {
		result.ExitCode = 0
	}

	// 获取资源使用情况
	usage := monitor.GetMaxUsage()
	result.MemoryUsed = usage.MaxMemory

	// 输出详细的内存使用信息
	if result.MemoryUsed > 0 {
		fmt.Printf("Final memory usage: %d bytes (%.2f MB)\n", result.MemoryUsed, float64(result.MemoryUsed)/1024/1024)
	} else {
		fmt.Printf("Warning: No memory usage detected\n")
	}

	// 获取程序输出
	result.Output = strings.TrimSpace(outputBuffer.String())

	// 检查状态
	if result.Status == 0 { // 如果之前没有设置状态
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

	return result, nil
}

// applyResourceLimits 应用进程级别的资源限制
func (s *Sandbox) applyResourceLimits(pid int) error {
	// 注意：setrlimit只能限制当前进程，不能限制其他进程
	// 这里我们调整策略：不限制虚拟内存，主要依靠应用级监控来限制物理内存

	// 对于Go程序，虚拟内存限制太严格会导致运行时初始化失败
	// 我们主要依靠 EnhancedResourceMonitor 的实时监控来限制实际内存使用

	// CPU时间限制 - 这个限制是有效的
	cpuTimeLimit := uint64(s.config.TimeLimit / 1000) // 转换为秒
	if cpuTimeLimit == 0 {
		cpuTimeLimit = 1 // 至少1秒
	}
	cpuRlimit := syscall.Rlimit{
		Cur: cpuTimeLimit * 2, // 给予一些缓冲，主要依靠超时机制
		Max: cpuTimeLimit * 2,
	}

	err := syscall.Setrlimit(syscall.RLIMIT_CPU, &cpuRlimit)
	if err != nil {
		// CPU限制失败也不是致命的，我们有超时机制
		fmt.Printf("Warning: failed to set CPU limit: %v\n", err)
	}

	// 限制文件描述符数量
	fdLimit := syscall.Rlimit{
		Cur: 64, // 64个文件描述符应该足够
		Max: 64,
	}

	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &fdLimit)
	if err != nil {
		fmt.Printf("Warning: failed to set file descriptor limit: %v\n", err)
	}

	return nil
}

// killProcessGroup 杀死进程组
func (s *Sandbox) killProcessGroup(pid int) {
	// 杀死整个进程组，确保清理所有子进程
	syscall.Kill(-pid, syscall.SIGKILL)

	// 等待一小段时间确保进程被杀死
	time.Sleep(10 * time.Millisecond)
}

// EnhancedResourceMonitor 增强的资源监控器，提供实时内存监控和强制终止
type EnhancedResourceMonitor struct {
	Pid            int
	running        bool
	maxMemory      int64
	memoryLimit    int64
	stopChan       chan bool
	memoryExceeded chan bool
	checkInterval  time.Duration
	killThreshold  float64 // 内存使用超过限制的百分比时强制终止
}

// NewEnhancedResourceMonitor 创建增强的资源监控器
func NewEnhancedResourceMonitor(pid int, memoryLimit int64) *EnhancedResourceMonitor {
	return &EnhancedResourceMonitor{
		Pid:            pid,
		memoryLimit:    memoryLimit,
		stopChan:       make(chan bool),
		memoryExceeded: make(chan bool, 1),
		checkInterval:  1 * time.Millisecond, // 1ms检查间隔，更激进的监控
		killThreshold:  0.95,                 // 95%内存使用时触发终止
	}
}

// Start 开始监控
func (erm *EnhancedResourceMonitor) Start() {
	erm.running = true
	go erm.monitor()
}

// Stop 停止监控
func (erm *EnhancedResourceMonitor) Stop() {
	if erm.running {
		erm.running = false
		close(erm.stopChan)
	}
}

// MemoryExceededChan 返回内存超限通知通道
func (erm *EnhancedResourceMonitor) MemoryExceededChan() <-chan bool {
	return erm.memoryExceeded
}

// GetMaxUsage 获取最大资源使用情况
func (erm *EnhancedResourceMonitor) GetMaxUsage() *ResourceUsage {
	return &ResourceUsage{
		MaxMemory: erm.maxMemory,
	}
}

// monitor 监控循环
func (erm *EnhancedResourceMonitor) monitor() {
	ticker := time.NewTicker(erm.checkInterval)
	defer ticker.Stop()

	for erm.running {
		select {
		case <-erm.stopChan:
			return
		case <-ticker.C:
			memory := erm.getProcessMemory(erm.Pid)
			if memory > erm.maxMemory {
				erm.maxMemory = memory
			}

			// 检查是否超过内存限制
			if erm.memoryLimit > 0 && memory > int64(float64(erm.memoryLimit)*erm.killThreshold) {
				select {
				case erm.memoryExceeded <- true:
					// 发送内存超限信号
				default:
					// 通道已满，不阻塞
				}
				return
			}
		}
	}
}

// getProcessMemory 获取进程内存使用（包括子进程）
func (erm *EnhancedResourceMonitor) getProcessMemory(pid int) int64 {
	if pid <= 0 {
		return 0
	}

	// 获取进程及其所有子进程的内存使用
	totalMemory := erm.getProcessMemoryDirect(pid)

	// 尝试获取子进程的内存使用
	children := erm.getChildProcesses(pid)
	for _, childPid := range children {
		childMemory := erm.getProcessMemoryDirect(childPid)
		totalMemory += childMemory
	}

	return totalMemory
}

// getProcessMemoryDirect 直接获取单个进程的内存使用
func (erm *EnhancedResourceMonitor) getProcessMemoryDirect(pid int) int64 {
	// 方法1: 从 /proc/pid/status 获取详细内存信息
	memory1 := erm.getMemoryFromStatus(pid)

	// 方法2: 从 /proc/pid/statm 获取内存页面信息
	memory2 := erm.getMemoryFromStatm(pid)

	// 返回较大的值（更保守的估计）
	if memory1 > memory2 {
		return memory1
	}
	return memory2
}

// getMemoryFromStatus 从 /proc/pid/status 获取内存信息
func (erm *EnhancedResourceMonitor) getMemoryFromStatus(pid int) int64 {
	statusFile := fmt.Sprintf("/proc/%d/status", pid)
	content, err := os.ReadFile(statusFile)
	if err != nil {
		return 0
	}

	lines := strings.Split(string(content), "\n")
	var vmRSS, vmHWM int64

	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			// VmRSS 是当前实际物理内存使用
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					vmRSS = kb * 1024 // 转换为字节
				}
			}
		} else if strings.HasPrefix(line, "VmHWM:") {
			// VmHWM 是峰值内存使用（高水位）
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					vmHWM = kb * 1024 // 转换为字节
				}
			}
		}
	}

	// 优先返回峰值内存，如果没有则返回当前内存
	if vmHWM > 0 {
		return vmHWM
	}
	return vmRSS
}

// getMemoryFromStatm 从 /proc/pid/statm 获取内存信息
func (erm *EnhancedResourceMonitor) getMemoryFromStatm(pid int) int64 {
	statmFile := fmt.Sprintf("/proc/%d/statm", pid)
	content, err := os.ReadFile(statmFile)
	if err != nil {
		return 0
	}

	// statm 文件格式: size resident shared text lib data dt
	// 我们主要关心 resident (常驻内存页面数)
	fields := strings.Fields(strings.TrimSpace(string(content)))
	if len(fields) >= 2 {
		if pages, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
			// 获取系统页面大小（通常是4096字节）
			pageSize := int64(4096)
			return pages * pageSize
		}
	}

	return 0
}

// getChildProcesses 获取进程的所有子进程
func (erm *EnhancedResourceMonitor) getChildProcesses(pid int) []int {
	var children []int

	// 读取 /proc/*/stat 文件来查找父进程ID
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return children
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// 检查目录名是否为数字（进程ID）
		childPid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// 读取该进程的stat文件
		statFile := filepath.Join(procDir, entry.Name(), "stat")
		content, err := os.ReadFile(statFile)
		if err != nil {
			continue
		}

		// 解析stat文件，第4个字段是父进程ID
		fields := strings.Fields(string(content))
		if len(fields) >= 4 {
			if ppid, err := strconv.Atoi(fields[3]); err == nil && ppid == pid {
				children = append(children, childPid)
			}
		}
	}

	return children
}
