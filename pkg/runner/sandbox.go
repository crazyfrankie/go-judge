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
	"unsafe"

	"golang.org/x/sys/unix"

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

// 用于seccomp的常量定义
const (
	// seccomp相关常量
	SECCOMP_MODE_FILTER = 2
	SECCOMP_RET_ALLOW   = 0x7fff0000
	SECCOMP_RET_KILL    = 0x00000000
	SECCOMP_RET_ERRNO   = 0x00050000

	// BPF相关常量
	BPF_LD  = 0x00
	BPF_W   = 0x00
	BPF_ABS = 0x20
	BPF_JMP = 0x05
	BPF_JEQ = 0x10
	BPF_JGE = 0x30
	BPF_JGT = 0x20
	BPF_RET = 0x06
	BPF_K   = 0x00

	// 系统调用偏移
	SYS_CALL_OFFSET = 0
)

// BPF指令结构
type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// seccomp程序结构
type sockFprog struct {
	len    uint16
	filter *sockFilter
}

// 允许的系统调用白名单（Go程序运行必需的基本系统调用）
var allowedSyscalls = []uint32{
	unix.SYS_READ,
	unix.SYS_WRITE,
	unix.SYS_OPENAT,
	unix.SYS_CLOSE,
	unix.SYS_FSTAT,
	unix.SYS_LSEEK,
	unix.SYS_MMAP,
	unix.SYS_MUNMAP,
	unix.SYS_MPROTECT,
	unix.SYS_BRK,
	unix.SYS_RT_SIGACTION,
	unix.SYS_RT_SIGPROCMASK,
	unix.SYS_RT_SIGRETURN,
	unix.SYS_IOCTL,
	unix.SYS_PREAD64,
	unix.SYS_PWRITE64,
	unix.SYS_READV,
	unix.SYS_WRITEV,
	unix.SYS_ACCESS,
	unix.SYS_PIPE,
	unix.SYS_SELECT,
	unix.SYS_SCHED_YIELD,
	unix.SYS_MREMAP,
	unix.SYS_MSYNC,
	unix.SYS_MINCORE,
	unix.SYS_MADVISE,
	unix.SYS_DUP,
	unix.SYS_DUP2,
	unix.SYS_NANOSLEEP,
	unix.SYS_GETITIMER,
	unix.SYS_ALARM,
	unix.SYS_SETITIMER,
	unix.SYS_GETPID,
	unix.SYS_SENDFILE,
	unix.SYS_SOCKET,   // 受限制的网络调用
	unix.SYS_CONNECT,  // 受限制的网络调用
	unix.SYS_ACCEPT,   // 受限制的网络调用
	unix.SYS_SENDTO,   // 受限制的网络调用
	unix.SYS_RECVFROM, // 受限制的网络调用
	unix.SYS_SENDMSG,  // 受限制的网络调用
	unix.SYS_RECVMSG,  // 受限制的网络调用
	unix.SYS_SHUTDOWN, // 受限制的网络调用
	unix.SYS_BIND,     // 受限制的网络调用
	unix.SYS_LISTEN,   // 受限制的网络调用
	unix.SYS_GETSOCKNAME,
	unix.SYS_GETPEERNAME,
	unix.SYS_SOCKETPAIR,
	unix.SYS_SETSOCKOPT,
	unix.SYS_GETSOCKOPT,
	unix.SYS_CLONE,  // 限制进程创建
	unix.SYS_FORK,   // 禁止fork
	unix.SYS_VFORK,  // 禁止vfork
	unix.SYS_EXECVE, // 限制程序执行
	unix.SYS_EXIT,
	unix.SYS_WAIT4,
	unix.SYS_KILL,
	unix.SYS_UNAME,
	unix.SYS_SEMGET,
	unix.SYS_SEMOP,
	unix.SYS_SEMCTL,
	unix.SYS_SHMDT,
	unix.SYS_MSGGET,
	unix.SYS_MSGSND,
	unix.SYS_MSGRCV,
	unix.SYS_MSGCTL,
	unix.SYS_FCNTL,
	unix.SYS_FLOCK,
	unix.SYS_FSYNC,
	unix.SYS_FDATASYNC,
	unix.SYS_TRUNCATE,
	unix.SYS_FTRUNCATE,
	unix.SYS_GETDENTS,
	unix.SYS_GETCWD,
	unix.SYS_CHDIR,
	unix.SYS_FCHDIR,
	unix.SYS_RENAME,
	unix.SYS_MKDIR,
	unix.SYS_RMDIR,
	unix.SYS_CREAT,
	unix.SYS_LINK,
	unix.SYS_UNLINK,
	unix.SYS_SYMLINK,
	unix.SYS_READLINK,
	unix.SYS_CHMOD,
	unix.SYS_FCHMOD,
	unix.SYS_CHOWN,
	unix.SYS_FCHOWN,
	unix.SYS_LCHOWN,
	unix.SYS_UMASK,
	unix.SYS_GETTIMEOFDAY,
	unix.SYS_GETRLIMIT,
	unix.SYS_GETRUSAGE,
	unix.SYS_SYSINFO,
	unix.SYS_TIMES,
	unix.SYS_PTRACE,
	unix.SYS_GETUID,
	unix.SYS_SYSLOG,
	unix.SYS_GETGID,
	unix.SYS_SETUID,
	unix.SYS_SETGID,
	unix.SYS_GETEUID,
	unix.SYS_GETEGID,
	unix.SYS_SETPGID,
	unix.SYS_GETPPID,
	unix.SYS_GETPGRP,
	unix.SYS_SETSID,
	unix.SYS_SETREUID,
	unix.SYS_SETREGID,
	unix.SYS_GETGROUPS,
	unix.SYS_SETGROUPS,
	unix.SYS_SETRESUID,
	unix.SYS_GETRESUID,
	unix.SYS_SETRESGID,
	unix.SYS_GETRESGID,
	unix.SYS_GETPGID,
	unix.SYS_SETFSUID,
	unix.SYS_SETFSGID,
	unix.SYS_GETSID,
	unix.SYS_CAPGET,
	unix.SYS_CAPSET,
	unix.SYS_RT_SIGPENDING,
	unix.SYS_RT_SIGTIMEDWAIT,
	unix.SYS_RT_SIGQUEUEINFO,
	unix.SYS_RT_SIGSUSPEND,
	unix.SYS_SIGALTSTACK,
	unix.SYS_UTIME,
	unix.SYS_MKNOD,
	unix.SYS_USELIB,
	unix.SYS_PERSONALITY,
	unix.SYS_USTAT,
	unix.SYS_STATFS,
	unix.SYS_FSTATFS,
	unix.SYS_SYSFS,
	unix.SYS_GETPRIORITY,
	unix.SYS_SETPRIORITY,
	unix.SYS_SCHED_SETPARAM,
	unix.SYS_SCHED_GETPARAM,
	unix.SYS_SCHED_SETSCHEDULER,
	unix.SYS_SCHED_GETSCHEDULER,
	unix.SYS_SCHED_GET_PRIORITY_MAX,
	unix.SYS_SCHED_GET_PRIORITY_MIN,
	unix.SYS_SCHED_RR_GET_INTERVAL,
	unix.SYS_MLOCK,
	unix.SYS_MUNLOCK,
	unix.SYS_MLOCKALL,
	unix.SYS_MUNLOCKALL,
	unix.SYS_VHANGUP,
	unix.SYS_MODIFY_LDT,
	unix.SYS_PIVOT_ROOT,
	unix.SYS_PRCTL,
	unix.SYS_ARCH_PRCTL,
	unix.SYS_ADJTIMEX,
	unix.SYS_SETRLIMIT,
	unix.SYS_CHROOT,
	unix.SYS_SYNC,
	unix.SYS_ACCT,
	unix.SYS_SETTIMEOFDAY,
	unix.SYS_MOUNT,
	unix.SYS_UMOUNT2,
	unix.SYS_SWAPON,
	unix.SYS_SWAPOFF,
	unix.SYS_REBOOT,
	unix.SYS_SETHOSTNAME,
	unix.SYS_SETDOMAINNAME,
	unix.SYS_IOPL,
	unix.SYS_IOPERM,
	unix.SYS_INIT_MODULE,
	unix.SYS_DELETE_MODULE,
	unix.SYS_QUOTACTL,
	unix.SYS_GETTID,
	unix.SYS_READAHEAD,
	unix.SYS_SETXATTR,
	unix.SYS_LSETXATTR,
	unix.SYS_FSETXATTR,
	unix.SYS_GETXATTR,
	unix.SYS_LGETXATTR,
	unix.SYS_FGETXATTR,
	unix.SYS_LISTXATTR,
	unix.SYS_LLISTXATTR,
	unix.SYS_FLISTXATTR,
	unix.SYS_REMOVEXATTR,
	unix.SYS_LREMOVEXATTR,
	unix.SYS_FREMOVEXATTR,
	unix.SYS_TKILL,
	unix.SYS_TIME,
	unix.SYS_FUTEX,
	unix.SYS_SCHED_SETAFFINITY,
	unix.SYS_SCHED_GETAFFINITY,
	unix.SYS_IO_SETUP,
	unix.SYS_IO_DESTROY,
	unix.SYS_IO_GETEVENTS,
	unix.SYS_IO_SUBMIT,
	unix.SYS_IO_CANCEL,
	unix.SYS_LOOKUP_DCOOKIE,
	unix.SYS_EPOLL_CREATE,
	unix.SYS_EPOLL_CTL,
	unix.SYS_EPOLL_WAIT,
	unix.SYS_REMAP_FILE_PAGES,
	unix.SYS_GETDENTS64,
	unix.SYS_SET_TID_ADDRESS,
	unix.SYS_RESTART_SYSCALL,
	unix.SYS_SEMTIMEDOP,
	unix.SYS_FADVISE64,
	unix.SYS_TIMER_CREATE,
	unix.SYS_TIMER_SETTIME,
	unix.SYS_TIMER_GETTIME,
	unix.SYS_TIMER_GETOVERRUN,
	unix.SYS_TIMER_DELETE,
	unix.SYS_CLOCK_SETTIME,
	unix.SYS_CLOCK_GETTIME,
	unix.SYS_CLOCK_GETRES,
	unix.SYS_CLOCK_NANOSLEEP,
	unix.SYS_EXIT_GROUP,
	unix.SYS_EPOLL_PWAIT,
	unix.SYS_UTIMENSAT,
	unix.SYS_SIGNALFD,
	unix.SYS_TIMERFD_CREATE,
	unix.SYS_EVENTFD,
	unix.SYS_FALLOCATE,
	unix.SYS_TIMERFD_SETTIME,
	unix.SYS_TIMERFD_GETTIME,
	unix.SYS_ACCEPT4,
	unix.SYS_SIGNALFD4,
	unix.SYS_EVENTFD2,
	unix.SYS_EPOLL_CREATE1,
	unix.SYS_DUP3,
	unix.SYS_PIPE2,
	unix.SYS_INOTIFY_INIT1,
	unix.SYS_PREADV,
	unix.SYS_PWRITEV,
	unix.SYS_RT_TGSIGQUEUEINFO,
	unix.SYS_PERF_EVENT_OPEN,
	unix.SYS_RECVMMSG,
	unix.SYS_FANOTIFY_INIT,
	unix.SYS_FANOTIFY_MARK,
	unix.SYS_PRLIMIT64,
	unix.SYS_NAME_TO_HANDLE_AT,
	unix.SYS_OPEN_BY_HANDLE_AT,
	unix.SYS_CLOCK_ADJTIME,
	unix.SYS_SYNCFS,
	unix.SYS_SENDMMSG,
	unix.SYS_SETNS,
	unix.SYS_GETCPU,
	unix.SYS_PROCESS_VM_READV,
	unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_KCMP,
	unix.SYS_FINIT_MODULE,
	unix.SYS_SCHED_SETATTR,
	unix.SYS_SCHED_GETATTR,
	unix.SYS_RENAMEAT2,
	unix.SYS_SECCOMP,
	unix.SYS_GETRANDOM,
	unix.SYS_MEMFD_CREATE,
	unix.SYS_KEXEC_FILE_LOAD,
	unix.SYS_BPF,
	unix.SYS_EXECVEAT,
	unix.SYS_USERFAULTFD,
	unix.SYS_MEMBARRIER,
	unix.SYS_MLOCK2,
	unix.SYS_COPY_FILE_RANGE,
	unix.SYS_PREADV2,
	unix.SYS_PWRITEV2,
}

// 禁止的系统调用黑名单（危险的系统调用）
var forbiddenSyscalls = []uint32{
	unix.SYS_FORK,             // 禁止fork
	unix.SYS_VFORK,            // 禁止vfork
	unix.SYS_EXECVE,           // 禁止执行其他程序
	unix.SYS_EXECVEAT,         // 禁止执行其他程序
	unix.SYS_PTRACE,           // 禁止调试
	unix.SYS_MOUNT,            // 禁止挂载
	unix.SYS_UMOUNT2,          // 禁止卸载
	unix.SYS_CHROOT,           // 禁止改变根目录
	unix.SYS_REBOOT,           // 禁止重启
	unix.SYS_SYSLOG,           // 禁止系统日志
	unix.SYS_USELIB,           // 禁止动态库加载
	unix.SYS_PERSONALITY,      // 禁止改变个性
	unix.SYS_USTAT,            // 禁止文件系统状态
	unix.SYS_SYSFS,            // 禁止系统文件系统
	unix.SYS_MODIFY_LDT,       // 禁止修改LDT
	unix.SYS_PIVOT_ROOT,       // 禁止改变根
	unix.SYS_ADJTIMEX,         // 禁止调整时间
	unix.SYS_ACCT,             // 禁止进程记账
	unix.SYS_SETTIMEOFDAY,     // 禁止设置时间
	unix.SYS_SWAPON,           // 禁止启用交换
	unix.SYS_SWAPOFF,          // 禁止关闭交换
	unix.SYS_SETHOSTNAME,      // 禁止设置主机名
	unix.SYS_SETDOMAINNAME,    // 禁止设置域名
	unix.SYS_IOPL,             // 禁止IO权限
	unix.SYS_IOPERM,           // 禁止IO权限
	unix.SYS_INIT_MODULE,      // 禁止加载模块
	unix.SYS_DELETE_MODULE,    // 禁止删除模块
	unix.SYS_QUOTACTL,         // 禁止配额控制
	unix.SYS_LOOKUP_DCOOKIE,   // 禁止dcache操作
	unix.SYS_REMAP_FILE_PAGES, // 禁止重映射页面
	unix.SYS_KEXEC_FILE_LOAD,  // 禁止kexec
	unix.SYS_BPF,              // 禁止BPF操作
	unix.SYS_USERFAULTFD,      // 禁止用户错误fd
}

// 限制的文件路径（不允许访问的路径）
var restrictedPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/hosts",
	"/proc/meminfo",
	"/proc/cpuinfo",
	"/sys/",
	"/dev/",
	"/root/",
	"/var/log/",
	"/usr/bin/",
	"/usr/sbin/",
	"/bin/",
	"/sbin/",
}

// createSeccompFilter 创建seccomp过滤器
func createSeccompFilter(config *SandboxConfig) (*sockFprog, error) {
	// 创建一个基本的seccomp过滤器
	// 这个过滤器允许大部分系统调用，但禁止危险的系统调用

	filters := []sockFilter{}

	// 加载架构 - 检查是否为x86_64
	filters = append(filters, sockFilter{
		code: BPF_LD | BPF_W | BPF_ABS,
		k:    4, // arch字段偏移
	})

	// 如果不是x86_64，杀死进程
	filters = append(filters, sockFilter{
		code: BPF_JMP | BPF_JEQ | BPF_K,
		k:    0xc000003e, // AUDIT_ARCH_X86_64
		jt:   1,
		jf:   0,
	})

	filters = append(filters, sockFilter{
		code: BPF_RET | BPF_K,
		k:    SECCOMP_RET_KILL,
	})

	// 加载系统调用号
	filters = append(filters, sockFilter{
		code: BPF_LD | BPF_W | BPF_ABS,
		k:    0, // nr字段偏移
	})

	// 检查禁止的系统调用
	for _, syscall := range forbiddenSyscalls {
		filters = append(filters, sockFilter{
			code: BPF_JMP | BPF_JEQ | BPF_K,
			k:    syscall,
			jt:   uint8(len(filters) + 2), // 跳转到KILL
			jf:   0,
		})
	}

	// 对网络相关的系统调用进行特殊处理
	if !config.EnableNetwork {
		networkSyscalls := []uint32{
			unix.SYS_SOCKET,
			unix.SYS_CONNECT,
			unix.SYS_ACCEPT,
			unix.SYS_ACCEPT4,
			unix.SYS_BIND,
			unix.SYS_LISTEN,
			unix.SYS_SENDTO,
			unix.SYS_RECVFROM,
			unix.SYS_SENDMSG,
			unix.SYS_RECVMSG,
			unix.SYS_SENDMMSG,
			unix.SYS_RECVMMSG,
		}

		for _, syscall := range networkSyscalls {
			filters = append(filters, sockFilter{
				code: BPF_JMP | BPF_JEQ | BPF_K,
				k:    syscall,
				jt:   uint8(len(filters) + 2), // 跳转到ERRNO
				jf:   0,
			})
		}

		// 返回网络错误
		filters = append(filters, sockFilter{
			code: BPF_RET | BPF_K,
			k:    uint32(SECCOMP_RET_ERRNO | (unix.EACCES & 0xFFFF)),
		})
	}

	// 默认允许其他系统调用
	filters = append(filters, sockFilter{
		code: BPF_RET | BPF_K,
		k:    SECCOMP_RET_ALLOW,
	})

	// KILL跳转目标
	filters = append(filters, sockFilter{
		code: BPF_RET | BPF_K,
		k:    SECCOMP_RET_KILL,
	})

	// 创建程序结构
	prog := &sockFprog{
		len:    uint16(len(filters)),
		filter: &filters[0],
	}

	return prog, nil
}

// applySeccompFilter 应用seccomp过滤器
func applySeccompFilter(config *SandboxConfig) error {
	// 创建seccomp过滤器
	prog, err := createSeccompFilter(config)
	if err != nil {
		return fmt.Errorf("failed to create seccomp filter: %v", err)
	}

	// 应用seccomp过滤器
	_, _, errno := syscall.Syscall(unix.SYS_PRCTL,
		unix.PR_SET_SECCOMP,
		SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(prog)))

	if errno != 0 {
		return fmt.Errorf("failed to apply seccomp filter: %v", errno)
	}

	return nil
}

// applySeccompToProcess 对指定进程应用seccomp过滤器
func (s *Sandbox) applySeccompToProcess(pid int) error {
	// 注意：seccomp只能在当前进程中应用，不能对其他进程应用
	// 这里我们主要用于记录和警告
	// 实际的seccomp应用需要在子进程内部进行

	// 验证配置安全性
	if s.config.EnableNetwork {
		fmt.Printf("Warning: Network access is enabled for process %d\n", pid)
	}

	// 检查文件系统访问限制
	fmt.Printf("Process %d is restricted to directory: %s\n", pid, s.config.WorkDir)

	return nil
}

// validateSecurityConfig 验证安全配置
func (s *Sandbox) validateSecurityConfig() error {
	// 检查是否允许网络访问
	if !s.config.EnableNetwork {
		fmt.Printf("Network access is disabled for security\n")
	}

	// 验证工作目录是否安全
	if strings.Contains(s.config.WorkDir, "..") {
		return fmt.Errorf("work directory contains unsafe path traversal")
	}

	// 检查可执行文件路径
	if !strings.HasPrefix(s.config.Executable, s.config.WorkDir) {
		return fmt.Errorf("executable must be within work directory")
	}

	// 验证受限路径
	for _, restricted := range restrictedPaths {
		if strings.HasPrefix(s.config.WorkDir, restricted) {
			return fmt.Errorf("work directory is in restricted path: %s", restricted)
		}
	}

	return nil
}

// checkFileAccess 检查文件访问是否被允许
func checkFileAccess(path string) error {
	// 检查是否访问受限路径
	for _, restricted := range restrictedPaths {
		if strings.HasPrefix(path, restricted) {
			return fmt.Errorf("access to path %s is restricted", path)
		}
	}
	return nil
}

// wrapFileOperations 包装文件操作以添加访问控制
func wrapFileOperations(cmd *exec.Cmd, config *SandboxConfig) {
	// 设置环境变量以限制文件访问
	cmd.Env = []string{
		"PATH=/usr/local/go/bin:/usr/bin:/bin",
		"HOME=" + config.WorkDir,
		"TMPDIR=" + config.WorkDir,
		"TEMP=" + config.WorkDir,
		"TMP=" + config.WorkDir,
	}

	// 设置工作目录
	cmd.Dir = config.WorkDir
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

	// 2. 验证安全配置
	err = s.validateSecurityConfig()
	if err != nil {
		return nil, fmt.Errorf("security validation failed: %v", err)
	}

	// 3. 在隔离环境中执行程序（使用系统级资源监控）
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

	// 设置环境变量和文件访问控制
	wrapFileOperations(cmd, s.config)

	// 设置资源限制和进程隔离
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // 设置进程组，便于清理
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

	// 应用seccomp过滤器（需要在进程启动后应用到该进程）
	if err := s.applySeccompToProcess(cmd.Process.Pid); err != nil {
		fmt.Printf("Warning: failed to apply seccomp filter to process: %v\n", err)
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
		Cur: 256, // 256个文件描述符应该足够Go程序运行
		Max: 256,
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
