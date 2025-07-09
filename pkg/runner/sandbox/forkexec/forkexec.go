package forkexec

/*
#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/sched.h>

// For clone3 support
#include <linux/types.h>

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

// We don't need to define struct clone_args as it's already defined in linux/sched.h

#define SANDBOX_INIT_ENV "SANDBOX_INIT"

// clone flags for sandbox creation
#define CLONE_FLAGS_FULL (CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC)
#define CLONE_FLAGS_NO_NET (CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC)

// Global variables to store sandbox configuration
static char *g_executable_path = NULL;
static char *g_work_dir = NULL;
static char *g_input_data = NULL;
static int g_enable_network = 0;
static char *g_cgroup_path = NULL;

// Function to set sandbox configuration from Go
void set_sandbox_config(const char *executable, const char *workdir, const char *input, int enable_net, const char *cgroup_path) {
    if (g_executable_path) free(g_executable_path);
    if (g_work_dir) free(g_work_dir);
    if (g_input_data) free(g_input_data);
    if (g_cgroup_path) free(g_cgroup_path);
    
    g_executable_path = strdup(executable);
    g_work_dir = strdup(workdir);
    g_input_data = input ? strdup(input) : NULL;
    g_enable_network = enable_net;
    g_cgroup_path = cgroup_path ? strdup(cgroup_path) : NULL;
}

// Setup basic mount points for sandbox
int setup_sandbox_mounts() {
    // Remount root filesystem as private
    if (mount("", "/", "", MS_PRIVATE | MS_REC, "") != 0) {
        fprintf(stderr, "sandbox: failed to mount root as private: %s\n", strerror(errno));
        return -1;
    }

    // Mount proc
    if (mount("proc", "/proc", "proc", MS_NOEXEC | MS_NOSUID | MS_NODEV, "") != 0) {
        fprintf(stderr, "sandbox: failed to mount proc: %s\n", strerror(errno));
        return -1;
    }

    // Mount tmpfs to /tmp
    if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "mode=755,size=10m") != 0) {
        fprintf(stderr, "sandbox: failed to mount /tmp: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

// Container init process - this runs in the child after clone
void container_init() {
    // First thing: add ourselves to the cgroup if we have a path
    // This ensures cgroup limits are applied before any significant work is done
    if (g_cgroup_path) {
        char cgroup_procs_path[1024];
        snprintf(cgroup_procs_path, sizeof(cgroup_procs_path), "%s/cgroup.procs", g_cgroup_path);
        
        // Open cgroup.procs file
        int cgroup_fd = open(cgroup_procs_path, O_WRONLY);
        if (cgroup_fd >= 0) {
            // Get current PID
            pid_t current_pid = getpid();
            char pid_str[32];
            snprintf(pid_str, sizeof(pid_str), "%d", current_pid);
            
            // Write PID to cgroup.procs
            if (write(cgroup_fd, pid_str, strlen(pid_str)) < 0) {
                fprintf(stderr, "sandbox: failed to write PID to cgroup: %s\n", strerror(errno));
            }
            close(cgroup_fd);
        } else {
            fprintf(stderr, "sandbox: failed to open cgroup.procs: %s\n", strerror(errno));
        }
    }

    // Change to working directory
    if (g_work_dir && chdir(g_work_dir) != 0) {
        fprintf(stderr, "sandbox: failed to change directory to %s: %s\n", g_work_dir, strerror(errno));
        exit(1);
    }

    // Setup mount points
    if (setup_sandbox_mounts() != 0) {
        fprintf(stderr, "sandbox: failed to setup mounts\n");
        exit(1);
    }

    // Setup stdin if input data is provided
    if (g_input_data) {
        int pipefd[2];
        if (pipe(pipefd) == -1) {
            fprintf(stderr, "sandbox: failed to create input pipe: %s\n", strerror(errno));
            exit(1);
        }

        if (write(pipefd[1], g_input_data, strlen(g_input_data)) == -1) {
            fprintf(stderr, "sandbox: failed to write input data: %s\n", strerror(errno));
            exit(1);
        }
        close(pipefd[1]);

        if (dup2(pipefd[0], STDIN_FILENO) == -1) {
            fprintf(stderr, "sandbox: failed to redirect stdin: %s\n", strerror(errno));
            exit(1);
        }
        close(pipefd[0]);
    }

    // Redirect stdout and stderr to files in working directory
    char stdout_path[1024];
    char stderr_path[1024];
    snprintf(stdout_path, sizeof(stdout_path), "%s/stdout.txt", g_work_dir ? g_work_dir : "/tmp");
    snprintf(stderr_path, sizeof(stderr_path), "%s/stderr.txt", g_work_dir ? g_work_dir : "/tmp");

    // Open stdout file
    int stdout_fd = open(stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (stdout_fd == -1) {
        fprintf(stderr, "sandbox: failed to open stdout file: %s\n", strerror(errno));
        exit(1);
    }

    // Open stderr file
    int stderr_fd = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (stderr_fd == -1) {
        fprintf(stderr, "sandbox: failed to open stderr file: %s\n", strerror(errno));
        close(stdout_fd);
        exit(1);
    }

    // Redirect stdout and stderr
    if (dup2(stdout_fd, STDOUT_FILENO) == -1) {
        fprintf(stderr, "sandbox: failed to redirect stdout: %s\n", strerror(errno));
        exit(1);
    }

    if (dup2(stderr_fd, STDERR_FILENO) == -1) {
        fprintf(stderr, "sandbox: failed to redirect stderr: %s\n", strerror(errno));
        exit(1);
    }

    close(stdout_fd);
    close(stderr_fd);

    // Set process name
    if (prctl(PR_SET_NAME, "sandbox-init", 0, 0, 0) != 0) {
        fprintf(stderr, "sandbox: failed to set process name: %s\n", strerror(errno));
    }

    // Execute the target program
    if (g_executable_path) {
        char *args[] = {g_executable_path, NULL};
        char *env[] = {
            "PATH=/usr/local/go/bin:/usr/bin:/bin",
            "HOME=/tmp",
            "TMPDIR=/tmp",
            NULL
        };
        
        execve(g_executable_path, args, env);
        fprintf(stderr, "sandbox: execve failed: %s\n", strerror(errno));
    }
    
    exit(1);
}

// Fork and exec in C to avoid Go runtime issues
int sandbox_clone_exec(const char *executable, const char *workdir, const char *input, int enable_network, const char *cgroup_path) {
    // Set configuration
    set_sandbox_config(executable, workdir, input, enable_network, cgroup_path);

    // Choose clone flags based on network requirement
    unsigned long clone_flags = enable_network ? CLONE_FLAGS_NO_NET : CLONE_FLAGS_FULL;
    
    pid_t child_pid;
    
    // Try to use clone3 if available (Linux 5.3+)
    if (cgroup_path != NULL) {
        struct clone_args args = {0};
        args.flags = clone_flags;
        args.exit_signal = SIGCHLD;
        
        // Open cgroup.procs file to get a file descriptor
        int cgroup_fd = -1;
        char cgroup_procs_path[1024];
        snprintf(cgroup_procs_path, sizeof(cgroup_procs_path), "%s/cgroup.procs", cgroup_path);
        
        cgroup_fd = open(cgroup_procs_path, O_WRONLY);
        if (cgroup_fd >= 0) {
            args.cgroup = (__aligned_u64)cgroup_fd;
            
            // Try clone3 syscall
            child_pid = syscall(__NR_clone3, &args, sizeof(args));
            
            // Close cgroup fd regardless of clone3 success
            close(cgroup_fd);
            
            if (child_pid >= 0) {
                // clone3 succeeded
                if (child_pid == 0) {
                    // Child process - run container init
                    container_init();
                    // Should never reach here
                    exit(1);
                }
                
                // Parent process - return child PID
                return child_pid;
            }
            
            // If clone3 failed (e.g., on older kernels), fall back to regular clone
            fprintf(stderr, "sandbox: clone3 failed (kernel may not support it): %s\n", strerror(errno));
        } else {
            fprintf(stderr, "sandbox: failed to open cgroup.procs: %s\n", strerror(errno));
        }
    }
    
    // Fallback to traditional clone if clone3 is not available or failed
    child_pid = syscall(SYS_clone, clone_flags | SIGCHLD, NULL, NULL, NULL, NULL);

    if (child_pid == -1) {
        fprintf(stderr, "sandbox: clone failed: %s\n", strerror(errno));
        return -1;
    }

    if (child_pid == 0) {
        // Child process - run container init which will add itself to cgroup
        container_init();
        // Should never reach here
        exit(1);
    }

    // Parent process - return child PID
    return child_pid;
}

// The constructor runs before Go runtime starts
__attribute__((constructor)) void sandbox_init(void) {
    char *sandbox_init;
    sandbox_init = getenv(SANDBOX_INIT_ENV);

    if (sandbox_init && strcmp(sandbox_init, "1") == 0) {
        // This is the sandbox init process - let Go runtime continue
        return;
    }
}
*/
import "C"

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// ForkExecConfig contains configuration for fork+exec operation
type ForkExecConfig struct {
	Executable    string
	WorkDir       string
	Input         string
	EnableNetwork bool
	CgroupPath    string // Added cgroup path
}

// ForkExec creates a new process using C's clone+exec to avoid Go runtime stack issues
func ForkExec(config *ForkExecConfig) (int, error) {
	// Convert Go strings to C strings
	cExecutable := C.CString(config.Executable)
	defer C.free(unsafe.Pointer(cExecutable))

	cWorkDir := C.CString(config.WorkDir)
	defer C.free(unsafe.Pointer(cWorkDir))

	var cInput *C.char
	if config.Input != "" {
		cInput = C.CString(config.Input)
		defer C.free(unsafe.Pointer(cInput))
	}

	enableNetwork := 0
	if config.EnableNetwork {
		enableNetwork = 1
	}
	
	var cCgroupPath *C.char
	if config.CgroupPath != "" {
		cCgroupPath = C.CString(config.CgroupPath)
		defer C.free(unsafe.Pointer(cCgroupPath))
	}

	// Call C function to perform clone+exec
	pid := int(C.sandbox_clone_exec(cExecutable, cWorkDir, cInput, C.int(enableNetwork), cCgroupPath))
	
	if pid == -1 {
		return 0, fmt.Errorf("failed to clone and exec process")
	}

	return pid, nil
}

// WaitForProcess waits for the process to complete and returns exit status
func WaitForProcess(pid int, timeout time.Duration) (int, error) {
	// Create a channel to signal completion
	done := make(chan error, 1)
	var waitStatus syscall.WaitStatus

	go func() {
		_, err := syscall.Wait4(pid, &waitStatus, 0, nil)
		done <- err
	}()

	// Wait for completion or timeout
	select {
	case err := <-done:
		if err != nil {
			return -1, fmt.Errorf("wait4 failed: %v", err)
		}
		
		// Check if process exited normally
		if waitStatus.Exited() {
			return waitStatus.ExitStatus(), nil
		} else if waitStatus.Signaled() {
			return -1, fmt.Errorf("process killed by signal %d", waitStatus.Signal())
		}
		
		return -1, fmt.Errorf("process ended with unknown status")
		
	case <-time.After(timeout):
		// Kill the process group on timeout
		syscall.Kill(-pid, syscall.SIGKILL)
		return -1, fmt.Errorf("process timeout")
	}
}

// KillProcess kills a process and its children
func KillProcess(pid int) error {
	// Kill the entire process group
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		return fmt.Errorf("failed to kill process group %d: %v", pid, err)
	}
	
	// Give it a moment to die
	time.Sleep(10 * time.Millisecond)
	
	return nil
}