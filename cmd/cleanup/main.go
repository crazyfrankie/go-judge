package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	fmt.Println("开始清理系统资源...")

	// 1. 清理僵尸进程
	fmt.Println("清理可能的僵尸进程...")
	killOrphanedProcesses()

	// 2. 关闭泄漏的文件描述符
	fmt.Println("关闭泄漏的文件描述符...")
	closeLeakedFileDescriptors()

	// 3. 强制垃圾回收
	fmt.Println("执行系统级别垃圾回收...")
	cmd := exec.Command("sync")
	cmd.Run()

	// 尝试清理overlay挂载点
	fmt.Println("清理可能的overlay挂载点...")
	cleanupOverlayMounts()

	fmt.Println("资源清理完成！")
}

// killOrphanedProcesses 杀死可能被遗漏的沙箱进程
func killOrphanedProcesses() {
	// 查找可能是沙箱创建但未被正确终止的进程
	cmd := exec.Command("ps", "-eo", "pid,ppid,cmd")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("无法列出进程: %v\n", err)
		return
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "main") && strings.Contains(line, "sandbox") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pidStr := fields[0]
				pid, err := strconv.Atoi(pidStr)
				if err == nil && pid > 1 {
					// 尝试终止进程
					fmt.Printf("杀死进程 %d\n", pid)
					syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}
	}
}

// closeLeakedFileDescriptors 关闭可能泄漏的文件描述符
func closeLeakedFileDescriptors() {
	// 获取当前进程的PID
	pid := os.Getpid()

	// 检查当前进程的文件描述符目录
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	files, err := ioutil.ReadDir(fdDir)
	if err != nil {
		fmt.Printf("无法读取文件描述符目录: %v\n", err)
		return
	}

	// 关闭除了标准输入/输出/错误之外的所有文件描述符
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		fdStr := file.Name()
		fd, err := strconv.Atoi(fdStr)
		if err != nil {
			continue
		}

		// 跳过标准输入/输出/错误
		if fd <= 2 {
			continue
		}

		// 获取文件描述符指向的实际文件
		fdPath := filepath.Join(fdDir, fdStr)
		target, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}

		// 检查是否是Docker overlay文件系统
		if strings.Contains(target, "overlay") && strings.Contains(target, "docker") {
			fmt.Printf("关闭文件描述符 %d -> %s\n", fd, target)
			syscall.Close(fd)
		}
	}
}

// cleanupOverlayMounts 尝试卸载overlay挂载点
func cleanupOverlayMounts() {
	// 读取当前挂载点
	cmd := exec.Command("mount")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("无法列出挂载点: %v\n", err)
		return
	}

	// 寻找overlay相关的挂载点
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "overlay") && strings.Contains(line, "docker") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				mountPoint := parts[2]
				fmt.Printf("尝试卸载: %s\n", mountPoint)
				umountCmd := exec.Command("sudo", "umount", mountPoint)
				umountCmd.Run()
			}
		}
	}
}
