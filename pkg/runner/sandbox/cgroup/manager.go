package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// CgroupRoot default cgroup2
	CgroupRoot = "/sys/fs/cgroup"
)

// CgroupManager cgroup manager
type CgroupManager struct {
	Path     string
	Resource *ResourceConfig
}

// ResourceConfig resource configuration
type ResourceConfig struct {
	MemoryLimit string // in bytes
	CpuQuota    string // CPU quota (microseconds per period)
	CpuPeriod   string // CPU period (microseconds, default 100000)
	CpuShare    string // in shares (relative weight)
	CpuSet      string // cpus the container can use, e.g., "0-1,3"
}

// NewCgroupManager creates a new CgroupManager instance
func NewCgroupManager(path string) *CgroupManager {
	return &CgroupManager{
		Path: path,
	}
}

// Apply adds a process to the cgroup
func (c *CgroupManager) Apply(pid int) error {
	if err := c.createCgroupIfNotExists(); err != nil {
		return err
	}
	// Write process ID to cgroup.procs
	cgroupProcsPath := filepath.Join(c.getAbsolutePath(), "cgroup.procs")
	return os.WriteFile(cgroupProcsPath, []byte(strconv.Itoa(pid)), 0700)
}

// Set sets resource limits
func (c *CgroupManager) Set(res *ResourceConfig) error {
	c.Resource = res
	if err := c.createCgroupIfNotExists(); err != nil {
		return err
	}

	cgroupPath := c.getAbsolutePath()

	// Set memory limit
	if res.MemoryLimit != "" {
		memoryLimitPath := filepath.Join(cgroupPath, "memory.max")
		if err := os.WriteFile(memoryLimitPath, []byte(res.MemoryLimit), 0700); err != nil {
			return fmt.Errorf("failed to set memory limit: %v", err)
		}
	}

	// Set CPU shares (weight)
	if res.CpuShare != "" {
		shares, err := strconv.Atoi(res.CpuShare)
		if err != nil {
			return fmt.Errorf("invalid cpu share value: %v", err)
		}

		// Convert from shares to weight (approximate conversion)
		weight := shares * 10
		if weight < 1 {
			weight = 1
		} else if weight > 10000 {
			weight = 10000
		}

		cpuWeightPath := filepath.Join(cgroupPath, "cpu.weight")
		if err := os.WriteFile(cpuWeightPath, []byte(strconv.Itoa(weight)), 0700); err != nil {
			return fmt.Errorf("failed to set cpu weight: %v", err)
		}
	}

	// Set CPU set
	if res.CpuSet != "" {
		cpuSetPath := filepath.Join(cgroupPath, "cpuset.cpus")
		if err := os.WriteFile(cpuSetPath, []byte(res.CpuSet), 0700); err != nil {
			return fmt.Errorf("failed to set cpuset: %v", err)
		}
	}

	// Set CPU quota and period
	if res.CpuQuota != "" && res.CpuPeriod != "" {
		cpuMaxPath := filepath.Join(cgroupPath, "cpu.max")
		cpuMaxValue := fmt.Sprintf("%s %s", res.CpuQuota, res.CpuPeriod)
		if err := os.WriteFile(cpuMaxPath, []byte(cpuMaxValue), 0700); err != nil {
			return fmt.Errorf("failed to set cpu quota and period: %v", err)
		}
	}

	return nil
}

// Destroy destroys the cgroup
func (c *CgroupManager) Destroy() error {
	cgroupPath := c.getAbsolutePath()

	// First, move all processes to parent cgroup
	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	procs, err := os.ReadFile(procsPath)
	if err == nil && len(procs) > 0 {
		// Get parent cgroup path
		parentPath := filepath.Dir(cgroupPath)
		parentProcsPath := filepath.Join(parentPath, "cgroup.procs")

		// Move each process to parent
		for _, pidStr := range strings.Split(string(procs), "\n") {
			if pidStr == "" {
				continue
			}
			if err := os.WriteFile(parentProcsPath, []byte(pidStr), 0700); err != nil {
				fmt.Printf("Warning: Failed to move process %s to parent cgroup: %v\n", pidStr, err)
			}
		}
	}

	// Remove the cgroup directory
	if err := os.RemoveAll(cgroupPath); err != nil {
		return fmt.Errorf("failed to remove cgroup: %v", err)
	}

	return nil
}

// createCgroupIfNotExists creates the cgroup directory if it doesn't exist
func (c *CgroupManager) createCgroupIfNotExists() error {
	cgroupPath := c.getAbsolutePath()
	if _, err := os.Stat(cgroupPath); os.IsNotExist(err) {
		if err := os.MkdirAll(cgroupPath, 0755); err != nil {
			return fmt.Errorf("failed to create cgroup directory: %v", err)
		}

		// Enable controllers in parent directory
		parentPath := filepath.Dir(cgroupPath)
		if parentPath != CgroupRoot {
			controllers := []string{"cpu", "cpuset", "memory"}
			for _, ctrl := range controllers {
				subtreeControlPath := filepath.Join(parentPath, "cgroup.subtree_control")
				if err := c.enableController(subtreeControlPath, ctrl); err != nil {
					fmt.Printf("Warning: Failed to enable %s controller: %v\n", ctrl, err)
				}
			}
		}
	}

	return nil
}

// enableController enables a controller
func (c *CgroupManager) enableController(subtreeControlPath string, controller string) error {
	content, err := os.ReadFile(subtreeControlPath)
	if err != nil {
		return err
	}

	// Check if controller is already enabled
	if strings.Contains(string(content), controller) {
		return nil
	}

	// Enable controller by writing "+controller"
	return os.WriteFile(subtreeControlPath, []byte(fmt.Sprintf("+%s", controller)), 0700)
}

// getAbsolutePath gets the absolute path
func (c *CgroupManager) getAbsolutePath() string {
	return filepath.Join(CgroupRoot, c.Path)
}

// GetMemoryUsage gets memory usage
func (c *CgroupManager) GetMemoryUsage() (int64, error) {
	cgroupPath := c.getAbsolutePath()

	// Try to read memory.current (cgroup v2)
	currentPath := filepath.Join(cgroupPath, "memory.current")
	if content, err := os.ReadFile(currentPath); err == nil {
		if usage, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64); err == nil {
			return usage, nil
		}
	}

	// Try to read memory.peak (cgroup v2 peak)
	peakPath := filepath.Join(cgroupPath, "memory.peak")
	if content, err := os.ReadFile(peakPath); err == nil {
		if usage, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64); err == nil {
			return usage, nil
		}
	}

	return 0, fmt.Errorf("failed to read memory usage")
}
