package docker

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/crazyfrankie/go-judge/pkg/types"
)

// RunWithContainerControlled runs evaluation using container-controlled mode
func RunWithContainerControlled(ctx context.Context, limit *types.Limit, inputs []string, expectedOutputs []string, workdir string) (*types.ContainerJudgeResult, error) {
	// Create necessary directory structure
	srcDir := fmt.Sprintf("%s/src", workdir)
	testcasesDir := fmt.Sprintf("%s/testcases", workdir)
	outputDir := fmt.Sprintf("%s/output", workdir)

	if err := os.MkdirAll(srcDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create src dir: %v", err)
	}
	if err := os.MkdirAll(testcasesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create testcases dir: %v", err)
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %v", err)
	}

	// Copy source code to src directory
	srcFile := fmt.Sprintf("%s/main.go", workdir)
	destFile := fmt.Sprintf("%s/main.go", srcDir)
	if err := copyFile(srcFile, destFile); err != nil {
		return nil, fmt.Errorf("failed to copy source file: %v", err)
	}

	// Prepare all test case files
	for i, input := range inputs {
		inputFile := fmt.Sprintf("%s/%d.in", testcasesDir, i+1)
		if err := os.WriteFile(inputFile, []byte(input), 0644); err != nil {
			return nil, fmt.Errorf("failed to write input file %d: %v", i+1, err)
		}

		expectedOutput := ""
		if i < len(expectedOutputs) {
			expectedOutput = expectedOutputs[i]
		}
		outputFile := fmt.Sprintf("%s/%d.out", testcasesDir, i+1)
		if err := os.WriteFile(outputFile, []byte(expectedOutput), 0644); err != nil {
			return nil, fmt.Errorf("failed to write output file %d: %v", i+1, err)
		}
	}

	// Generate main judge script
	judgeScriptPath := fmt.Sprintf("%s/main_judge.sh", workdir)
	timeLimit := int(math.Ceil(float64(limit.TimeLimit) / 1000)) // Convert to seconds
	if timeLimit < 1 {
		timeLimit = 1
	}

	judgeScript := fmt.Sprintf(types.GoMainJudgeShell, timeLimit, limit.MemoryLimit, true, false)
	if err := os.WriteFile(judgeScriptPath, []byte(judgeScript), 0755); err != nil {
		return nil, fmt.Errorf("failed to write judge script: %v", err)
	}

	// Start container for evaluation
	containerID, err := startContainerControlledJudge(ctx, workdir, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to start container-controlled judge: %v", err)
	}
	defer func() {
		stopContainer(containerID)
	}()

	// Wait for container to complete
	err = waitForContainerCompletion(ctx, containerID, 5*time.Minute) // Give container up to 5 minutes to execute
	if err != nil {
		return nil, fmt.Errorf("container execution failed: %v", err)
	}

	// Read final results
	resultFile := fmt.Sprintf("%s/final_result.json", outputDir)
	return parseContainerJudgeResult(resultFile)
}

// startContainerControlledJudge starts a container for container-controlled evaluation
func startContainerControlledJudge(ctx context.Context, workdir string, limit *types.Limit) (string, error) {
	args := []string{
		"run", "-d",
		"--name", fmt.Sprintf("judge-container-controlled-%d", time.Now().UnixNano()),

		// Mount directories
		"-v", fmt.Sprintf("%s/src:/src:ro", workdir), // Source code (read-only)
		"-v", fmt.Sprintf("%s/testcases:/testcases:ro", workdir), // Test cases (read-only)
		"-v", fmt.Sprintf("%s/output:/output", workdir), // Output directory (writable)

		// Resource limits
		"--memory", fmt.Sprintf("%dm", limit.MemoryLimit+128), // Extra 128MB for compiler
		"--pids-limit", "200",
		"--ulimit", fmt.Sprintf("cpu=%d:%d", int(math.Ceil(float64(limit.TimeLimit)/1000))+30, int(math.Ceil(float64(limit.TimeLimit)/1000))+30),
		"--ulimit", "nofile=2048:2048",

		// Temporary filesystem
		"--tmpfs", "/run:exec,size=500m", // More space for evaluation working directory
		"--tmpfs", "/tmp:exec,size=300m",

		// Security settings
		"--network", "none",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",

		// Image and command
		types.GoImage,
		"/app/main_judge.sh", // Execute main control script directly
	}

	// First copy the main control script to a location accessible by the container
	containerScriptPath := fmt.Sprintf("%s/main_judge.sh", workdir)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to start container: %v, output: %s", err, output)
	}

	containerID := strings.TrimSpace(string(output))
	fmt.Printf("Started container-controlled judge: %s\n", containerID)

	// Copy the main control script to the container
	copyCmd := exec.Command("docker", "cp", containerScriptPath, fmt.Sprintf("%s:/app/main_judge.sh", containerID))
	if err := copyCmd.Run(); err != nil {
		stopContainer(containerID)
		return "", fmt.Errorf("failed to copy judge script to container: %v", err)
	}

	// Ensure the script is executable
	chmodCmd := exec.Command("docker", "exec", containerID, "chmod", "+x", "/app/main_judge.sh")
	if err := chmodCmd.Run(); err != nil {
		stopContainer(containerID)
		return "", fmt.Errorf("failed to make judge script executable: %v", err)
	}

	// Start the main control script
	execCmd := exec.Command("docker", "exec", "-d", containerID, "/app/main_judge.sh")
	if err := execCmd.Run(); err != nil {
		stopContainer(containerID)
		return "", fmt.Errorf("failed to start judge script: %v", err)
	}

	return containerID, nil
}

// waitForContainerCompletion waits for container execution to complete
func waitForContainerCompletion(ctx context.Context, containerID string, timeout time.Duration) error {
	start := time.Now()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(timeout):
			return fmt.Errorf("container execution timeout after %v", timeout)
		case <-ticker.C:
			// Check container status
			cmd := exec.Command("docker", "inspect", "--format={{.State.Status}}", containerID)
			output, err := cmd.Output()
			if err != nil {
				return fmt.Errorf("failed to inspect container: %v", err)
			}

			status := strings.TrimSpace(string(output))
			if status == "exited" {
				// Check exit code
				cmd = exec.Command("docker", "inspect", "--format={{.State.ExitCode}}", containerID)
				output, err = cmd.Output()
				if err != nil {
					return fmt.Errorf("failed to get container exit code: %v", err)
				}

				exitCode := strings.TrimSpace(string(output))
				if exitCode != "0" {
					// Get container logs for debugging
					logCmd := exec.Command("docker", "logs", containerID)
					logs, _ := logCmd.Output()
					return fmt.Errorf("container exited with code %s, logs: %s", exitCode, string(logs))
				}

				fmt.Printf("Container %s completed successfully in %v\n", containerID, time.Since(start))
				return nil
			}
		}
	}
}

// parseContainerJudgeResult parses container evaluation results
func parseContainerJudgeResult(resultFile string) (*types.ContainerJudgeResult, error) {
	content, err := os.ReadFile(resultFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read result file: %v", err)
	}

	var result types.ContainerJudgeResult
	// Since the JSON generated by bash script might not be standard format, we parse it manually
	lines := strings.Split(string(content), "\n")

	// Simple JSON parsing (for our known structure)
	result.TestResults = make([]types.ContainerTestResult, 0)

	inTestResults := false
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, `"status":`) {
			if status := extractJSONValue(line, "status"); status != "" {
				result.Status = status
			}
		} else if strings.Contains(line, `"total_test_cases":`) {
			if value := extractJSONValue(line, "total_test_cases"); value != "" {
				if val, err := strconv.Atoi(value); err == nil {
					result.TotalTestCases = val
				}
			}
		} else if strings.Contains(line, `"passed_test_cases":`) {
			if value := extractJSONValue(line, "passed_test_cases"); value != "" {
				if val, err := strconv.Atoi(value); err == nil {
					result.PassedTestCases = val
				}
			}
		} else if strings.Contains(line, `"total_time":`) {
			if value := extractJSONValue(line, "total_time"); value != "" {
				if val, err := strconv.ParseInt(value, 10, 64); err == nil {
					result.TotalTime = val
				}
			}
		} else if strings.Contains(line, `"total_memory":`) {
			if value := extractJSONValue(line, "total_memory"); value != "" {
				if val, err := strconv.ParseInt(value, 10, 64); err == nil {
					result.TotalMemory = val
				}
			}
		} else if strings.Contains(line, `"max_memory":`) {
			if value := extractJSONValue(line, "max_memory"); value != "" {
				if val, err := strconv.ParseInt(value, 10, 64); err == nil {
					result.MaxMemory = val
				}
			}
		} else if strings.Contains(line, `"avg_memory":`) {
			if value := extractJSONValue(line, "avg_memory"); value != "" {
				if val, err := strconv.ParseInt(value, 10, 64); err == nil {
					result.AvgMemory = val
				}
			}
		} else if strings.Contains(line, `"test_results":`) {
			inTestResults = true
		} else if inTestResults && strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			// Parse individual test case result
			testResult := parseTestCaseResult(line)
			result.TestResults = append(result.TestResults, testResult)
		}
	}

	return &result, nil
}

// extractJSONValue extracts a value from a JSON line
func extractJSONValue(line, key string) string {
	re := strings.NewReplacer(`"`, "", `,`, "", `}`, "", `:`, " ")
	cleaned := re.Replace(line)

	parts := strings.Fields(cleaned)
	for i, part := range parts {
		if part == key && i+1 < len(parts) {
			return parts[i+1]
		}
	}

	return ""
}

// parseTestCaseResult parses a single test case result
func parseTestCaseResult(line string) types.ContainerTestResult {
	result := types.ContainerTestResult{}

	if testId := extractJSONValue(line, "test_id"); testId != "" {
		result.TestId = testId
	}
	if status := extractJSONValue(line, "status"); status != "" {
		result.Status = status
	}
	if timeUsed := extractJSONValue(line, "time_used"); timeUsed != "" {
		if val, err := strconv.ParseInt(timeUsed, 10, 64); err == nil {
			result.TimeUsed = val
		}
	}
	if memoryUsed := extractJSONValue(line, "memory_used"); memoryUsed != "" {
		if val, err := strconv.ParseInt(memoryUsed, 10, 64); err == nil {
			result.MemoryUsed = val
		}
	}
	if output := extractJSONValue(line, "output"); output != "" {
		result.Output = output
	}
	if expectedOutput := extractJSONValue(line, "expected_output"); expectedOutput != "" {
		result.ExpectedOutput = expectedOutput
	}
	if errorMessage := extractJSONValue(line, "error_message"); errorMessage != "" {
		result.ErrorMessage = errorMessage
	}

	return result
}

// copyFile copies a file
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = destFile.ReadFrom(sourceFile)
	return err
}

// stopContainer stops and cleans up a container
func stopContainer(containerID string) {
	if containerID == "" {
		return
	}

	cmd := exec.Command("docker", "stop", containerID)
	cmd.Run()

	cmd = exec.Command("docker", "rm", containerID)
	cmd.Run()

	fmt.Printf("Stopped and removed container: %s\n", containerID)
}
