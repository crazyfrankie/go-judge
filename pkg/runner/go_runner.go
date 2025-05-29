package runner

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/crazyfrankie/go-judge/pkg/rpc"
	"github.com/crazyfrankie/go-judge/pkg/types"
)

type GoRunner struct{}

func (g *GoRunner) Run(ctx context.Context, req *rpc.JudgeRequest) (*rpc.JudgeResponse, error) {
	cmd := exec.Command("whoami")
	user, _ := cmd.CombinedOutput()

	// build work dir
	workdir := fmt.Sprintf("%s/%d/%d", fmt.Sprintf(types.WorkDir, strings.TrimSpace(string(user))), req.GetProblemId(), req.GetUid())

	if err := os.MkdirAll(workdir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workdir: %v", err)
	}
	defer os.RemoveAll(workdir)

	limit := &types.Limit{}
	if req.GetMaxTime() != "" {
		if timeLimit, err := strconv.Atoi(req.GetMaxTime()); err == nil {
			limit.TimeLimit = timeLimit
		}
	}
	if req.GetMaxMem() != "" {
		if memLimit, err := strconv.Atoi(req.GetMaxMem()); err == nil {
			limit.MemoryLimit = memLimit
		}
	}

	// parse code template
	err := parseTemplate(req.GetFullTemplate(), req.GetCode(), req.GetTypeDefinition(), workdir)
	if err != nil {
		return nil, fmt.Errorf("template parse error: %v", err)
	}

	// precompile
	compileRes, err := preCompile(workdir)
	if err != nil || (compileRes != nil && compileRes.Status == types.StatusCompilationError) {
		// 编译错误，直接返回
		result := &rpc.Result{
			Status:       rpc.Status_status_compilation_error,
			ErrorMessage: compileRes.ErrorMessage,
			StatusMsg:    "Compilation Error",
		}

		return &rpc.JudgeResponse{
			Result: result,
			Overall: &rpc.OverallStatistics{
				TotalTestcases: uint32(len(req.GetInput())),
				TotalCorrect:   0,
				FinalStatus:    rpc.Status_status_compilation_error,
				Finished:       true,
			},
		}, nil
	}

	// create watch shell
	err = buildShellForWatch(workdir)
	if err != nil {
		return nil, err
	}

	containerID, err := startLongRunningContainer(ctx, workdir, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %v", err)
	}
	defer func() {
		stopContainer(containerID)
	}()

	var bestTimeResult *rpc.Result
	var bestMemoryResult *rpc.Result
	var totalTime int64
	var totalMemory int64
	var maxMemory int64

	for i, input := range req.GetInput() {
		expectedOutput := ""
		if i < len(req.GetOutput()) {
			expectedOutput = req.GetOutput()[i]
		}

		testResult, err := g.judgeOneTest(limit, input, expectedOutput, workdir)
		if err != nil {
			testResult = &types.TestCaseResult{
				Status:       types.StatusRuntimeError,
				ErrorMessage: fmt.Sprintf("Test execution error: %v", err),
			}
		}

		result := &rpc.Result{
			TimeUsed:          testResult.TimeUsed,
			MemoryUsed:        testResult.MemoryUsed,
			Output:            testResult.Output,
			ExpectedOutput:    testResult.ExpectedOutput,
			StatusRuntime:     formatRuntime(testResult.TimeUsed),
			StatusMemory:      formatMemory(testResult.MemoryUsed),
			StatusMsg:         getStatusMessage(testResult.Status),
			RuntimePercentile: calculatePercentile(testResult.TimeUsed, false),
			MemoryPercentile:  calculatePercentile(testResult.MemoryUsed, true),
			ErrorMessage:      testResult.ErrorMessage,
			TestcaseInput:     input,
		}

		switch testResult.Status {
		case types.StatusAccepted:
			result.Status = rpc.Status_status_accepted
		case types.StatusWrongAnswer:
			result.Status = rpc.Status_status_wrong_answer
		case types.StatusTimeLimitExceeded:
			result.Status = rpc.Status_status_time_limit_exceeded
		case types.StatusMemoryLimitExceeded:
			result.Status = rpc.Status_status_memory_limit_exceeded
		case types.StatusRuntimeError:
			result.Status = rpc.Status_status_runtime_error
		case types.StatusCompilationError:
			result.Status = rpc.Status_status_compilation_error
		default:
			result.Status = rpc.Status_status_runtime_error
		}

		if result.Status != rpc.Status_status_accepted {
			result.FailedTestcaseIndex = int32(i)
			return &rpc.JudgeResponse{
				Result: result,
				Overall: &rpc.OverallStatistics{
					TotalTestcases: uint32(len(req.GetInput())),
					TotalCorrect:   uint32(i),
					CompareResult:  strings.Repeat("1", i) + "X",
					FinalStatus:    result.Status,
					TaskFinishTime: uint64(time.Now().UnixMilli()),
					Finished:       true,
				},
			}, nil
		}

		totalTime += testResult.TimeUsed
		totalMemory += testResult.MemoryUsed
		if testResult.MemoryUsed > maxMemory {
			maxMemory = testResult.MemoryUsed
		}

		if bestTimeResult == nil || testResult.TimeUsed < bestTimeResult.TimeUsed {
			bestTimeResult = result
		}
		if bestMemoryResult == nil || testResult.MemoryUsed < bestMemoryResult.MemoryUsed {
			bestMemoryResult = result
		}
	}

	bestResult := bestTimeResult
	if bestMemoryResult != nil && bestMemoryResult.MemoryUsed < bestResult.MemoryUsed {
		bestResult = bestMemoryResult
	}

	overall := &rpc.OverallStatistics{
		TotalTestcases:           uint32(len(req.GetInput())),
		TotalCorrect:             uint32(len(req.GetInput())),
		CompareResult:            strings.Repeat("1", len(req.GetInput())),
		TotalTime:                totalTime,
		MaxMemory:                maxMemory,
		AvgMemory:                totalMemory / int64(len(req.GetInput())),
		FinalStatus:              rpc.Status_status_accepted,
		TaskFinishTime:           uint64(time.Now().UnixMilli()),
		Finished:                 true,
		OverallRuntimePercentile: bestResult.RuntimePercentile,
		OverallMemoryPercentile:  bestResult.MemoryPercentile,
	}

	return &rpc.JudgeResponse{
		Result:  bestResult,
		Overall: overall,
	}, nil
}

func (g *GoRunner) judgeOneTest(limit *types.Limit, input string, expectedOutput string, workdir string) (*types.TestCaseResult, error) {
	result := &types.TestCaseResult{
		ExpectedOutput: expectedOutput,
	}

	err := buildShellRunExec(workdir, input)
	if err != nil {
		result.Status = types.StatusRuntimeError
		result.ErrorMessage = fmt.Sprintf("Failed to create shell script: %v", err)
		return result, nil
	}

	execResult, err := waitForContainerExecution(workdir, 30*time.Second)
	if err != nil {
		result.Status = types.StatusRuntimeError
		result.ErrorMessage = fmt.Sprintf("Container execution failed: %v", err)
		return result, nil
	}

	result.ExecutionResult = execResult
	result.TimeUsed = execResult.TimeUsed
	result.MemoryUsed = execResult.MemoryUsed
	result.Output = execResult.Output

	if execResult.ExitCode != 0 {
		if execResult.ErrorOutput != "" {
			result.Status = types.StatusRuntimeError
			result.ErrorMessage = execResult.ErrorOutput
		} else {
			result.Status = types.StatusRuntimeError
			result.ErrorMessage = "Program exited with non-zero code"
		}
		return result, nil
	}

	if limit != nil && execResult.TimeUsed > int64(limit.TimeLimit) {
		result.Status = types.StatusTimeLimitExceeded
		result.ErrorMessage = fmt.Sprintf("Time limit exceeded: %dms > %dms", execResult.TimeUsed, limit.TimeLimit)
		return result, nil
	}

	if limit != nil && execResult.MemoryUsed > int64(limit.MemoryLimit*1024*1024) {
		result.Status = types.StatusMemoryLimitExceeded
		result.ErrorMessage = fmt.Sprintf("Memory limit exceeded: %d bytes > %d bytes", execResult.MemoryUsed, limit.MemoryLimit*1024*1024)
		return result, nil
	}

	compareConfig := &types.CompareConfig{
		IgnoreWhitespace: true,
		IgnoreCase:       false,
		Precision:        -1,
	}

	if compareOutput(result.Output, expectedOutput, compareConfig) {
		result.Status = types.StatusAccepted
	} else {
		result.Status = types.StatusWrongAnswer
		result.ErrorMessage = "Output mismatch"
	}

	return result, nil
}

func parseTemplate(fullTemp string, userCode string, types string, workdir string) error {
	tpl, _ := template.New("main").Parse(fullTemp)

	tmp, _ := os.CreateTemp(os.TempDir(), "main_*.go")
	defer os.Remove(tmp.Name())

	err := tpl.Execute(tmp, map[string]string{
		"TYPES":     types,
		"USER_CODE": userCode,
		"IMPORTS":   "",
	})
	if err != nil {
		return err
	}

	content, _ := os.ReadFile(tmp.Name())
	imports := detectImports(string(content))

	var final string
	if len(imports) != 0 {
		final = "\n\nimport (\n" + strings.Join(imports, "\n") + "\n)\n"
	}

	newTpl, _ := template.New("main").Parse(fullTemp)
	codeFile, _ := os.OpenFile(fmt.Sprintf("%s/main.go", workdir), os.O_CREATE|os.O_RDWR, 0644)
	err = newTpl.Execute(codeFile, map[string]string{
		"USER_CODE": userCode,
		"TYPES":     types,
		"IMPORTS":   final,
	})
	defer codeFile.Close()
	if err != nil {
		return err
	}

	return nil
}

func detectImports(code string) []string {
	set := make(map[string]bool)
	fset := token.NewFileSet()
	f, _ := parser.ParseFile(fset, "", code, parser.AllErrors)
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				set[ident.Name] = true
			}
		}
		return true
	})
	allowed := map[string]string{
		"fmt":     `"fmt"`,
		"sort":    `"sort"`,
		"math":    `"math"`,
		"strings": `"strings"`,
		"strconv": `"strconv"`,
		"heap":    `"container/heap"`,
		"json":    `"encoding/json"`,
	}
	var imports []string
	for name := range set {
		if imp, ok := allowed[name]; ok {
			imports = append(imports, imp)
		}
	}
	return imports
}

func preCompile(workdir string) (*types.PreCompileResult, error) {
	result := &types.PreCompileResult{}

	shFile := fmt.Sprintf("%s/%s", workdir, "build.sh")
	sh, err := os.OpenFile(shFile, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	defer sh.Close()
	if _, err = sh.WriteString(fmt.Sprintf(types.GoBuildShell, workdir)); err != nil {
		return nil, err
	}
	cmd := exec.Command("chmod", "+x", sh.Name())
	cmd.Run()

	cmd = exec.Command("sh", shFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		result.Status = types.StatusCompilationError
		result.ErrorMessage = string(out)
		return result, nil
	}

	return nil, nil
}

func buildShellForWatch(workdir string) error {
	var sh = `#!/bin/sh
while inotifywait -e create,modify /app; do
    [ -f ./run.sh ] && ./run.sh && rm -f ./run.sh
done`

	runFile := fmt.Sprintf("%s/entrypoint.sh", workdir)
	err := os.WriteFile(runFile, []byte(sh), 0755)
	if err != nil {
		return fmt.Errorf("failed to write run.sh: %v", err)
	}

	cmd := exec.Command("chmod", "+x", runFile)
	err = cmd.Run()

	return err
}

func startLongRunningContainer(ctx context.Context, workdir string, limit *types.Limit) (string, error) {
	args := buildDockerArgs(limit)
	defaultArgs := []string{
		"run", "-d",
		"-v", fmt.Sprintf("%s:/app", workdir),
		"--name", fmt.Sprintf("judge-container-%d", time.Now().UnixNano()),
	}

	args = append(defaultArgs, args...)
	args = append(args, types.GoImage)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to start container: %v", err)
	}

	containerID := strings.TrimSpace(string(output))
	fmt.Printf("Started judge container: %s\n", containerID)

	return containerID, nil
}

func buildShellRunExec(workdir string, input string) error {
	runFile := fmt.Sprintf("%s/run.sh", workdir)
	err := os.WriteFile(runFile, []byte(fmt.Sprintf(types.GoRunShell, input)), 0755)
	if err != nil {
		return fmt.Errorf("failed to write run.sh: %v", err)
	}

	return nil
}

// waitForContainerExecution Waiting for container execution to complete (by listening for file system changes)
func waitForContainerExecution(workdir string, timeout time.Duration) (*types.ExecutionResult, error) {
	runFile := fmt.Sprintf("%s/run.sh", workdir)
	resultFile := fmt.Sprintf("%s/result.txt", workdir)

	start := time.Now()

	// Wait for the run.sh file to be deleted by the container (indicating completion of execution)
	for time.Since(start) < timeout {
		// Check if run.sh still exists.
		if _, err := os.Stat(runFile); os.IsNotExist(err) {
			// run.sh has been deleted, check if the result file was generated
			if _, err := os.Stat(resultFile); err == nil {
				// Result file exists, parse results
				return parseStatsFile(workdir)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	return nil, fmt.Errorf("container execution timeout after %v", timeout)
}

// buildDockerArgs Building Docker startup parameters
func buildDockerArgs(limit *types.Limit) []string {
	args := make([]string, 0, 8)

	// 内存限制 - 用户程序限制 + Go编译器和运行时开销
	// Go编译器和运行时需要额外的128MB内存
	memLimit := limit.MemoryLimit + 128
	memStr := fmt.Sprintf("%dm", memLimit)
	args = append(args, "--memory="+memStr)

	// 限制进程数量 - Go编译器需要很多子进程，所以给一个合理的限制
	args = append(args, "--pids-limit=200")

	// CPU时间限制（秒） - 用户程序时间 + 编译时间
	// 给Go编译过程额外20秒时间
	cpuSeconds := int(math.Ceil(float64(limit.TimeLimit)/1000)) + 20
	args = append(args, "--ulimit", fmt.Sprintf("cpu=%d:%d", cpuSeconds, cpuSeconds))

	// 文件描述符限制 - 编译需要打开很多文件
	args = append(args, "--ulimit", "nofile=2048:2048")

	// 临时文件系统，允许执行和写入
	args = append(args, "--tmpfs", "/tmp:exec,size=300m")

	// 网络隔离
	args = append(args, "--network=none")

	// 安全选项
	args = append(args, "--security-opt=no-new-privileges")
	args = append(args, "--cap-drop=ALL")

	return args
}

func compareOutput(actual, expected string, config *types.CompareConfig) bool {
	if config == nil {
		config = &types.CompareConfig{
			IgnoreWhitespace: true,
			IgnoreCase:       false,
			Precision:        -1,
		}
	}

	actualProcessed := actual
	expectedProcessed := expected
	if config.IgnoreCase {
		actualProcessed = strings.ToLower(actualProcessed)
		expectedProcessed = strings.ToLower(expectedProcessed)
	}
	if config.IgnoreWhitespace {
		actualProcessed = strings.Join(strings.Fields(actualProcessed), " ")
		expectedProcessed = strings.Join(strings.Fields(expectedProcessed), " ")
	}
	if config.Precision >= 0 {
		return compareFloatOutput(actualProcessed, expectedProcessed, config.Precision)
	}

	return actualProcessed == expectedProcessed
}

func compareFloatOutput(actual, expected string, precision int) bool {
	actualNums := extractNumbers(actual)
	expectedNums := extractNumbers(expected)

	if len(actualNums) != len(expectedNums) {
		return false
	}

	tolerance := math.Pow(10, -float64(precision))

	for i, actualNum := range actualNums {
		expectedNum := expectedNums[i]
		if math.Abs(actualNum-expectedNum) > tolerance {
			return false
		}
	}

	return true
}

func extractNumbers(s string) []float64 {
	var numbers []float64
	words := strings.Fields(s)

	for _, word := range words {
		if num, err := strconv.ParseFloat(word, 64); err == nil {
			numbers = append(numbers, num)
		}
	}

	return numbers
}

func parseStatsFile(workdir string) (*types.ExecutionResult, error) {
	result := &types.ExecutionResult{}

	statsPath := fmt.Sprintf("%s/stats.txt", workdir)
	content, err := os.ReadFile(statsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read stats file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	stats := make(map[string]string)

	for _, line := range lines {
		if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			stats[key] = val
		}
	}

	if elapsedTime, exists := stats["Elapsed (wall clock) time (h:mm:ss or m:ss)"]; exists {
		if seconds := parseElapsedTime(elapsedTime); seconds > 0 {
			result.TimeUsed = int64(seconds * 1000)
		}
	} else if userTime, exists := stats["User time (seconds)"]; exists {
		if seconds, err := strconv.ParseFloat(userTime, 64); err == nil {
			result.TimeUsed = int64(seconds * 1000)
		}
	}

	if maxMem, exists := stats["Maximum resident set size (kbytes)"]; exists {
		if kb, err := strconv.ParseInt(maxMem, 10, 64); err == nil {
			result.MemoryUsed = kb * 1024 // 转换为字节
		}
	}

	exitCodePath := fmt.Sprintf("%s/exitcode.txt", workdir)
	if exitCodeData, err := os.ReadFile(exitCodePath); err == nil {
		if exitCode, err := strconv.Atoi(strings.TrimSpace(string(exitCodeData))); err == nil {
			result.ExitCode = exitCode
		}
	}

	resultPath := fmt.Sprintf("%s/result.txt", workdir)
	if resultData, err := os.ReadFile(resultPath); err == nil {
		result.Output = strings.TrimSpace(string(resultData))
	}

	errorPath := fmt.Sprintf("%s/error.txt", workdir)
	if errorData, err := os.ReadFile(errorPath); err == nil {
		result.ErrorOutput = strings.TrimSpace(string(errorData))
	}

	return result, nil
}

func formatRuntime(timeMs int64) string {
	if timeMs < 1000 {
		return fmt.Sprintf("%d ms", timeMs)
	}
	return fmt.Sprintf("%.2f s", float64(timeMs)/1000.0)
}

func formatMemory(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	if bytes < KB {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < MB {
		return fmt.Sprintf("%.1f KB", float64(bytes)/KB)
	} else if bytes < GB {
		return fmt.Sprintf("%.1f MB", float64(bytes)/MB)
	}
	return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
}

func getStatusMessage(status types.Status) string {
	switch status {
	case types.StatusAccepted:
		return "Accepted"
	case types.StatusWrongAnswer:
		return "Wrong Answer"
	case types.StatusTimeLimitExceeded:
		return "Time Limit Exceeded"
	case types.StatusMemoryLimitExceeded:
		return "Memory Limit Exceeded"
	case types.StatusRuntimeError:
		return "Runtime Error"
	case types.StatusCompilationError:
		return "Compilation Error"
	default:
		return "Unknown"
	}
}

func calculatePercentile(value int64, isMemory bool) uint32 {
	// 简化的百分位计算，实际应该基于历史数据
	// 可以后续接入数据库来计算真实的百分位
	if isMemory {
		// 基于内存使用的简单百分位估算
		if value < 1024*1024 { // < 1MB
			return 95
		} else if value < 10*1024*1024 { // < 10MB
			return 80
		} else if value < 50*1024*1024 { // < 50MB
			return 50
		}
		return 20
	} else {
		// 基于执行时间的简单百分位估算
		if value < 100 { // < 100ms
			return 95
		} else if value < 500 { // < 500ms
			return 80
		} else if value < 1000 { // < 1s
			return 50
		}
		return 20
	}
}

// parseElapsedTime Parse elapsed time as "0m 2.57s" or "1:23:45".
func parseElapsedTime(timeStr string) float64 {
	timeStr = strings.TrimSpace(timeStr)

	if strings.Contains(timeStr, "m") && strings.Contains(timeStr, "s") {
		parts := strings.Fields(timeStr)
		var totalSeconds float64

		for _, part := range parts {
			if strings.HasSuffix(part, "m") {
				if minutes, err := strconv.ParseFloat(strings.TrimSuffix(part, "m"), 64); err == nil {
					totalSeconds += minutes * 60
				}
			} else if strings.HasSuffix(part, "s") {
				if seconds, err := strconv.ParseFloat(strings.TrimSuffix(part, "s"), 64); err == nil {
					totalSeconds += seconds
				}
			}
		}
		return totalSeconds
	}

	// Processing the "1:23:45" format
	if strings.Contains(timeStr, ":") {
		parts := strings.Split(timeStr, ":")
		var totalSeconds float64

		switch len(parts) {
		case 2: // mm:ss
			if minutes, err := strconv.ParseFloat(parts[0], 64); err == nil {
				totalSeconds += minutes * 60
			}
			if seconds, err := strconv.ParseFloat(parts[1], 64); err == nil {
				totalSeconds += seconds
			}
		case 3: // hh:mm:ss
			if hours, err := strconv.ParseFloat(parts[0], 64); err == nil {
				totalSeconds += hours * 3600
			}
			if minutes, err := strconv.ParseFloat(parts[1], 64); err == nil {
				totalSeconds += minutes * 60
			}
			if seconds, err := strconv.ParseFloat(parts[2], 64); err == nil {
				totalSeconds += seconds
			}
		}
		return totalSeconds
	}

	// Direct parse seconds
	if seconds, err := strconv.ParseFloat(timeStr, 64); err == nil {
		return seconds
	}

	return 0
}

// stopContainer stop and clean container
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
