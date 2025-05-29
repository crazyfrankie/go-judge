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
	"sync"
	"text/template"
	"time"

	"github.com/crazyfrankie/go-judge/pkg/rpc"
	"github.com/crazyfrankie/go-judge/pkg/types"
)

type GoRunner struct{}

func (g *GoRunner) Run(ctx context.Context, req *rpc.JudgeRequest) (*rpc.JudgeResponse, error) {
	cmd := exec.Command("whoami")
	user, _ := cmd.CombinedOutput()

	// build base dir
	baseDir := fmt.Sprintf("%s/%d/%d", fmt.Sprintf(types.WorkDir, strings.TrimSpace(string(user))), req.GetProblemId(), req.GetUid())

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

	var wg sync.WaitGroup
	results := make([]*rpc.Result, len(req.GetInput()))

	for i, input := range req.GetInput() {
		wg.Add(1)
		go func(index int, testInput string) {
			defer wg.Done()

			testWorkDir := fmt.Sprintf("%s/test_%d", baseDir, index)

			expectedOutput := ""
			if index < len(req.GetOutput()) {
				expectedOutput = req.GetOutput()[index]
			}

			testResult, err := judgeTestCase(ctx, req.GetFullTemplate(), req.GetCode(),
				req.GetTypeDefinition(), testInput, expectedOutput, limit, testWorkDir)

			result := &rpc.Result{
				TimeUsed:       testResult.TimeUsed,
				MemoryUsed:     testResult.MemoryUsed,
				Output:         testResult.Output,
				ExpectedOutput: testResult.ExpectedOutput,

				// formate status info
				StatusRuntime: formatRuntime(testResult.TimeUsed),
				StatusMemory:  formatMemory(testResult.MemoryUsed),
				StatusMsg:     getStatusMessage(testResult.Status),

				RuntimePercentile: calculatePercentile(testResult.TimeUsed, false),
				MemoryPercentile:  calculatePercentile(testResult.MemoryUsed, true), // 错误信息
				ErrorMessage:      testResult.ErrorMessage,
				TestcaseInput:     testInput,
				IsLastTestcase:    index == len(req.GetInput())-1,
				ExecutionId:       fmt.Sprintf("%d_%d_%d", req.GetProblemId(), req.GetUid(), index),
			}

			if testResult.ExecutionResult != nil {
				result.ExitCode = int32(testResult.ExecutionResult.ExitCode)
				if testResult.ExecutionResult.ErrorOutput != "" {
					result.CompileError = testResult.ExecutionResult.ErrorOutput
				}
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

			if err != nil {
				result.Status = rpc.Status_status_runtime_error
				result.Output = fmt.Sprintf("Internal error: %v", err)
			}

			results[index] = result
		}(i, input)
	}

	wg.Wait()

	overall := calculateOverallStatistics(results, req)

	return &rpc.JudgeResponse{
		Results: results,
		Overall: overall,
	}, nil
}

func judgeTestCase(ctx context.Context, fullTemp string, userCode string, typesDef string, input string, expectedOutput string, limit *types.Limit, workdir string) (*types.TestCaseResult, error) {
	result := &types.TestCaseResult{
		ExpectedOutput: expectedOutput,
	}

	// make sure dir is existed
	if err := os.MkdirAll(workdir, 0755); err != nil {
		result.Status = types.StatusRuntimeError
		result.ErrorMessage = fmt.Sprintf("Failed to create workdir: %v", err)
		return result, nil
	}

	// parse code template
	err := parseTemplate(fullTemp, userCode, typesDef, input, workdir)
	if err != nil {
		result.Status = types.StatusCompilationError
		result.ErrorMessage = fmt.Sprintf("Template parse error: %v", err)
		return result, nil
	}

	// generate run shell
	err = buildShell(workdir)
	if err != nil {
		result.Status = types.StatusRuntimeError
		result.ErrorMessage = fmt.Sprintf("Failed to create shell script: %v", err)
		return result, nil
	}

	// run in docker container
	err = runDocker(ctx, limit, workdir)
	if err != nil {
		result.Status = types.StatusRuntimeError
		result.ErrorMessage = fmt.Sprintf("Docker execution error: %v", err)
		return result, nil
	}
	// 解析执行结果
	execResult, err := parseStatsFile(workdir)
	if err != nil {
		result.Status = types.StatusRuntimeError
		result.ErrorMessage = fmt.Sprintf("Failed to parse execution result: %v", err)
		return result, nil
	}
	defer func() {
		os.RemoveAll(workdir)
	}()
	result.ExecutionResult = execResult
	result.TimeUsed = execResult.TimeUsed
	result.MemoryUsed = execResult.MemoryUsed
	result.Output = execResult.Output

	// 判断执行状态
	if execResult.ExitCode != 0 {
		if execResult.ErrorOutput != "" {
			// 检查是否是编译错误
			if strings.Contains(execResult.ErrorOutput, "compile") || strings.Contains(execResult.ErrorOutput, "syntax") {
				result.Status = types.StatusCompilationError
				result.ErrorMessage = execResult.ErrorOutput
			} else {
				result.Status = types.StatusRuntimeError
				result.ErrorMessage = execResult.ErrorOutput
			}
		} else {
			result.Status = types.StatusRuntimeError
			result.ErrorMessage = "Program exited with non-zero code"
		}
		return result, nil
	}

	// 检查时间限制
	if limit != nil && execResult.TimeUsed > int64(limit.TimeLimit) {
		result.Status = types.StatusTimeLimitExceeded
		result.ErrorMessage = fmt.Sprintf("Time limit exceeded: %dms > %dms", execResult.TimeUsed, limit.TimeLimit)
		return result, nil
	}

	// 检查内存限制
	if limit != nil && execResult.MemoryUsed > int64(limit.MemoryLimit*1024*1024) {
		result.Status = types.StatusMemoryLimitExceeded
		result.ErrorMessage = fmt.Sprintf("Memory limit exceeded: %d bytes > %d bytes", execResult.MemoryUsed, limit.MemoryLimit*1024*1024)
		return result, nil
	}

	// 比较输出结果
	compareConfig := &types.CompareConfig{
		IgnoreWhitespace: true,
		IgnoreCase:       false,
		Precision:        -1,
	}

	if compareOutputAdvanced(strings.TrimSpace(execResult.Output), strings.TrimSpace(expectedOutput), compareConfig) {
		result.Status = types.StatusAccepted
	} else {
		result.Status = types.StatusWrongAnswer
		result.ErrorMessage = "Output mismatch"
	}

	return result, nil
}

func compareOutputAdvanced(actual, expected string, config *types.CompareConfig) bool {
	if config == nil {
		config = &types.CompareConfig{
			IgnoreWhitespace: true,
			IgnoreCase:       false,
			Precision:        -1,
		}
	}

	actualProcessed := actual
	expectedProcessed := expected

	// 处理大小写
	if config.IgnoreCase {
		actualProcessed = strings.ToLower(actualProcessed)
		expectedProcessed = strings.ToLower(expectedProcessed)
	}

	// 处理空白字符
	if config.IgnoreWhitespace {
		actualProcessed = strings.Join(strings.Fields(actualProcessed), " ")
		expectedProcessed = strings.Join(strings.Fields(expectedProcessed), " ")
	}

	// 如果设置了浮点数精度，尝试按浮点数比较
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

func calculateOverallStatistics(results []*rpc.Result, req *rpc.JudgeRequest) *rpc.OverallStatistics {
	if len(results) == 0 {
		return &rpc.OverallStatistics{}
	}

	stats := &rpc.OverallStatistics{
		TotalTestcases: uint32(len(results)),
		SubmissionId:   fmt.Sprintf("%d_%d_%d", req.GetProblemId(), req.GetUid(), time.Now().Unix()),
		TaskFinishTime: uint64(time.Now().UnixMilli()),
		Finished:       true,
	}

	var compareResultBuilder strings.Builder
	var totalTime, maxTime, totalMemory, maxMemory int64
	var correctCount uint32
	var finalStatus rpc.Status = rpc.Status_status_accepted

	for _, result := range results {
		// 统计通过情况
		if result.Status == rpc.Status_status_accepted {
			compareResultBuilder.WriteString("1")
			correctCount++
		} else {
			compareResultBuilder.WriteString("0")
			// 更新最终状态（优先级：编译错误 > 运行时错误 > 其他错误）
			if finalStatus == rpc.Status_status_accepted ||
				(result.Status == rpc.Status_status_compilation_error) ||
				(result.Status == rpc.Status_status_runtime_error && finalStatus != rpc.Status_status_compilation_error) {
				finalStatus = result.Status
			}
		}

		// 时间统计
		totalTime += result.TimeUsed
		if result.TimeUsed > maxTime {
			maxTime = result.TimeUsed
		}

		// 内存统计
		totalMemory += result.MemoryUsed
		if result.MemoryUsed > maxMemory {
			maxMemory = result.MemoryUsed
		}
	}

	stats.TotalCorrect = correctCount
	stats.CompareResult = compareResultBuilder.String()
	stats.FinalStatus = finalStatus

	// 时间统计
	stats.TotalTime = totalTime
	stats.MaxTime = maxTime
	if len(results) > 0 {
		stats.AvgTime = totalTime / int64(len(results))
	}

	// 内存统计
	stats.TotalMemory = totalMemory
	stats.MaxMemory = maxMemory
	if len(results) > 0 {
		stats.AvgMemory = totalMemory / int64(len(results))
	}

	// 整体性能百分位（基于最差表现）
	stats.OverallRuntimePercentile = calculatePercentile(maxTime, false)
	stats.OverallMemoryPercentile = calculatePercentile(maxMemory, true)

	return stats
}

func parseTemplate(fullTemp string, userCode string, types string, input string, workdir string) error {
	tpl, _ := template.New("main").Parse(fullTemp)

	tmp, _ := os.CreateTemp(os.TempDir(), "main_*.go")
	defer os.Remove(tmp.Name())

	err := tpl.Execute(tmp, map[string]string{
		"TYPES":     types,
		"USER_CODE": userCode,
		"INPUT":     input,
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
		"INPUT":     input,
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

func buildShell(workdir string) error {
	sh, err := os.OpenFile(fmt.Sprintf("%s/run.sh", workdir), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer sh.Close()
	res := fmt.Sprintf(types.GoShell, "main.go", "main.go")
	if _, err = sh.WriteString(res); err != nil {
		return err
	}

	cmd := exec.Command("chmod", "+x", sh.Name())
	return cmd.Run()
}

func runDocker(ctx context.Context, limit *types.Limit, workdir string) error {
	args := buildDockerArgs(limit)
	defaultArgs := []string{"run", "--rm", "-v", fmt.Sprintf("%s:/app", workdir)}

	args = append(defaultArgs, args...)
	args = append(args, types.GoImage)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func buildDockerArgs(limit *types.Limit) []string {
	args := make([]string, 0, 8)

	// Memory limitations - user program limitations + Go compiler and runtime overheads
	// Go compiler and runtime require an additional 128MB of memory
	memLimit := limit.MemoryLimit + 128
	memStr := fmt.Sprintf("%dm", memLimit)
	args = append(args, "--memory="+memStr)

	// Limit the number of processes - the Go compiler requires a lot of sub-processes, so there's a good limit.
	args = append(args, "--pids-limit=200")

	// CPU time limit (seconds) - user program time + compilation time
	// Give an extra 20 seconds to the Go compilation process
	cpuSeconds := int(math.Ceil(float64(limit.TimeLimit)/1000)) + 20
	args = append(args, "--ulimit", fmt.Sprintf("cpu=%d:%d", cpuSeconds, cpuSeconds))

	// File descriptor limitations - compiling requires opening many files
	args = append(args, "--ulimit", "nofile=2048:2048")

	// Temporary file system, allowing execution and writing
	args = append(args, "--tmpfs", "/tmp:exec,size=300m")

	// Network isolation
	args = append(args, "--network=none")

	// Security Options
	args = append(args, "--security-opt=no-new-privileges")
	args = append(args, "--cap-drop=ALL")

	return args
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

	// Parse memory usage (bytes)
	if maxMem, exists := stats["Maximum resident set size (kbytes)"]; exists {
		if kb, err := strconv.ParseInt(maxMem, 10, 64); err == nil {
			result.MemoryUsed = kb * 1024
		}
	}

	// Read exit code
	exitCodePath := fmt.Sprintf("%s/exitcode.txt", workdir)
	if exitCodeData, err := os.ReadFile(exitCodePath); err == nil {
		if exitCode, err := strconv.Atoi(strings.TrimSpace(string(exitCodeData))); err == nil {
			result.ExitCode = exitCode
		}
	}

	// Read program output
	resultPath := fmt.Sprintf("%s/result.txt", workdir)
	if resultData, err := os.ReadFile(resultPath); err == nil {
		result.Output = strings.TrimSpace(string(resultData))
	}

	// Read error output
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
