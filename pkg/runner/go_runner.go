package runner

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"html/template"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crazyfrankie/go-judge/pkg/rpc"
	"github.com/crazyfrankie/go-judge/pkg/types"
)

type GoRunner struct {
	rpc.UnimplementedRunnerServiceServer
}

func (g *GoRunner) Run(ctx context.Context, req *rpc.JudgeRequest) (*rpc.JudgeResponse, error) {
	cmd := exec.Command("whoami")
	user, _ := cmd.CombinedOutput()

	// 构建基础工作目录
	baseDir := fmt.Sprintf("%s/%d/%d", fmt.Sprintf(types.WorkDir, strings.TrimSpace(string(user))), req.GetProblemId(), req.GetUid())

	// 解析限制条件
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

	// 并行处理所有测试用例
	var wg sync.WaitGroup
	results := make([]*rpc.Result, len(req.GetInput()))

	for i, input := range req.GetInput() {
		wg.Add(1)
		go func() {
			defer wg.Done()

			testWorkDir := fmt.Sprintf("%s/test_%d", baseDir, i)

			expectedOutput := ""
			if i < len(req.GetOutput()) {
				expectedOutput = req.GetOutput()[i]
			}

			// 执行测试用例
			testResult, err := judgeTestCase(ctx, req.GetFullTemplate(), req.GetCode(),
				req.GetTypeDefinition(), input, expectedOutput, limit, testWorkDir)

			result := &rpc.Result{
				TimeUsed:       testResult.TimeUsed,
				MemoryUsed:     testResult.MemoryUsed,
				Output:         testResult.Output,
				ExpectedOutput: testResult.ExpectedOutput,

				// 格式化显示信息
				StatusRuntime: formatRuntime(testResult.TimeUsed),
				StatusMemory:  formatMemory(testResult.MemoryUsed),
				StatusMsg:     getStatusMessage(testResult.Status),

				// 性能百分位
				RuntimePercentile: calculatePercentile(testResult.TimeUsed, false),
				MemoryPercentile:  calculatePercentile(testResult.MemoryUsed, true),

				// 错误信息
				ErrorMessage:   testResult.ErrorMessage,
				TestcaseInput:  input,
				IsLastTestcase: i == len(req.GetInput())-1,
				ExecutionId:    fmt.Sprintf("%d_%d_%d", req.GetProblemId(), req.GetUid(), i),
			}

			// 如果有执行结果详情，添加退出码
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

			results[i] = result
		}()
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

	// 确保工作目录存在
	if err := os.MkdirAll(workdir, 0755); err != nil {
		result.Status = types.StatusRuntimeError
		result.ErrorMessage = fmt.Sprintf("Failed to create workdir: %v", err)
		return result, nil
	}

	// 生成代码文件
	codeFile, err := parseTemplate(fullTemp, userCode, typesDef, input)
	if err != nil {
		result.Status = types.StatusCompilationError
		result.ErrorMessage = fmt.Sprintf("Template parse error: %v", err)
		return result, nil
	}
	defer os.Remove(codeFile)

	// 复制代码文件到工作目录
	mainGoPath := fmt.Sprintf("%s/main.go", workdir)
	if err := copyFile(codeFile, mainGoPath); err != nil {
		result.Status = types.StatusRuntimeError
		result.ErrorMessage = fmt.Sprintf("Failed to copy code file: %v", err)
		return result, nil
	}

	// 生成运行脚本
	shFile, err := buildShell(workdir, "main.go")
	if err != nil {
		result.Status = types.StatusRuntimeError
		result.ErrorMessage = fmt.Sprintf("Failed to create shell script: %v", err)
		return result, nil
	}
	defer os.Remove(shFile)

	// 在 Docker 容器中运行
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

func parseTemplate(fullTemp string, userCode string, types string, input string) (string, error) {
	tpl, _ := template.New("main").Funcs(template.FuncMap{
		"safe": func(s string) template.HTML { return template.HTML(s) },
	}).Parse(fullTemp)

	tmp, _ := os.CreateTemp(os.TempDir(), "main_*.go")
	defer os.Remove(tmp.Name())

	err := tpl.Execute(tmp, map[string]string{
		"TYPES":     types,
		"USER_CODE": userCode,
		"TEST_CODE": input,
		"IMPORTS":   "",
	})
	if err != nil {
		return "", err
	}

	content, _ := os.ReadFile(tmp.Name())
	imports := detectImports(string(content))

	var final string
	if len(imports) != 0 {
		final = "\n\nimport (\n" + strings.Join(imports, "\n") + "\n)\n"
	}

	newTpl, _ := template.New("main").Funcs(template.FuncMap{
		"safe": func(s string) template.HTML { return template.HTML(s) },
	}).Parse(fullTemp)
	codeFile, _ := os.CreateTemp(os.TempDir(), "main_*.go")
	err = newTpl.Execute(codeFile, map[string]string{
		"USER_CODE": userCode,
		"TEST_CODE": input,
		"TYPES":     types,
		"IMPORTS":   final,
	})
	if err != nil {
		return "", err
	}

	return codeFile.Name(), nil
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

func buildShell(workdir, path string) (string, error) {
	sh, err := os.OpenFile(fmt.Sprintf("%s/run.sh", workdir), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return "", err
	}
	res := fmt.Sprintf(types.GoShell, path, path)
	_, err = sh.WriteString(res)

	return sh.Name(), err
}

func runDocker(ctx context.Context, limit *types.Limit, workdir string) error {
	args := buildDockerArgs(limit)
	defaultArgs := []string{"run", "--rm", "-v", fmt.Sprintf("%s:/app", workdir)}

	args = append(args, defaultArgs...)
	args = append(args, types.GoImage)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func buildDockerArgs(limit *types.Limit) []string {
	args := make([]string, 0, 5)

	//  MB -> m
	memStr := fmt.Sprintf("%dm", limit.MemoryLimit)
	args = append(args, "--memory="+memStr)

	// address space limit (byte)
	asLimit := limit.MemoryLimit * 1024 * 1024
	args = append(args, "--ulimit", fmt.Sprintf("as=%d", asLimit))

	args = append(args, "--pids-limit=1")

	// cpu time limit (s)
	cpuSeconds := int(math.Ceil(float64(limit.TimeLimit) / 1000))
	args = append(args, "--ulimit", fmt.Sprintf("cpu=%d", cpuSeconds))

	// Estimated number of CPU cores available (rough), e.g. 1 sec / 2 sec = 0.5 cores
	// optional： Trying to get tighter control of the CPU
	//if cpuSeconds > 0 {
	//	cpuQuota := cpuSeconds * 100000 // 100ms = 100000 us
	//	args = append(args, "--cpu-period=100000", fmt.Sprintf("--cpu-quota=%d", cpuQuota))
	//	args = append(args, fmt.Sprintf("--cpus=%.2f", float64(limit.TimeLimit)/2000.0))
	//}

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

	// 解析时间使用（毫秒）
	if userTime, exists := stats["User time (seconds)"]; exists {
		if seconds, err := strconv.ParseFloat(userTime, 64); err == nil {
			result.TimeUsed = int64(seconds * 1000) // 转换为毫秒
		}
	}

	// 解析内存使用（字节）
	if maxMem, exists := stats["Maximum resident set size (kbytes)"]; exists {
		if kb, err := strconv.ParseInt(maxMem, 10, 64); err == nil {
			result.MemoryUsed = kb * 1024 // 转换为字节
		}
	}

	// 读取退出码
	exitCodePath := fmt.Sprintf("%s/exitcode.txt", workdir)
	if exitCodeData, err := os.ReadFile(exitCodePath); err == nil {
		if exitCode, err := strconv.Atoi(strings.TrimSpace(string(exitCodeData))); err == nil {
			result.ExitCode = exitCode
		}
	}

	// 读取程序输出
	resultPath := fmt.Sprintf("%s/result.txt", workdir)
	if resultData, err := os.ReadFile(resultPath); err == nil {
		result.Output = strings.TrimSpace(string(resultData))
	}

	// 读取错误输出
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
