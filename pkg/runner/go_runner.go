package runner

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/crazyfrankie/go-judge/pkg/rpc"
	"github.com/crazyfrankie/go-judge/pkg/runner/docker"
	"github.com/crazyfrankie/go-judge/pkg/runner/sandbox"
	"github.com/crazyfrankie/go-judge/pkg/types"
	"github.com/crazyfrankie/go-judge/pkg/utils"
)

// init handles the sandbox-init command
func init() {
	// Check if this is a sandbox initialization process
	if len(os.Args) > 1 && os.Args[1] == "sandbox-init" {
		if err := sandbox.ContainerInitProcess(); err != nil {
			fmt.Printf("Container init process failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

type GoRunner struct{}

func (g *GoRunner) RunWithDocker(ctx context.Context, req *rpc.JudgeRequest) (*rpc.JudgeResponse, error) {
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

	start := time.Now()
	judgeResult, err := docker.RunWithContainerControlled(ctx, limit, req.GetInput(), req.GetOutput(), workdir)
	if err != nil {
		return nil, fmt.Errorf("container-controlled execution failed: %v", err)
	}
	totalExecutionTime := time.Since(start)
	fmt.Printf("Container-controlled execution completed in %v for %d test cases\n", totalExecutionTime, len(req.GetInput()))

	if judgeResult.Status == "compilation_error" {
		result := &rpc.Result{
			Status:       rpc.Status_status_compilation_error,
			ErrorMessage: judgeResult.ErrorMessage,
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

	// Find the first failed test case (if any)
	var firstFailedResult *types.ContainerTestResult
	for i := range judgeResult.TestResults {
		if judgeResult.TestResults[i].Status != "accepted" {
			firstFailedResult = &judgeResult.TestResults[i]
			break
		}
	}

	// Construct the best result (shortest time)
	var bestResult *rpc.Result
	if len(judgeResult.TestResults) > 0 {
		bestTestResult := judgeResult.TestResults[0]
		for _, testResult := range judgeResult.TestResults {
			if testResult.Status == "accepted" && testResult.TimeUsed < bestTestResult.TimeUsed {
				bestTestResult = testResult
			}
		}

		bestResult = &rpc.Result{
			TimeUsed:          bestTestResult.TimeUsed,
			MemoryUsed:        bestTestResult.MemoryUsed,
			StatusRuntime:     utils.FormatRuntime(bestTestResult.TimeUsed),
			StatusMemory:      utils.FormatMemory(bestTestResult.MemoryUsed),
			RuntimePercentile: utils.CalculatePercentile(bestTestResult.TimeUsed, false),
			MemoryPercentile:  utils.CalculatePercentile(bestTestResult.MemoryUsed, true),
		}

		// If there are failed test cases, use the results of the first failure
		if firstFailedResult != nil {
			bestResult.TimeUsed = firstFailedResult.TimeUsed
			bestResult.MemoryUsed = firstFailedResult.MemoryUsed
			bestResult.Output = firstFailedResult.Output
			bestResult.ExpectedOutput = firstFailedResult.ExpectedOutput
			bestResult.ErrorMessage = firstFailedResult.ErrorMessage
			bestResult.StatusRuntime = utils.FormatRuntime(firstFailedResult.TimeUsed)
			bestResult.StatusMemory = utils.FormatMemory(firstFailedResult.MemoryUsed)
			bestResult.RuntimePercentile = utils.CalculatePercentile(firstFailedResult.TimeUsed, false)
			bestResult.MemoryPercentile = utils.CalculatePercentile(firstFailedResult.MemoryUsed, true)
		}

		switch judgeResult.Status {
		case "accepted":
			bestResult.Status = rpc.Status_status_accepted
			bestResult.StatusMsg = "Accepted"
		case "wrong_answer":
			bestResult.Status = rpc.Status_status_wrong_answer
			bestResult.StatusMsg = "Wrong Answer"
		case "time_limit_exceeded":
			bestResult.Status = rpc.Status_status_time_limit_exceeded
			bestResult.StatusMsg = "Time Limit Exceeded"
		case "memory_limit_exceeded":
			bestResult.Status = rpc.Status_status_memory_limit_exceeded
			bestResult.StatusMsg = "Memory Limit Exceeded"
		case "runtime_error":
			bestResult.Status = rpc.Status_status_runtime_error
			bestResult.StatusMsg = "Runtime Error"
		default:
			bestResult.Status = rpc.Status_status_runtime_error
			bestResult.StatusMsg = "Unknown Error"
		}

		// Setting up test case inputs (inputs for the first test case as an example)
		if len(req.GetInput()) > 0 {
			bestResult.TestcaseInput = req.GetInput()[0]
		}
	}

	// If there is a failure, set the index of the failed test case and return it immediately
	if judgeResult.Status != "accepted" && firstFailedResult != nil {
		// Find the index of failed test cases
		failedIndex := 0
		for i, testResult := range judgeResult.TestResults {
			if testResult.Status != "accepted" {
				failedIndex = i
				break
			}
		}

		bestResult.FailedTestcaseIndex = int32(failedIndex)

		// Constructing the comparison result string
		compareResult := ""
		for i := 0; i < len(judgeResult.TestResults); i++ {
			if i < failedIndex {
				compareResult += "1"
			} else if i == failedIndex {
				compareResult += "X"
				break
			}
		}

		return &rpc.JudgeResponse{
			Result: bestResult,
			Overall: &rpc.OverallStatistics{
				TotalTestcases: uint32(judgeResult.TotalTestCases),
				TotalCorrect:   uint32(judgeResult.PassedTestCases),
				CompareResult:  compareResult,
				FinalStatus:    bestResult.Status,
				TaskFinishTime: uint64(time.Now().UnixMilli()),
				Finished:       true,
			},
		}, nil
	}

	overall := &rpc.OverallStatistics{
		TotalTestcases:           uint32(judgeResult.TotalTestCases),
		TotalCorrect:             uint32(judgeResult.PassedTestCases),
		CompareResult:            strings.Repeat("1", judgeResult.TotalTestCases),
		TotalTime:                judgeResult.TotalTime,
		MaxMemory:                judgeResult.MaxMemory,
		AvgMemory:                judgeResult.AvgMemory,
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

func (g *GoRunner) RunWithSandbox(ctx context.Context, req *rpc.JudgeRequest) (*rpc.JudgeResponse, error) {
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

	start := time.Now()
	testResults, err := g.runWithNativeSandbox(limit, req.GetInput(), req.GetOutput(), workdir)
	if err != nil {
		return nil, fmt.Errorf("sandbox execution failed: %v", err)
	}
	totalExecutionTime := time.Since(start)
	fmt.Printf("Sandbox execution completed in %v for %d test cases\n", totalExecutionTime, len(req.GetInput()))

	var bestTimeResult *rpc.Result
	var bestMemoryResult *rpc.Result
	var totalTime int64
	var totalMemory int64
	var maxMemory int64

	for i, testResult := range testResults {
		input := ""
		if i < len(req.GetInput()) {
			input = req.GetInput()[i]
		}

		result := &rpc.Result{
			TimeUsed:          testResult.TimeUsed,
			MemoryUsed:        testResult.MemoryUsed,
			StatusRuntime:     utils.FormatRuntime(testResult.TimeUsed),
			StatusMemory:      utils.FormatMemory(testResult.MemoryUsed),
			StatusMsg:         utils.GetStatusMessage(testResult.Status),
			RuntimePercentile: utils.CalculatePercentile(testResult.TimeUsed, false),
			MemoryPercentile:  utils.CalculatePercentile(testResult.MemoryUsed, true),
			TestcaseInput:     input,
		}

		if testResult.Status != types.StatusAccepted {
			result.Output = testResult.Output
			result.ExpectedOutput = testResult.ExpectedOutput
			result.ErrorMessage = testResult.ErrorMessage
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

// runWithNativeSandbox run user code in linux native
func (g *GoRunner) runWithNativeSandbox(limit *types.Limit, inputs []string, expectedOutputs []string, workdir string) ([]*types.TestCaseResult, error) {
	results := make([]*types.TestCaseResult, 0, len(inputs))

	for i, input := range inputs {
		result := &types.TestCaseResult{
			ExpectedOutput: expectedOutputs[i],
		}

		sandboxResult, err := sandbox.ExecuteWithSandbox(workdir, limit.TimeLimit, limit.MemoryLimit, input)
		if err != nil {
			result.Status = types.StatusRuntimeError
			result.ErrorMessage = fmt.Sprintf("Sandbox execution failed: %v", err)
		} else {
			result.TimeUsed = sandboxResult.TimeUsed
			result.MemoryUsed = sandboxResult.MemoryUsed
			result.Output = sandboxResult.Output
			result.ExecutionResult = &types.ExecutionResult{
				TimeUsed:    sandboxResult.TimeUsed,
				MemoryUsed:  sandboxResult.MemoryUsed,
				ExitCode:    sandboxResult.ExitCode,
				Output:      sandboxResult.Output,
				ErrorOutput: sandboxResult.ErrorOutput,
			}

			if sandboxResult.Status == types.StatusAccepted {
				compareConfig := &types.CompareConfig{
					IgnoreWhitespace: true,
					IgnoreCase:       false,
					Precision:        -1,
				}

				if utils.CompareOutput(result.Output, result.ExpectedOutput, compareConfig) {
					result.Status = types.StatusAccepted
				} else {
					result.Status = types.StatusWrongAnswer
					result.ErrorMessage = "Output mismatch"
				}
			} else {
				result.Status = sandboxResult.Status
				result.ErrorMessage = utils.GetStatusMessage(sandboxResult.Status)
			}
		}

		results = append(results, result)
	}

	return results, nil
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
		"list":    `"container/list"`,
		"ring":    `"container/ring"`,
		"json":    `"encoding/json"`,
		"path":    `"path"`,
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
