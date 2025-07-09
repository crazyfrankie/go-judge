package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/crazyfrankie/go-judge/pkg/rpc"
	"github.com/crazyfrankie/go-judge/pkg/runner/sandbox"
	"github.com/crazyfrankie/go-judge/pkg/types"
	"github.com/crazyfrankie/go-judge/pkg/utils"
)

type CRunner struct{}

func (c *CRunner) RunWithSandbox(ctx context.Context, req *rpc.JudgeRequest) (*rpc.JudgeResponse, error) {
	// build work dir
	workdir := fmt.Sprintf("%s/%d/%d", req.GetWorkdir(), req.GetProblemId(), req.GetUid())

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
	err := c.parseCTemplate(req.GetFullTemplate(), req.GetCode(), req.GetTypeDefinition(), workdir)
	if err != nil {
		return nil, fmt.Errorf("template parse error: %v", err)
	}

	// precompile
	compileRes, err := c.preCompile(workdir)
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
	testResults, err := c.runWithNativeSandbox(limit, req.GetInput(), req.GetOutput(), workdir)
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

func (c *CRunner) RunWithDocker(ctx context.Context, req *rpc.JudgeRequest) (*rpc.JudgeResponse, error) {
	return nil, nil
}

func (c *CRunner) runWithNativeSandbox(limit *types.Limit, inputs []string, expectedOutputs []string, workdir string) ([]*types.TestCaseResult, error) {
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

func (c *CRunner) parseCTemplate(fullTemp string, userCode string, types string, workdir string) error {
	tpl, _ := template.New("main").Delims("[[", "]]").Parse(fullTemp)
	codeFile, _ := os.OpenFile(fmt.Sprintf("%s/main.c", workdir), os.O_CREATE|os.O_RDWR, 0644)
	err := tpl.Execute(codeFile, map[string]string{
		"USER_CODE": userCode,
		"TYPES":     types,
	})
	defer codeFile.Close()
	if err != nil {
		return err
	}

	return nil
}

func (c *CRunner) preCompile(workdir string) (*types.PreCompileResult, error) {
	result := &types.PreCompileResult{}

	shFile := fmt.Sprintf("%s/%s", workdir, "build.sh")
	sh, err := os.OpenFile(shFile, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	defer sh.Close()
	if _, err = sh.WriteString(fmt.Sprintf(types.CBuildShell, workdir)); err != nil {
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
