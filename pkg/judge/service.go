package judge

import (
	"context"
	"fmt"
	"time"

	"github.com/crazyfrankie/go-judge/pkg/rpc"
	"github.com/crazyfrankie/go-judge/pkg/runner"
	"github.com/crazyfrankie/go-judge/pkg/types"
)

type JudgeService struct {
	rpc.UnimplementedJudgeServiceServer
	goRunner *runner.GoRunner
}

func NewJudgeService() *JudgeService {
	return &JudgeService{
		goRunner: &runner.GoRunner{},
	}
}

func (j *JudgeService) Judge(ctx context.Context, req *rpc.JudgeRequest) (*rpc.JudgeResponse, error) {
	var response *rpc.JudgeResponse
	var err error

	switch req.GetLanguage() {
	case rpc.Language_go:
		response, err = j.goRunner.RunWithSandbox(ctx, req)
	case rpc.Language_java:
		// TODO: 实现 Java runner
		return nil, fmt.Errorf("Java runner not implemented yet")
	case rpc.Language_cpp:
		// TODO: 实现 C++ runner
		return nil, fmt.Errorf("C++ runner not implemented yet")
	case rpc.Language_python:
		// TODO: 实现 Python runner
		return nil, fmt.Errorf("Python runner not implemented yet")
	default:
		return nil, fmt.Errorf("unsupported language: %v", req.GetLanguage())
	}

	if err != nil {
		return nil, fmt.Errorf("judge execution failed: %v", err)
	}

	if response != nil {
		j.logJudgeResult(req, response)
	}

	return response, nil
}

func (j *JudgeService) logJudgeResult(req *rpc.JudgeRequest, resp *rpc.JudgeResponse) {

	if resp.Overall != nil {
		overall := resp.Overall
		fmt.Printf("Judge completed - Problem: %d, User: %d, Total: %d, Correct: %d, Status: %v\n",
			req.GetProblemId(), req.GetUid(), overall.TotalTestcases, overall.TotalCorrect, overall.FinalStatus)

		if overall.FinalStatus == rpc.Status_status_accepted {
			fmt.Printf("Performance - TotalTime: %dms, MaxMemory: %d bytes, AvgMemory: %d bytes\n",
				overall.TotalTime, overall.MaxMemory, overall.AvgMemory)
		}
	}

	if resp.Result != nil {
		result := resp.Result
		fmt.Printf("Result - Status: %v, Time: %dms, Memory: %d bytes\n",
			result.Status, result.TimeUsed, result.MemoryUsed)

		if result.Status != rpc.Status_status_accepted && result.ErrorMessage != "" {
			fmt.Printf("Error: %s\n", result.ErrorMessage)
		}
	}
}

func (j *JudgeService) createDetailedResult(results []*types.TestCaseResult) *types.JudgeResult {
	if len(results) == 0 {
		return &types.JudgeResult{
			Status:       types.StatusRuntimeError,
			ErrorMessage: "No test cases found",
		}
	}

	overallStatus := types.StatusAccepted
	var errorMessage string

	for _, result := range results {
		if result.Status != types.StatusAccepted {
			overallStatus = result.Status
			if errorMessage == "" && result.ErrorMessage != "" {
				errorMessage = result.ErrorMessage
			}
			if result.Status == types.StatusCompilationError {
				break
			}
		}
	}

	statistics := j.calculateStatistics(results)

	return &types.JudgeResult{
		Status:       overallStatus,
		TestCases:    results,
		Statistics:   statistics,
		ErrorMessage: errorMessage,
		SubmissionId: fmt.Sprintf("%d", time.Now().UnixNano()),
	}
}

func (j *JudgeService) calculateStatistics(results []*types.TestCaseResult) *types.JudgeStatistics {
	stats := &types.JudgeStatistics{
		TotalTestCases: len(results),
	}

	for _, result := range results {
		if result.Status == types.StatusAccepted {
			stats.AcceptedTestCases++
		}

		stats.TotalTime += result.TimeUsed
		if result.TimeUsed > stats.MaxTime {
			stats.MaxTime = result.TimeUsed
		}

		stats.TotalMemory += result.MemoryUsed
		if result.MemoryUsed > stats.MaxMemory {
			stats.MaxMemory = result.MemoryUsed
		}
	}

	return stats
}
