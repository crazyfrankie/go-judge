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
	// 根据语言选择对应的 runner
	var response *rpc.JudgeResponse
	var err error

	switch req.GetLanguage() {
	case rpc.Language_go:
		response, err = j.goRunner.Run(ctx, req)
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

	// 添加提交ID和时间戳等元数据
	if response != nil {
		// 这里可以添加额外的处理逻辑，比如记录到数据库等
		j.logJudgeResult(req, response)
	}

	return response, nil
}

// 记录评测结果（可选）
func (j *JudgeService) logJudgeResult(req *rpc.JudgeRequest, resp *rpc.JudgeResponse) {
	// 计算总体统计
	var totalCorrect, totalTests int
	var maxTime, maxMemory int64

	for _, result := range resp.GetResults() {
		totalTests++
		if result.Status == rpc.Status_status_accepted {
			totalCorrect++
		}
		if result.TimeUsed > maxTime {
			maxTime = result.TimeUsed
		}
		if result.MemoryUsed > maxMemory {
			maxMemory = result.MemoryUsed
		}
	}

	// 这里可以记录到日志或数据库
	fmt.Printf("Judge completed - Problem: %d, User: %d, Total: %d, Correct: %d, MaxTime: %dms, MaxMemory: %d bytes\n",
		req.GetProblemId(), req.GetUid(), totalTests, totalCorrect, maxTime, maxMemory)
}

// 创建详细的评测结果
func (j *JudgeService) createDetailedResult(results []*types.TestCaseResult) *types.JudgeResult {
	if len(results) == 0 {
		return &types.JudgeResult{
			Status:       types.StatusRuntimeError,
			ErrorMessage: "No test cases found",
		}
	}

	// 计算整体状态
	overallStatus := types.StatusAccepted
	var errorMessage string

	for _, result := range results {
		if result.Status != types.StatusAccepted {
			overallStatus = result.Status
			if errorMessage == "" && result.ErrorMessage != "" {
				errorMessage = result.ErrorMessage
			}
			// 如果是编译错误，立即返回
			if result.Status == types.StatusCompilationError {
				break
			}
		}
	}

	// 计算统计信息
	statistics := j.calculateStatistics(results)

	return &types.JudgeResult{
		Status:       overallStatus,
		TestCases:    results,
		Statistics:   statistics,
		ErrorMessage: errorMessage,
		SubmissionId: fmt.Sprintf("%d", time.Now().UnixNano()),
	}
}

// 计算统计信息
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
