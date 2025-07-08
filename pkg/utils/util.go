package utils

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/crazyfrankie/go-judge/pkg/types"
)

func CompareOutput(actual, expected string, config *types.CompareConfig) bool {
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

func FormatRuntime(timeMs int64) string {
	if timeMs < 1000 {
		return fmt.Sprintf("%d ms", timeMs)
	}
	return fmt.Sprintf("%.2f s", float64(timeMs)/1000.0)
}

func FormatMemory(bytes int64) string {
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

func GetStatusMessage(status types.Status) string {
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

func CalculatePercentile(value int64, isMemory bool) uint32 {
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
