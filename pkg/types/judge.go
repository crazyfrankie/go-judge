package types

type Limit struct {
	TimeLimit   int `json:"timeLimit"`   // in milliseconds
	MemoryLimit int `json:"memoryLimit"` // in MB
}

type ErrorRecord struct {
	Err error
	Num int
}

type PreCompileResult struct {
	Status       Status `json:"status"`
	ErrorMessage string `json:"error_message"`
}

type ExecutionResult struct {
	TimeUsed    int64  `json:"time_used"`    // 执行时间（毫秒）
	MemoryUsed  int64  `json:"memory_used"`  // 内存使用（字节）
	ExitCode    int    `json:"exit_code"`    // 退出码
	Output      string `json:"output"`       // 程序输出
	ErrorOutput string `json:"error_output"` // 错误输出
}

type TestCaseResult struct {
	Status          Status           `json:"status"`
	TimeUsed        int64            `json:"time_used"`        // 毫秒
	MemoryUsed      int64            `json:"memory_used"`      // 字节
	Output          string           `json:"output"`           // 实际输出
	ExpectedOutput  string           `json:"expected_output"`  // 期望输出
	ErrorMessage    string           `json:"error_message"`    // 错误信息
	ExecutionResult *ExecutionResult `json:"execution_result"` // 详细执行信息
}

// ContainerJudgeResult 容器内主控评测的结果
type ContainerJudgeResult struct {
	Status          string                `json:"status"`
	TotalTestCases  int                   `json:"total_test_cases"`
	PassedTestCases int                   `json:"passed_test_cases"`
	TotalTime       int64                 `json:"total_time"`
	TotalMemory     int64                 `json:"total_memory"`
	MaxMemory       int64                 `json:"max_memory"`
	AvgMemory       int64                 `json:"avg_memory"`
	TestResults     []ContainerTestResult `json:"test_results"`
	ErrorMessage    string                `json:"error_message,omitempty"`
}

// ContainerTestResult 容器内单个测试用例结果
type ContainerTestResult struct {
	TestId         string `json:"test_id"`
	Status         string `json:"status"`
	TimeUsed       int64  `json:"time_used"`
	MemoryUsed     int64  `json:"memory_used"`
	Output         string `json:"output,omitempty"`
	ExpectedOutput string `json:"expected_output,omitempty"`
	ErrorMessage   string `json:"error_message,omitempty"`
}

type Status int

const (
	StatusAccepted Status = iota
	StatusWrongAnswer
	StatusTimeLimitExceeded
	StatusMemoryLimitExceeded
	StatusRuntimeError
	StatusCompilationError
)

// CompareConfig Output Comparison Configuration
type CompareConfig struct {
	IgnoreWhitespace bool `json:"ignore_whitespace"` // 是否忽略空白字符
	IgnoreCase       bool `json:"ignore_case"`       // 是否忽略大小写
	Precision        int  `json:"precision"`         // 浮点数精度（小数点后位数）
}

// JudgeStatistics Judge Statistical Information
type JudgeStatistics struct {
	TotalTestCases    int   `json:"total_test_cases"`
	AcceptedTestCases int   `json:"accepted_test_cases"`
	TotalTime         int64 `json:"total_time"`   // 总时间（毫秒）
	MaxTime           int64 `json:"max_time"`     // 最大单个测试用例时间
	TotalMemory       int64 `json:"total_memory"` // 总内存使用
	MaxMemory         int64 `json:"max_memory"`   // 最大单个测试用例内存
}

type JudgeResult struct {
	Status       Status            `json:"status"`        // 整体状态
	TestCases    []*TestCaseResult `json:"test_cases"`    // 每个测试用例结果
	Statistics   *JudgeStatistics  `json:"statistics"`    // 统计信息
	ErrorMessage string            `json:"error_message"` // 错误信息
	SubmissionId string            `json:"submission_id"` // 提交ID
}
