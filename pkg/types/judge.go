package types

type Limit struct {
	TimeLimit   int `json:"timeLimit"`   // in milliseconds
	MemoryLimit int `json:"memoryLimit"` // in MB
}

type ErrorRecord struct {
	Err error
	Num int
}

// Status represents the status of a code evaluation
type Status int

const (
	StatusAccepted Status = iota
	StatusWrongAnswer
	StatusTimeLimitExceeded
	StatusMemoryLimitExceeded
	StatusRuntimeError
	StatusCompilationError
	StatusSecurityViolation
)

func (s Status) String() string {
	switch s {
	case StatusAccepted:
		return "Accepted"
	case StatusWrongAnswer:
		return "Wrong Answer"
	case StatusTimeLimitExceeded:
		return "Time Limit Exceeded"
	case StatusMemoryLimitExceeded:
		return "Memory Limit Exceeded"
	case StatusRuntimeError:
		return "Runtime Error"
	case StatusCompilationError:
		return "Compilation Error"
	case StatusSecurityViolation:
		return "Security Violation"
	default:
		return "Unknown"
	}
}
