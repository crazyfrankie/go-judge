# Container Judge - 基于容器的代码评测系统

这是一个基于容器(Docker/自实现容器)的分布式代码评测系统，支持多种编程语言，具有完整的安全隔离和资源限制功能。

## 项目特点

### 🚀 完整的评测流程
- **编译检查**: 自动检测语法错误和编译错误
- **运行时监控**: 实时监控程序执行状态
- **资源限制**: 支持时间和内存限制
- **输出比较**: 智能输出比较，支持多种比较模式
- **详细统计**: 提供详细的执行统计信息

### 🔒 安全隔离
- **容器隔离**: 每个测试用例在独立容器中运行
- **资源限制**: 严格的CPU、内存、文件系统限制
- **进程限制**: 限制进程数量，防止fork炸弹
- **网络隔离**: 默认禁用网络访问

### 📊 丰富的结果信息
```json
{
  "status": "accepted",
  "test_cases": [
    {
      "status": "accepted",
      "time_used": 150,
      "memory_used": 2048000,
      "output": "[5,4,3,2,1]",
      "expected_output": "[5,4,3,2,1]",
      "execution_result": {
        "time_used": 150,
        "memory_used": 2048000,
        "exit_code": 0,
        "output": "[5,4,3,2,1]",
        "error_output": ""
      }
    }
  ],
  "statistics": {
    "total_test_cases": 3,
    "accepted_test_cases": 3,
    "total_time": 450,
    "max_time": 200,
    "total_memory": 6144000,
    "max_memory": 2048000
  }
}
```

## 系统架构

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client API    │    │   Judge Service  │    │  Runner Service │
│                 │───▶│                  │───▶│                 │
│ gRPC Interface  │    │  Multi-language  │    │Language-specific│
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                         │
                                ▼                         ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │   Result Parser  │    │  Container      │
                       │                  │    │                 │
                       │ stats.txt        │    │ Isolated Exec   │
                       │ result.txt       │    │ Resource Limits │
                       │ error.txt        │    │ Security        │
                       │ exitcode.txt     │    │                 │
                       └──────────────────┘    └─────────────────┘
```

## 支持的评测状态

| 状态 | 说明 | 对应场景 |
|------|------|----------|
| `ACCEPTED` | 通过 | 输出完全正确 |
| `WRONG_ANSWER` | 答案错误 | 输出与期望不符 |
| `TIME_LIMIT_EXCEEDED` | 超时 | 执行时间超过限制 |
| `MEMORY_LIMIT_EXCEEDED` | 内存超限 | 内存使用超过限制 |
| `RUNTIME_ERROR` | 运行时错误 | 程序崩溃或异常 |
| `COMPILATION_ERROR` | 编译错误 | 代码语法错误 |

## API 使用示例

### gRPC 接口
```go
// 创建评测请求
req := &rpc.JudgeRequest{
    Language:    rpc.Language_go,
    ProblemId:   206,
    Uid:         12345,
    Code:        userCode,
    FullTemplate: template,
    TypeDefinition: types,
    Input:       []string{"[1,2,3]", "[4,5]"},
    Output:      []string{"[3,2,1]", "[5,4]"},
    MaxMem:      "128",  // 128MB
    MaxTime:     "1000", // 1000ms
}

// 发送评测请求
resp, err := client.Judge(ctx, req)
```

## 开发指南

### 添加新语言支持

1. 在 `pkg/runner/` 下创建新的 runner 文件
2. 实现 `RunnerServiceServer` 接口
3. 在 `pkg/types/const.go` 中添加语言相关常量
4. 创建对应的 Docker 镜像

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License
