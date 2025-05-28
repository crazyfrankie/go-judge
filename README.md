# Container Judge - 基于Docker的代码评测系统

这是一个基于Docker容器的分布式代码评测系统，支持多种编程语言，具有完整的安全隔离和资源限制功能。

## 项目特点

### 🚀 完整的评测流程
- **编译检查**: 自动检测语法错误和编译错误
- **运行时监控**: 实时监控程序执行状态
- **资源限制**: 支持时间和内存限制
- **输出比较**: 智能输出比较，支持多种比较模式
- **详细统计**: 提供详细的执行统计信息

### 🔒 安全隔离
- **Docker容器隔离**: 每个测试用例在独立容器中运行
- **资源限制**: 严格的CPU、内存、文件系统限制
- **进程限制**: 限制进程数量，防止fork炸弹
- **网络隔离**: 默认禁用网络访问

### 📊 丰富的结果信息

与LeetCode相比，我们的系统提供了更详细的评测信息：

#### LeetCode 返回的信息：
```json
{
  "status_code": 10,
  "lang": "golang", 
  "run_success": true,
  "status_runtime": "0 ms",
  "memory": 5852000,
  "total_correct": 63,
  "total_testcases": 63,
  "status_msg": "Accepted"
}
```

#### 我们系统返回的信息：
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
                       │   Result Parser  │    │ Docker Container│
                       │                  │    │                 │
                       │ stats.txt        │    │ Isolated Exec   │
                       │ result.txt       │    │ Resource Limits │
                       │ error.txt        │    │ Security        │
                       │ exitcode.txt     │    │                 │
                       └──────────────────┘    └─────────────────┘
```

## 快速开始

### 1. 环境准备
```bash
# 确保已安装 Docker
docker --version

# 安装 Go 依赖
make deps
```

### 2. 构建 Docker 镜像
```bash
make docker-build
```

### 3. 启动评测服务
```bash
make run-server
```

### 4. 测试评测功能
```bash
# 在另一个终端运行客户端
make run-client
```

## 评测文件详解

我们的系统生成以下评测文件，每个文件都有特定的作用：

### 📁 stats.txt
包含详细的系统资源使用统计：
```
Command being timed: "go run main.go"
User time (seconds): 7.54          # CPU用户态时间
System time (seconds): 1.41        # CPU系统态时间  
Percent of CPU this job got: 381%   # CPU使用率
Elapsed (wall clock) time: 0m 2.34s # 实际执行时间
Maximum resident set size (kbytes): 226268 # 最大内存使用
```

### 📁 result.txt
程序的标准输出，即程序运行结果

### 📁 error.txt  
程序的错误输出，包括：
- 编译错误信息
- 运行时错误
- 异常堆栈

### 📁 exitcode.txt
程序退出码：
- `0`: 正常退出
- `非0`: 异常退出

## 支持的评测状态

| 状态 | 说明 | 对应场景 |
|------|------|----------|
| `ACCEPTED` | 通过 | 输出完全正确 |
| `WRONG_ANSWER` | 答案错误 | 输出与期望不符 |
| `TIME_LIMIT_EXCEEDED` | 超时 | 执行时间超过限制 |
| `MEMORY_LIMIT_EXCEEDED` | 内存超限 | 内存使用超过限制 |
| `RUNTIME_ERROR` | 运行时错误 | 程序崩溃或异常 |
| `COMPILATION_ERROR` | 编译错误 | 代码语法错误 |

## 高级特性

### 🔍 智能输出比较
支持多种输出比较模式：
- **精确匹配**: 字符串完全相同
- **忽略空白**: 忽略多余的空格和换行
- **忽略大小写**: 不区分大小写
- **浮点数比较**: 支持精度设置的浮点数比较

### ⚡ 并发执行
- 多个测试用例并行执行
- 独立的工作目录，避免冲突
- 异步结果收集

### 📈 详细统计
- 每个测试用例的详细执行信息
- 整体统计数据
- 性能分析指标

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

### 扩展输出比较功能

在 `pkg/runner/go_runner.go` 中修改 `compareOutputAdvanced` 函数，添加自定义比较逻辑。

## 与 LeetCode 的对比

| 特性 | LeetCode | 我们的系统 |
|------|----------|------------|
| 执行环境 | 黑盒 | 完全透明的 Docker 容器 |
| 资源监控 | 基础信息 | 详细的系统级统计 |
| 错误信息 | 简单 | 详细的错误堆栈和调试信息 |
| 扩展性 | 封闭 | 开源，可自由扩展 |
| 部署方式 | SaaS | 可私有化部署 |
| 语言支持 | 预设 | 可自由添加新语言 |

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License
