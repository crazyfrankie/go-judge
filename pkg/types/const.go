package types

const (
	WorkDir = "/home/%s/judge"
)

const (
	GoBuildShell = `
#!/bin/sh
set -e
cd %s

# [1/3] 清理之前的结果文件
rm -f result.txt error.txt stats.txt exitcode.txt compile.txt

# [2/3] 编译检查和格式化
if ! go fmt main.go > compile.txt 2>&1; then
    echo "1" > exitcode.txt
    cat compile.txt > error.txt
    echo "Format error" >> error.txt
    exit 1
fi

# [3/3] 编译新的文件
if ! go build main.go > compile.txt 2>&1; then
    echo "1" > exitcode.txt
    cat compile.txt > error.txt
    echo "Compilation error" >> error.txt
    exit 1
fi
`

	GoRunShell = `
#!/bin/sh
set -e
cd /app

# 清理之前的结果文件
rm -f result.txt error.txt stats.txt exitcode.txt

# 运行预编译的程序并收集统计信息
echo '%s' | /usr/bin/time -v -o stats.txt timeout 30s ./main > result.txt 2> error.txt
echo $? > exitcode.txt

echo "Test execution completed"
`

	// 容器内主控评测脚本模板
	GoMainJudgeShell = `#!/bin/bash
# Container-Controlled Judge Script
set -e

# 配置参数
TIME_LIMIT=%d  # 秒
MEMORY_LIMIT=%d  # MB
IGNORE_WHITESPACE=%t
IGNORE_CASE=%t

# 工作目录
WORK_DIR="/run/work"
SRC_DIR="/src"
TESTCASES_DIR="/testcases"
OUTPUT_DIR="/output"

# 创建工作目录
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# 函数：记录错误并退出
log_error() {
    echo "{\"status\":\"compilation_error\",\"error_message\":\"$1\",\"test_results\":[]}" > "$OUTPUT_DIR/final_result.json"
    exit 1
}

# 函数：编译用户代码
compile_user_code() {
    echo "Starting compilation..."
    
    # 复制源代码到工作目录
    cp "$SRC_DIR/main.go" ./
    
    # 格式化检查
    if ! go fmt main.go 2>/dev/null; then
        log_error "Code format error"
    fi
    
    # 编译
    if ! go build -o user_program main.go 2>compile_error.log; then
        error_msg=$(cat compile_error.log 2>/dev/null || echo "Unknown compilation error")
        log_error "Compilation failed: $error_msg"
    fi
    
    echo "Compilation successful"
}

# 函数：获取cgroup内存峰值(字节)
get_peak_memory() {
    local pid=$1
    local max_memory=0
    
    # 尝试从不同的cgroup路径读取内存使用
    for cgroup_path in "/sys/fs/cgroup/memory/memory.max_usage_in_bytes" \
                       "/sys/fs/cgroup/memory.peak" \
                       "/sys/fs/cgroup/memory.current"; do
        if [ -f "$cgroup_path" ]; then
            local mem=$(cat "$cgroup_path" 2>/dev/null || echo "0")
            if [ "$mem" -gt "$max_memory" ]; then
                max_memory=$mem
            fi
        fi
    done
    
    # 如果cgroup不可用，使用ps估算
    if [ "$max_memory" -eq 0 ]; then
        max_memory=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{print $1*1024}' || echo "0")
    fi
    
    echo $max_memory
}

# 函数：运行单个测试用例
run_single_testcase() {
    local input_file="$1"
    local expected_file="$2"
    local test_id="$3"
    
    echo "Running test case $test_id..."
    
    # 准备输入
    cp "$input_file" ./input.txt
    
    # 运行程序并监控
    local start_time=$(date +%%s%%3N)
    timeout "${TIME_LIMIT}s" ./user_program < input.txt > user_output.txt 2> user_error.txt &
    local pid=$!
    
    # 等待程序结束
    wait $pid
    local exit_code=$?
    local end_time=$(date +%%s%%3N)
    local time_used=$((end_time - start_time))
    
    # 获取内存使用
    local memory_used=$(get_peak_memory $pid)
    
    # 判断执行状态
    local status="accepted"
    local error_message=""
    
    # 检查超时
    if [ $exit_code -eq 124 ]; then
        status="time_limit_exceeded"
        error_message="Time limit exceeded"
        echo "{\"test_id\":\"$test_id\",\"status\":\"$status\",\"time_used\":$time_used,\"memory_used\":$memory_used,\"error_message\":\"$error_message\"}"
        return
    fi
    
    # 检查运行时错误
    if [ $exit_code -ne 0 ]; then
        status="runtime_error"
        error_message="Program exited with code $exit_code"
        if [ -s user_error.txt ]; then
            error_message="$error_message: $(cat user_error.txt)"
        fi
        echo "{\"test_id\":\"$test_id\",\"status\":\"$status\",\"time_used\":$time_used,\"memory_used\":$memory_used,\"error_message\":\"$error_message\"}"
        return
    fi
    
    # 检查内存限制 (转换MB到字节)
    local memory_limit_bytes=$((MEMORY_LIMIT * 1024 * 1024))
    if [ "$memory_used" -gt "$memory_limit_bytes" ]; then
        status="memory_limit_exceeded"
        error_message="Memory limit exceeded"
        echo "{\"test_id\":\"$test_id\",\"status\":\"$status\",\"time_used\":$time_used,\"memory_used\":$memory_used,\"error_message\":\"$error_message\"}"
        return
    fi
    
    # 比较输出
    local user_output=$(cat user_output.txt)
    local expected_output=$(cat "$expected_file")
    
    # 处理输出比较选项
    if [ "$IGNORE_WHITESPACE" = "true" ]; then
        user_output=$(echo "$user_output" | tr -s ' \t\n' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
        expected_output=$(echo "$expected_output" | tr -s ' \t\n' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
    fi
    
    if [ "$IGNORE_CASE" = "true" ]; then
        user_output=$(echo "$user_output" | tr '[:upper:]' '[:lower:]')
        expected_output=$(echo "$expected_output" | tr '[:upper:]' '[:lower:]')
    fi
    
    if [ "$user_output" != "$expected_output" ]; then
        status="wrong_answer"
        error_message="Output mismatch"
    fi
    
    echo "{\"test_id\":\"$test_id\",\"status\":\"$status\",\"time_used\":$time_used,\"memory_used\":$memory_used,\"output\":\"$(echo "$user_output" | sed 's/"/\\"/g')\",\"expected_output\":\"$(echo "$expected_output" | sed 's/"/\\"/g')\"}"
}

# 主流程开始
echo "Container-controlled judge starting..."

# 编译用户代码
compile_user_code

# 获取所有测试用例
testcases=$(find "$TESTCASES_DIR" -name "*.in" | sort)
test_results=()
total_tests=0
passed_tests=0
total_time=0
total_memory=0
max_memory=0

echo "Found test cases:"
echo "$testcases"

# 遍历执行所有测试用例
for input_file in $testcases; do
    test_name=$(basename "$input_file" .in)
    output_file="${input_file%%.in}.out"
    
    if [ ! -f "$output_file" ]; then
        echo "Warning: Expected output file not found: $output_file"
        continue
    fi
    
    total_tests=$((total_tests + 1))
    
    # 运行测试用例
    result=$(run_single_testcase "$input_file" "$output_file" "$test_name")
    test_results+=("$result")
    
    # 解析结果统计
    status=$(echo "$result" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    time_used=$(echo "$result" | grep -o '"time_used":[0-9]*' | cut -d':' -f2)
    memory_used=$(echo "$result" | grep -o '"memory_used":[0-9]*' | cut -d':' -f2)
    
    if [ "$status" = "accepted" ]; then
        passed_tests=$((passed_tests + 1))
    else
        # 如果有测试用例失败，记录失败信息并可以选择是否继续
        echo "Test case $test_name failed with status: $status"
    fi
    
    total_time=$((total_time + time_used))
    total_memory=$((total_memory + memory_used))
    
    if [ "$memory_used" -gt "$max_memory" ]; then
        max_memory=$memory_used
    fi
    
    # 清理临时文件
    rm -f input.txt user_output.txt user_error.txt
done

# 确定最终状态
final_status="accepted"
if [ $passed_tests -ne $total_tests ]; then
    # 找到第一个失败的测试用例状态
    for result in "${test_results[@]}"; do
        status=$(echo "$result" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        if [ "$status" != "accepted" ]; then
            final_status="$status"
            break
        fi
    done
fi

# 生成最终结果JSON
{
    echo "{"
    echo "  \"status\": \"$final_status\","
    echo "  \"total_test_cases\": $total_tests,"
    echo "  \"passed_test_cases\": $passed_tests,"
    echo "  \"total_time\": $total_time,"
    echo "  \"total_memory\": $total_memory,"
    echo "  \"max_memory\": $max_memory,"
    echo "  \"avg_memory\": $((total_memory / total_tests)),"
    echo "  \"test_results\": ["
    
    # 输出所有测试结果
    for i in "${!test_results[@]}"; do
        echo "    ${test_results[i]}"
        if [ $i -lt $((${#test_results[@]} - 1)) ]; then
            echo ","
        fi
    done
    
    echo "  ]"
    echo "}"
} > "$OUTPUT_DIR/final_result.json"

echo "Judge completed. Results written to $OUTPUT_DIR/final_result.json"
`
)

const (
	GoImage = "oj/go-runner:1.24.2"
)
