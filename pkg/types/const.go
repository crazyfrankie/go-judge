package types

const (
	WorkDir = "/home/%s/judge"
)

const (
	GoShell = `#!/bin/sh
set -e
cd /app

# [1/5] 清理之前的结果文件
rm -f result.txt error.txt stats.txt exitcode.txt compile.txt

# [2/5] 编译检查和格式化
echo "Compiling..." > /tmp/compile.log
if ! go fmt %s > compile.txt 2>&1; then
    echo "1" > exitcode.txt
    cat compile.txt > error.txt
    echo "Format error" >> error.txt
    exit 1
fi

# [3/5] 编译程序（不运行）
if ! go build -o /tmp/program %s > compile.txt 2>&1; then
    echo "1" > exitcode.txt
    cat compile.txt > error.txt
    echo "Compilation error" >> error.txt
    exit 1
fi

# [4/5] 运行编译好的程序并测量时间
echo "Running..." > /tmp/run.log
/usr/bin/time -v -o stats.txt timeout 30s /tmp/program > result.txt 2> error.txt
echo $? > exitcode.txt

# [5/5] 清理临时文件
rm -f /tmp/program compile.txt
`
	GoImage = "oj/go-runner:1.24"
)
