package types

const (
	WorkDir = "/home/%s/judge"
)

const (
	GoShell = `#!/bin/sh
set -e
cd /app

# 清理之前的结果文件
rm -f result.txt error.txt stats.txt exitcode.txt

# 尝试编译检查语法
if ! go fmt %s > error.txt 2>&1; then
    echo "1" > exitcode.txt
    echo "Format error" >> error.txt
    exit 1
fi

# 运行程序并收集统计信息
/usr/bin/time -v -o stats.txt timeout 30s go run %s > result.txt 2> error.txt
echo $? > exitcode.txt

# 如果有编译错误，确保记录
if [ -s error.txt ] && [ ! -s result.txt ]; then
    echo "1" > exitcode.txt
fi
`
	GoImage = "oj/go-runner:1.24"
)
