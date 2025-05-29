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
)

const (
	GoImage = "oj/go-runner:1.24.2"
)
