package types

const (
	WorkDir = "/home/%s/judge"
)

const (
	GoShell = `#!/bin/sh
set -e
cd /app

rm -f result.txt error.txt stats.txt exitcode.txt

/usr/bin/time -v -o stats.txt go run %s > result.txt 2> error.txt
echo $? > exitcode.txt
`
	GoImage = "oj/go-runner:1.24"
)
