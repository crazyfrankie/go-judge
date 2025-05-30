.PHONY: build run-server run-client test docker-build docker-run clean proto

# 构建所有组件
build:
	go build -o bin/server cmd/server/main.go
	go build -o bin/client cmd/client/main.go

# 运行服务器
run-server: build
	./bin/server

# 运行客户端
run-client: build
	./bin/client

# 运行测试
test:
	go test ./...

# 构建 Docker 镜像
docker-build:
	docker build -t oj/go-runner:1.24 .

# 运行 Docker 容器进行测试
docker-run: docker-build
	docker run --rm -v $(PWD)/work:/app oj/go-runner:1.24

# 清理构建文件
clean:
	rm -rf bin/
	rm -f work/result.txt work/error.txt work/stats.txt work/exitcode.txt

# 清理系统资源（修复文件描述符泄漏）
clean-system:
	chmod +x ./cleanup.sh
	./cleanup.sh

# 生成 protobuf 文件
proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		pkg/rpc/proto/judge.proto

# 安装依赖
deps:
	go mod tidy
	go mod download

# 格式化代码
fmt:
	go fmt ./...

# 检查代码
lint:
	golangci-lint run ./...

# 创建工作目录
setup:
	mkdir -p work
	mkdir -p bin
	chmod +x work/run.sh

# 完整测试流程
test-full: docker-build setup
	@echo "Testing Go runner..."
	cd work && /usr/bin/time -v -o stats.txt go run main.go > result.txt 2> error.txt; echo $$? > exitcode.txt
	@echo "Results:"
	@cat work/result.txt
	@echo "Stats:"
	@cat work/stats.txt | head -10

# 构建清理工具
build-cleanup:
	mkdir -p bin
	go build -o bin/cleanup cmd/cleanup/main.go

# 运行清理工具（解决文件描述符泄漏问题）
cleanup: build-cleanup
	./bin/cleanup
	
# 运行测试（测试后自动清理）
test-safe: 
	go test ./...
	make cleanup
