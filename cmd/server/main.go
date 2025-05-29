package main

import (
	"log"
	"net"

	"github.com/crazyfrankie/go-judge/pkg/judge"
	"github.com/crazyfrankie/go-judge/pkg/rpc"
	"google.golang.org/grpc"
)

func main() {
	// 创建 gRPC 服务器
	s := grpc.NewServer()

	// 注册服务
	judgeService := judge.NewJudgeService()
	rpc.RegisterJudgeServiceServer(s, judgeService)

	// 监听端口
	lis, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Println("Judge service starting on :8080")

	// 启动服务器
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
