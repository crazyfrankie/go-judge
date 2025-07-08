package main

import (
	"net"

	"google.golang.org/grpc"

	"github.com/crazyfrankie/go-judge/pkg/judge"
	"github.com/crazyfrankie/go-judge/pkg/rpc"
)

func main() {
	srv := grpc.NewServer()

	rpc.RegisterJudgeServiceServer(srv, judge.NewJudgeService())

	conn, err := net.Listen("tcp", ":8086")
	if err != nil {
		panic(err)
	}
	err = srv.Serve(conn)
	if err != nil {
		panic(err)
	}
}
