package main

import (
	"context"
	"log"
	"time"

	"github.com/crazyfrankie/go-judge/pkg/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// 连接到服务器
	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// 创建客户端
	client := rpc.NewJudgeServiceClient(conn)

	// 构造测试请求 - 反转链表问题
	req := &rpc.JudgeRequest{
		Language:       rpc.Language_go,
		ProblemId:      206,
		Uid:            12345,
		Code:           getReverseListCode(),
		FullTemplate:   getGoTemplate(),
		TypeDefinition: getListNodeDefinition(),
		Input:          []string{"[1,2,3,4,5]", "[1,2]", "[]"},
		Output:         []string{"[5,4,3,2,1]", "[2,1]", "[]"},
		MaxMem:         "128",  // 128MB
		MaxTime:        "1000", // 1000ms
	}

	// 发送评测请求
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Judge(ctx, req)
	if err != nil {
		log.Fatalf("Judge failed: %v", err)
	}

	// 打印结果
	log.Printf("Judge completed with %d test cases", len(resp.Results))
	for i, result := range resp.Results {
		log.Printf("Test case %d: Status=%v, Time=%dms, Memory=%d bytes",
			i+1, result.Status, result.TimeUsed, result.MemoryUsed)
		if result.Status != rpc.Status_status_accepted {
			log.Printf("  Expected: %s", result.ExpectedOutput)
			log.Printf("  Actual:   %s", result.Output)
		}
	}
}

func getReverseListCode() string {
	return `func reverseList(head *ListNode) *ListNode {
    var prev *ListNode
    for head != nil {
        next := head.Next
        head.Next = prev
        prev = head
        head = next
    }
    return prev
}`
}

func getGoTemplate() string {
	return `package main

import (
    "fmt"
    "strconv"
    "strings"
)

{{.TYPES}}

{{.USER_CODE}}

func main() {
    // 解析输入
    input := "{{.INPUT}}"
    result := processInput(input)
    fmt.Print(result)
}

func processInput(input string) string {
    if input == "[]" {
        return "[]"
    }
    
    // 解析数组
    input = strings.Trim(input, "[]")
    if input == "" {
        return "[]"
    }
    
    parts := strings.Split(input, ",")
    var nums []int
    for _, part := range parts {
        num, _ := strconv.Atoi(strings.TrimSpace(part))
        nums = append(nums, num)
    }
    
    // 构建链表
    head := buildList(nums)
    
    // 反转链表
    reversed := reverseList(head)
    
    // 输出结果
    return formatList(reversed)
}

func buildList(nums []int) *ListNode {
    if len(nums) == 0 {
        return nil
    }
    
    head := &ListNode{Val: nums[0]}
    curr := head
    
    for i := 1; i < len(nums); i++ {
        curr.Next = &ListNode{Val: nums[i]}
        curr = curr.Next
    }
    
    return head
}

func formatList(head *ListNode) string {
    if head == nil {
        return "[]"
    }
    
    var result []string
    for head != nil {
        result = append(result, strconv.Itoa(head.Val))
        head = head.Next
    }
    
    return "[" + strings.Join(result, ",") + "]"
}`
}

func getListNodeDefinition() string {
	return `type ListNode struct {
    Val  int
    Next *ListNode
}`
}
