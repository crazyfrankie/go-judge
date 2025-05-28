package runner

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"html/template"
	"math"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/crazyfrankie/go-judge/pkg/rpc"
	"github.com/crazyfrankie/go-judge/pkg/types"
)

var (
	ErrCompilation = errors.New("compilation error")
)

type GoRunner struct {
	rpc.UnimplementedRunnerServiceServer
}

func (g *GoRunner) Run(ctx context.Context, req *rpc.JudgeRequest) (*rpc.JudgeResponse, error) {
	cmd := exec.Command("whoami")
	user, _ := cmd.CombinedOutput()

	pdir := fmt.Sprintf("%s/%d/%d", fmt.Sprintf(types.WorkDir, string(user)), req.GetProblemId(), req.GetUid())

	var wg sync.WaitGroup
	errResult := make([]types.ErrorRecord, 0, len(req.GetInput()))

	for i, input := range req.GetInput() {
		go func() {
			wg.Add(1)
			// pdir : /home/{user}/judge/{uid}/{pid}/{tid}
			tdir := fmt.Sprintf("%s/%d", pdir, i)
			execPath := fmt.Sprintf("%s/%d", tdir, i)
			err := judgeOneTestCase(context.Background(), req.GetFullTemplate(), req.GetCode(),
				req.GetTypeDefinition(), input, execPath, tdir)
			if err != nil {
				errResult = append(errResult, types.ErrorRecord{
					Err: err,
					Num: i,
				})
			}
			wg.Done()
		}()
	}

	wg.Wait()

	if len(errResult) == 0 {
		return nil, nil
	}

	return nil, nil
}

func judgeOneTestCase(ctx context.Context, fullTemp string, userCode string, types string, input string, execPath string, workdir string) error {
	codeFile, err := parseTemplate(fullTemp, userCode, types, input)
	if err != nil {
		return err
	}
	defer os.Remove(codeFile)

	err = buildExec(execPath, "")
	if err != nil {
		return ErrCompilation
	}
	defer os.Remove(execPath)

	shFile, err := buildShell(workdir, execPath)
	if err != nil {
		return err
	}
	defer os.Remove(shFile)

	err = runDocker(ctx, nil, workdir)
	if err != nil {
		return err
	}

	stats := parseStatsFile(workdir)
	fmt.Println(stats)

	return nil
}

func parseTemplate(fullTemp string, userCode string, types string, input string) (string, error) {
	tpl, _ := template.New("main").Funcs(template.FuncMap{
		"safe": func(s string) template.HTML { return template.HTML(s) },
	}).Parse(fullTemp)

	tmp, _ := os.CreateTemp(os.TempDir(), "main_*.go")
	defer os.Remove(tmp.Name())

	err := tpl.Execute(tmp, map[string]string{
		"TYPES":     types,
		"USER_CODE": userCode,
		"TEST_CODE": input,
		"IMPORTS":   "",
	})
	if err != nil {
		return "", err
	}

	content, _ := os.ReadFile(tmp.Name())
	imports := detectImports(string(content))

	var final string
	if len(imports) != 0 {
		final = "\n\nimport (\n" + strings.Join(imports, "\n") + "\n)\n"
	}

	newTpl, _ := template.New("main").Funcs(template.FuncMap{
		"safe": func(s string) template.HTML { return template.HTML(s) },
	}).Parse(fullTemp)
	codeFile, _ := os.CreateTemp(os.TempDir(), "main_*.go")
	err = newTpl.Execute(codeFile, map[string]string{
		"USER_CODE": userCode,
		"TEST_CODE": input,
		"TYPES":     types,
		"IMPORTS":   final,
	})
	if err != nil {
		return "", err
	}

	return codeFile.Name(), nil
}

func detectImports(code string) []string {
	set := make(map[string]bool)
	fset := token.NewFileSet()
	f, _ := parser.ParseFile(fset, "", code, parser.AllErrors)
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				set[ident.Name] = true
			}
		}
		return true
	})
	allowed := map[string]string{
		"fmt":     `"fmt"`,
		"sort":    `"sort"`,
		"math":    `"math"`,
		"strings": `"strings"`,
		"strconv": `"strconv"`,
		"heap":    `"container/heap"`,
		"json":    `"encoding/json"`,
	}
	var imports []string
	for name := range set {
		if imp, ok := allowed[name]; ok {
			imports = append(imports, imp)
		}
	}
	return imports
}

func buildExec(target string, origin string) error {
	cmd := exec.Command("go", "build", "-o", target, origin)
	return cmd.Run()
}

func buildShell(workdir, exec string) (string, error) {
	sh, err := os.OpenFile(fmt.Sprintf("%s/run.sh", workdir), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return "", nil
	}
	res := fmt.Sprintf(types.GoShell, exec)
	_, err = sh.WriteString(res)

	return sh.Name(), err
}

func runDocker(ctx context.Context, limit *types.Limit, workdir string) error {
	args := buildDockerArgs(limit)
	defaultArgs := []string{"run", "--rm", "-v", fmt.Sprintf("%s:/app", workdir)}

	args = append(args, defaultArgs...)
	args = append(args, types.GoImage)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func buildDockerArgs(limit *types.Limit) []string {
	args := make([]string, 0, 5)

	//  MB -> m
	memStr := fmt.Sprintf("%dm", limit.MemoryLimit)
	args = append(args, "--memory="+memStr)

	// address space limit (byte)
	asLimit := limit.MemoryLimit * 1024 * 1024
	args = append(args, "--ulimit", fmt.Sprintf("as=%d", asLimit))

	args = append(args, "--pids-limit=1")

	// cpu time limit (s)
	cpuSeconds := int(math.Ceil(float64(limit.TimeLimit) / 1000))
	args = append(args, "--ulimit", fmt.Sprintf("cpu=%d", cpuSeconds))

	// Estimated number of CPU cores available (rough), e.g. 1 sec / 2 sec = 0.5 cores
	// optional： Trying to get tighter control of the CPU
	//if cpuSeconds > 0 {
	//	cpuQuota := cpuSeconds * 100000 // 100ms = 100000 us
	//	args = append(args, "--cpu-period=100000", fmt.Sprintf("--cpu-quota=%d", cpuQuota))
	//	args = append(args, fmt.Sprintf("--cpus=%.2f", float64(limit.TimeLimit)/2000.0))
	//}

	return args
}

func parseStatsFile(workdir string) map[string]string {
	content, _ := os.ReadFile(fmt.Sprintf("%s/stats.txt", workdir))
	lines := strings.Split(string(content), "\n")
	stats := make(map[string]string)
	for _, line := range lines {
		if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			stats[key] = val
		}
	}
	return stats
}

func verifyResult() error {
	return nil
}
