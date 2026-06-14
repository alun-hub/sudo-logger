//go:build ignore

package main

import (
	"fmt"
	"github.com/cilium/ebpf"
)

func main() {
	spec, err := LoadTestDpath()
	if err != nil {
		fmt.Println("Load error:", err)
		return
	}
	var objs TestDpathObjects
	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		fmt.Println("LoadAndAssign error:", err)
		return
	}
	fmt.Println("Success")
}
