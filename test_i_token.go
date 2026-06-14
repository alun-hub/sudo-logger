package main

import (
	"bytes"
	"fmt"
)

func main() {
	line1 := []byte(`[0.523, "i", "@k"]`)
	line2 := []byte(`[0.523,"i","@k"]`)
	iToken := []byte(`,"i",`)

	fmt.Printf("line1 contains iToken: %v\n", bytes.Contains(line1, iToken))
	fmt.Printf("line2 contains iToken: %v\n", bytes.Contains(line2, iToken))
}
