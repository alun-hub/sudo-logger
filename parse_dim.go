package main

import (
	"fmt"
	"regexp"
)

func main() {
	text := "some text \x1b[24;80H more text \x1b[50;120f"
	re := regexp.MustCompile(`\x1b\[(\d+);(\d+)[Hf]`)
	matches := re.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		fmt.Printf("Row: %s, Col: %s\n", m[1], m[2])
	}
}
