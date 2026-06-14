package main
import (
	"bytes"
	"fmt"
)
func main() {
	data := []byte("\x1b[A \x1b[B \x1b[@k")
	var buf bytes.Buffer
	for _, r := range string(data) {
		switch r {
		case '"':  buf.WriteString(`\"`)
		case '\\': buf.WriteString(`\\`)
		case '\b': buf.WriteString(`\b`)
		case '\f': buf.WriteString(`\f`)
		case '\n': buf.WriteString(`\n`)
		case '\r': buf.WriteString(`\r`)
		case '\t': buf.WriteString(`\t`)
		default:
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				fmt.Fprintf(&buf, "\\u%04x", r)
			} else if r == '\ufffd' {
				buf.WriteRune(r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	fmt.Println(buf.String())
}
