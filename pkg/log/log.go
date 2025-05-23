package log

import (
	"fmt"
	"os"
)

func ErrPrintf(format string, a ...interface{}) {
	_, err := fmt.Fprintf(os.Stderr, format, a...)
	if err != nil {
		return
	}
}

func Printf(format string, a ...interface{}) {
	_, err := fmt.Printf(format, a...)
	if err != nil {
		return
	}
}

func ErrPrintln(a ...interface{}) {
	_, err := fmt.Fprintln(os.Stderr, a...)
	if err != nil {
		return
	}
}
