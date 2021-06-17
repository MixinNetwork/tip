package logger

import (
	"fmt"
	"log"
)

const (
	ERROR   = 1
	INFO    = 2
	VERBOSE = 3
	DEBUG   = 7
)

var (
	level = DEBUG
)

func SetLevel(l int) {
	level = l
}

func Errorf(format string, v ...interface{}) {
	printfAtLevel(ERROR, format, v...)
}

func Infof(format string, v ...interface{}) {
	printfAtLevel(INFO, format, v...)
}

func Verbosef(format string, v ...interface{}) {
	printfAtLevel(VERBOSE, format, v...)
}

func Verbose(v ...interface{}) {
	printAtLevel(VERBOSE, v...)
}

func Debugf(format string, v ...interface{}) {
	printfAtLevel(DEBUG, format, v...)
}

func printfAtLevel(l int, format string, v ...interface{}) {
	if level < l {
		return
	}
	out := fmt.Sprintf(format, v...)
	log.Print(out)
}

func printAtLevel(l int, v ...interface{}) {
	if level < l {
		return
	}
	log.Println(v...)
}
