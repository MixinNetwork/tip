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

func Errorf(format string, v ...any) {
	printfAtLevel(ERROR, format, v...)
}

func Error(v ...any) {
	printAtLevel(ERROR, v...)
}

func Infof(format string, v ...any) {
	printfAtLevel(INFO, format, v...)
}

func Info(v ...any) {
	printAtLevel(INFO, v...)
}

func Verbosef(format string, v ...any) {
	printfAtLevel(VERBOSE, format, v...)
}

func Verbose(v ...any) {
	printAtLevel(VERBOSE, v...)
}

func Debugf(format string, v ...any) {
	printfAtLevel(DEBUG, format, v...)
}

func Debug(v ...any) {
	printAtLevel(DEBUG, v...)
}

func printfAtLevel(l int, format string, v ...any) {
	if level < l {
		return
	}
	out := fmt.Sprintf(format, v...)
	log.Print(out)
}

func printAtLevel(l int, v ...any) {
	if level < l {
		return
	}
	log.Println(v...)
}
