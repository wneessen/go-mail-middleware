// SPDX-FileCopyrightText: 2023 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package log implements a convenient wrapper for the Go stdlib log.Logger that can
// used in the different go-mail-middleware modules
package log

import (
	"fmt"
	"io"
	"log"
)

// Level is a type wrapper for an int
type Level int

// Logger represents the main Logger type
type Logger struct {
	p     string
	l     Level
	err   *log.Logger
	warn  *log.Logger
	info  *log.Logger
	debug *log.Logger
}

const (
	// LevelError is the Level for only ERROR log messages
	LevelError Level = iota
	// LevelWarn is the Level for WARN and higher log messages
	LevelWarn
	// LevelInfo is the Level for INFO and higher log messages
	LevelInfo
	// LevelDebug is the Level for DEBUG and higher log messages
	LevelDebug
)

// New returns a new log.Logger type for the corresponding Middleware to use
func New(o io.Writer, p string, l Level) *Logger {
	lf := log.Lmsgprefix | log.LstdFlags
	return &Logger{
		l:     l,
		p:     p,
		err:   log.New(o, fmt.Sprintf("[%s] ERROR: ", p), lf),
		warn:  log.New(o, fmt.Sprintf("[%s]  WARN: ", p), lf),
		info:  log.New(o, fmt.Sprintf("[%s]  INFO: ", p), lf),
		debug: log.New(o, fmt.Sprintf("[%s] DEBUG: ", p), lf),
	}
}

// Debug performs a print() on the debug logger
func (l *Logger) Debug(v ...interface{}) {
	if l.l >= LevelDebug {
		_ = l.debug.Output(2, fmt.Sprint(v...))
	}
}

// Info performs a print() on the info logger
func (l *Logger) Info(v ...interface{}) {
	if l.l >= LevelInfo {
		_ = l.info.Output(2, fmt.Sprint(v...))
	}
}

// Warn performs a print() on the warn logger
func (l *Logger) Warn(v ...interface{}) {
	if l.l >= LevelWarn {
		_ = l.warn.Output(2, fmt.Sprint(v...))
	}
}

// Error performs a print() on the error logger
func (l *Logger) Error(v ...interface{}) {
	if l.l >= LevelError {
		_ = l.err.Output(2, fmt.Sprint(v...))
	}
}

// Debugf performs a Printf() on the debug logger
func (l *Logger) Debugf(f string, v ...interface{}) {
	if l.l >= LevelDebug {
		_ = l.debug.Output(2, fmt.Sprintf(f, v...))
	}
}

// Infof performs a Printf() on the info logger
func (l *Logger) Infof(f string, v ...interface{}) {
	if l.l >= LevelInfo {
		_ = l.info.Output(2, fmt.Sprintf(f, v...))
	}
}

// Warnf performs a Printf() on the warn logger
func (l *Logger) Warnf(f string, v ...interface{}) {
	if l.l >= LevelWarn {
		_ = l.warn.Output(2, fmt.Sprintf(f, v...))
	}
}

// Errorf performs a Printf() on the error logger
func (l *Logger) Errorf(f string, v ...interface{}) {
	if l.l >= LevelError {
		_ = l.err.Output(2, fmt.Sprintf(f, v...))
	}
}
