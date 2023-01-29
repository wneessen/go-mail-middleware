// SPDX-FileCopyrightText: 2023 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package log

import (
	"bytes"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, "test", LevelDebug)

	if l.p != "test" {
		t.Error("Expected prefix to be test, got ", l.p)
	}
	if l.l != LevelDebug {
		t.Error("Expected level to be LevelDebug, got ", l.l)
	}
	if l.err == nil || l.warn == nil || l.info == nil || l.debug == nil {
		t.Error("Loggers not initialized")
	}
}

func TestDebug(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, "test", LevelDebug)

	l.Debug("test")
	expected := "[test] DEBUG: test\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.l = LevelInfo
	l.Debug("test")
	if b.String() != "" {
		t.Error("Debug message was not expected to be logged")
	}
}

func TestDebugf(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, "test", LevelDebug)

	l.Debugf("test %s", "foo")
	expected := "[test] DEBUG: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.l = LevelInfo
	l.Debugf("test %s", "foo")
	if b.String() != "" {
		t.Error("Debug message was not expected to be logged")
	}
}

func TestInfo(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, "test", LevelInfo)

	l.Info("test")
	expected := "[test]  INFO: test\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.l = LevelWarn
	l.Info("test")
	if b.String() != "" {
		t.Error("Info message was not expected to be logged")
	}
}

func TestInfof(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, "test", LevelInfo)

	l.Infof("test %s", "foo")
	expected := "[test]  INFO: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.l = LevelWarn
	l.Infof("test %s", "foo")
	if b.String() != "" {
		t.Error("Info message was not expected to be logged")
	}
}

func TestWarn(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, "test", LevelWarn)

	l.Warn("test")
	expected := "[test]  WARN: test\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.l = LevelError
	l.Warn("test")
	if b.String() != "" {
		t.Error("Warn message was not expected to be logged")
	}
}

func TestWarnf(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, "test", LevelWarn)

	l.Warnf("test %s", "foo")
	expected := "[test]  WARN: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.l = LevelError
	l.Warnf("test %s", "foo")
	if b.String() != "" {
		t.Error("Warn message was not expected to be logged")
	}
}

func TestError(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, "test", LevelError)

	l.Error("test")
	expected := "[test] ERROR: test\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}
}

func TestErrorf(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, "test", LevelError)

	l.Errorf("test %s", "foo")
	expected := "[test] ERROR: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}
}
