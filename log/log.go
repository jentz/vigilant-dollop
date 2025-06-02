package log

import (
	"fmt"
	"io"
	"os"
)

// Logger holds the configuration for logging.
type Logger struct {
	verbose bool
	errOut  io.Writer
	stdOut  io.Writer
}

type Option func(*Logger)

// WithVerbose enables verbose logging.
func WithVerbose(verbose bool) Option {
	return func(l *Logger) {
		l.verbose = verbose
	}
}

// WithStderr sets the writer for error output.
func WithStderr(w io.Writer) Option {
	return func(l *Logger) {
		l.errOut = w
	}
}

// WithStdout sets the writer for standard output.
func WithStdout(w io.Writer) Option {
	return func(l *Logger) {
		l.stdOut = w
	}
}

// WithOutput sets both standard and error output writers.
func WithOutput(stdOut, errOut io.Writer) Option {
	return func(l *Logger) {
		l.stdOut = stdOut
		l.errOut = errOut
	}
}

// New creates a new Logger with the provided options.
func New(opts ...Option) *Logger {
	logger := &Logger{
		verbose: false,
		errOut:  os.Stderr,
		stdOut:  os.Stdout,
	}

	for _, opt := range opts {
		opt(logger)
	}

	return logger
}

// Printf formats and writes a message to the error output (only in verbose mode).
func (l *Logger) Printf(format string, a ...interface{}) {
	if l.verbose {
		_, _ = fmt.Fprintf(l.errOut, format, a...)
	}
}

// Println writes a message to the error output (only in verbose mode).
func (l *Logger) Println(a ...interface{}) {
	if l.verbose {
		_, _ = fmt.Fprintln(l.errOut, a...)
	}
}

// Errorf writes a formatted error message to the error output (always).
func (l *Logger) Errorf(format string, a ...interface{}) {
	_, _ = fmt.Fprintf(l.errOut, format, a...)
}

// Errorln writes an error message to the error output (always).
func (l *Logger) Errorln(a ...interface{}) {
	_, _ = fmt.Fprintln(l.errOut, a...)
}

// Outputf writes formatted output to stdout (always).
func (l *Logger) Outputf(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(l.stdOut, format, args...)
}

// Outputln writes line output to stdout (always).
func (l *Logger) Outputln(args ...interface{}) {
	_, _ = fmt.Fprintln(l.stdOut, args...)
}

// Verbosef writes formatted output to stdout (only in verbose mode)
func (l *Logger) Verbosef(format string, args ...interface{}) {
	if l.verbose {
		_, _ = fmt.Fprintf(l.stdOut, format, args...)
	}
}

// Verboseln writes line output to stdout (only in verbose mode)
func (l *Logger) Verboseln(args ...interface{}) {
	if l.verbose {
		_, _ = fmt.Fprintln(l.stdOut, args...)
	}
}

var defaultLogger = New(WithVerbose(true), WithStderr(os.Stderr), WithStdout(os.Stdout))

// SetDefaultLogger sets the default logger with the provided options.
func SetDefaultLogger(opts ...Option) {
	defaultLogger = New(opts...)
}

// Printf writes formatted output to the default logger's error output.
func Printf(format string, a ...interface{}) {
	defaultLogger.Printf(format, a...)
}

// Println writes a line to the default logger's error output.
func Println(a ...interface{}) {
	defaultLogger.Println(a...)
}

// Errorf writes a formatted error message to the default logger's error output.
func Errorf(format string, a ...interface{}) {
	defaultLogger.Errorf(format, a...)
}

// Errorln writes a line to the default logger's error output.
func Errorln(a ...interface{}) {
	defaultLogger.Errorln(a...)
}

// Outputf writes formatted output to the default logger's standard output.
func Outputf(format string, a ...interface{}) {
	defaultLogger.Outputf(format, a...)
}

// Outputln writes a line to the default logger's standard output.
func Outputln(a ...interface{}) {
	defaultLogger.Outputln(a...)
}

// Verbosef writes formatted output to the default logger's standard output.
func Verbosef(format string, a ...interface{}) {
	defaultLogger.Verbosef(format, a...)
}

// Verboseln writes a line to the default logger's standard output.
func Verboseln(a ...interface{}) {
	defaultLogger.Verboseln(a...)
}
