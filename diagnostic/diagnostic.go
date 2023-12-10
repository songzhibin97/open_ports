package diagnostic

import (
	"fmt"
	"strings"

	"github.com/songzhibin97/go-baseutils/base/banytostring"
)

type Level int

const (
	DiagnosisLevelTrace Level = iota
	DiagnosisLevelDebug
	DiagnosisLevelInfo
	DiagnosisLevelWarn
	DiagnosisLevelError
	DiagnosisLevelFatal
)

func (x Level) String() string {
	switch x {
	case DiagnosisLevelTrace:
		return "trace"
	case DiagnosisLevelDebug:
		return "debug"
	case DiagnosisLevelInfo:
		return "info"
	case DiagnosisLevelWarn:
		return "warn"
	case DiagnosisLevelError:
		return "error"
	case DiagnosisLevelFatal:
		return "fatal"
	default:
		return "unknown"
	}
}

// ------------------------------------------------- -------------------------------------------------------------------

type Diagnostic struct {
	level   Level
	content any
}

func (x *Diagnostic) String() string {
	return fmt.Sprintf("[ %s ] ", x.Level().String()) + banytostring.ToString(x.Content())
}

func NewDiagnostic(level Level, content any) *Diagnostic {
	return &Diagnostic{
		level:   level,
		content: content,
	}
}

func NewInfoDiagnostic(content any) *Diagnostic {
	return NewDiagnostic(DiagnosisLevelInfo, content)
}

func NewWarnDiagnostic(content any) *Diagnostic {
	return NewDiagnostic(DiagnosisLevelWarn, content)
}

func NewErrorDiagnostic(content any) *Diagnostic {
	return NewDiagnostic(DiagnosisLevelError, content)
}

func NewFatalDiagnostic(content any) *Diagnostic {
	return NewDiagnostic(DiagnosisLevelFatal, content)
}

func (x *Diagnostic) Level() Level {
	return x.level
}

func (x *Diagnostic) Content() any {
	return x.content
}

// ------------------------------------------------- -------------------------------------------------------------------

// Diagnostics Represents a series of diagnostic information
type Diagnostics struct {

	// Check whether the collected diagnosis information contains ERROR or later diagnosis information
	hasError bool

	// Multiple diagnoses, and there's an order between them
	diagnostics []*Diagnostic
}

func NewDiagnostics() *Diagnostics {
	return &Diagnostics{
		diagnostics: make([]*Diagnostic, 0),
	}
}

// Add d type *Diagnostic or *Diagnostics or error
func (x *Diagnostics) Add(d any) *Diagnostics {
	if d == nil {
		return x
	}
	switch v := d.(type) {
	case *Diagnostic:
		return x.AddDiagnostic(v)
	case Diagnostic:
		return x.AddDiagnostic(&v)
	case *Diagnostics:
		return x.AddDiagnostics(v)
	case Diagnostics:
		return x.AddDiagnostics(&v)
	case error:
		return x.AddError(v)
	default:
		panic("Diagnostics add type error")
	}
}

func (x *Diagnostics) AddInfo(format string, args ...any) *Diagnostics {
	return x._append(NewInfoDiagnostic(fmt.Sprintf(format, args...)))
}

func (x *Diagnostics) AddWarn(format string, args ...any) *Diagnostics {
	return x._append(NewWarnDiagnostic(fmt.Sprintf(format, args...)))
}

func (x *Diagnostics) AddErrorMsg(format string, args ...any) *Diagnostics {
	return x._append(NewErrorDiagnostic(fmt.Sprintf(format, args...)))
}

func NewDiagnosticsAddErrorMsg(format string, args ...any) *Diagnostics {
	return NewDiagnostics().AddErrorMsg(format, args...)
}

func (x *Diagnostics) AddError(err error) *Diagnostics {
	if err == nil {
		return x
	}
	return x._append(NewErrorDiagnostic(err.Error()))
}

func (x *Diagnostics) AddFatal(format string, args ...any) *Diagnostics {
	return x._append(NewFatalDiagnostic(fmt.Sprintf(format, args...)))
}

func (x *Diagnostics) AddDiagnostics(diagnostics *Diagnostics) *Diagnostics {
	if diagnostics != nil {
		for _, diagnostic := range diagnostics.GetDiagnosticSlice() {
			x._append(diagnostic)
		}
	}
	return x
}

func (x *Diagnostics) AddDiagnostic(diagnostic *Diagnostic) *Diagnostics {
	if diagnostic != nil {
		x._append(diagnostic)
	}
	return x
}

func (x *Diagnostics) GetDiagnosticSlice() []*Diagnostic {
	return x.diagnostics
}

func (x *Diagnostics) Size() int {
	return len(x.diagnostics)
}

func (x *Diagnostics) IsEmpty() bool {
	return x.Size() == 0
}

func (x *Diagnostics) HasError() bool {
	return x.hasError
}

func (x *Diagnostics) String() string {
	return x.ToString()
}

func (x *Diagnostics) ToString() string {
	builder := strings.Builder{}
	for index, diagnostic := range x.diagnostics {
		builder.WriteString(fmt.Sprintf("[ %s ] ", diagnostic.Level().String()))
		builder.WriteString(banytostring.ToString(diagnostic.Content()))
		if index < len(x.diagnostics)-1 {
			builder.WriteString("\n")
		}
	}
	return builder.String()
}

// All additional diagnostic information must be updated using this method and cannot be added directly to the data
func (x *Diagnostics) _append(diagnostic *Diagnostic) *Diagnostics {
	if diagnostic.Level() == DiagnosisLevelError || diagnostic.Level() == DiagnosisLevelFatal {
		x.hasError = true
	}
	x.diagnostics = append(x.diagnostics, diagnostic)
	return x
}
