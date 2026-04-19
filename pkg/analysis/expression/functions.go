// pkg/analysis/expression/functions.go
package expression

import (
	"encoding/json"
	"fmt"
	"strings"
)

// callFunction dispatches function calls to their implementations
func callFunction(name string, args []Value) (Value, error) {
	switch name {
	case "contains":
		return fnContains(args)
	case "startsWith":
		return fnStartsWith(args)
	case "success":
		return fnSuccess(args)
	case "failure":
		return fnFailure(args)
	case "always":
		return fnAlways(args)
	case "canceled":
		return fnCancelled(args)
	case "fromJson", "fromJSON":
		return fnFromJson(args)
	case "toJson", "toJSON":
		return fnToJson(args)
	case "format":
		return fnFormat(args)
	case "endsWith":
		return fnEndsWith(args)
	case "join":
		return fnJoin(args)
	case "hashFiles":
		return fnHashFiles(args)
	default:
		return nil, fmt.Errorf("unknown function: %s", name)
	}
}

// fnContains checks if a contains b
func fnContains(args []Value) (Value, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("contains() requires 2 arguments, got %d", len(args))
	}

	a := args[0]
	b := args[1]

	// If a is a Wildcard, it contains anything
	if _, ok := a.(*Wildcard); ok {
		return NewBoolValue(true), nil
	}

	// String containment check
	aStr := a.String()
	bStr := b.String()
	return NewBoolValue(strings.Contains(strings.ToLower(aStr), strings.ToLower(bStr))), nil
}

// fnStartsWith checks if a starts with b
func fnStartsWith(args []Value) (Value, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("startsWith() requires 2 arguments, got %d", len(args))
	}

	a := args[0]
	b := args[1]

	// If a is a Wildcard, it can start with anything
	if _, ok := a.(*Wildcard); ok {
		return NewBoolValue(true), nil
	}

	// String prefix check
	aStr := a.String()
	bStr := b.String()
	return NewBoolValue(strings.HasPrefix(strings.ToLower(aStr), strings.ToLower(bStr))), nil
}

// fnSuccess always returns true (step always reachable after success)
func fnSuccess(args []Value) (Value, error) {
	return NewBoolValue(true), nil
}

// fnFailure always returns true (step can be reached by inducing failure)
func fnFailure(args []Value) (Value, error) {
	return NewBoolValue(true), nil
}

// fnAlways always returns true (step always reachable)
func fnAlways(args []Value) (Value, error) {
	return NewBoolValue(true), nil
}

// fnCancelled returns false (cannot be induced externally)
func fnCancelled(args []Value) (Value, error) {
	return NewBoolValue(false), nil
}

// fnFromJson parses a JSON string (taint propagates through)
func fnFromJson(args []Value) (Value, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("fromJson() requires 1 argument, got %d", len(args))
	}

	s := args[0]

	// If input is a Wildcard, output is also a Wildcard (taint propagation)
	if w, ok := s.(*Wildcard); ok {
		return w, nil
	}

	// Try to parse JSON (for now, just return the string representation)
	// In a real implementation, we'd parse into a structured value
	return NewStringValue(s.String()), nil
}

// fnToJson converts a value to JSON string
func fnToJson(args []Value) (Value, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("toJson() requires 1 argument, got %d", len(args))
	}

	v := args[0]

	if w, ok := v.(*Wildcard); ok {
		return w, nil
	}

	// Simple JSON conversion
	jsonBytes, err := json.Marshal(v.String())
	if err != nil {
		return nil, fmt.Errorf("toJson conversion failed: %w", err)
	}

	return NewStringValue(string(jsonBytes)), nil
}

// fnFormat performs string formatting
func fnFormat(args []Value) (Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("format() requires at least 1 argument")
	}

	for _, arg := range args {
		if w, ok := arg.(*Wildcard); ok {
			return w, nil
		}
	}

	formatStr := args[0].String()

	// Simple implementation: replace {0}, {1}, etc. with arguments
	result := formatStr
	for i := 1; i < len(args); i++ {
		placeholder := fmt.Sprintf("{%d}", i-1)
		result = strings.ReplaceAll(result, placeholder, args[i].String())
	}

	return NewStringValue(result), nil
}

func fnEndsWith(args []Value) (Value, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("endsWith() requires 2 arguments, got %d", len(args))
	}
	if _, ok := args[0].(*Wildcard); ok {
		return NewBoolValue(true), nil
	}
	aStr := strings.ToLower(args[0].String())
	bStr := strings.ToLower(args[1].String())
	return NewBoolValue(strings.HasSuffix(aStr, bStr)), nil
}

func fnJoin(args []Value) (Value, error) {
	if len(args) < 1 || len(args) > 2 {
		return nil, fmt.Errorf("join() requires 1-2 arguments, got %d", len(args))
	}
	for _, arg := range args {
		if w, ok := arg.(*Wildcard); ok {
			return w, nil
		}
	}
	return NewStringValue(args[0].String()), nil
}

func fnHashFiles(args []Value) (Value, error) {
	return NewStringValue("hash_placeholder"), nil
}
