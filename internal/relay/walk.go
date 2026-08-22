package relay

import "reflect"

// streamDirection selects the side of a split FDStream that a capability
// applies to. streamBoth is used only for capabilities, such as explicit
// polling, that need to inspect the whole endpoint.
type streamDirection uint8

const (
	streamRead streamDirection = iota
	streamWrite
	streamBoth
)

// maxStreamWalkNodes is only a final guard for pathological, non-comparable
// value wrappers that manufacture a fresh wrapper on every unwrap. Comparable
// wrappers, including the pointer wrappers used by the relay, are stopped by
// the cycle detector instead of an arbitrary nesting limit.
const maxStreamWalkNodes = 1024

// walkStreamCapabilities traverses a wrapper graph until visit reports that
// it found the requested capability. It is shared by deadline, polling, FD,
// and zero-copy discovery so every path has the same ordering and cycle
// protection. children controls which wrappers are safe to unwrap for the
// specific capability.
func walkStreamCapabilities(root any, visit func(any) bool, children func(any) []any) bool {
	stack := []any{root}
	seen := make(map[any]struct{})
	for visited := 0; len(stack) > 0 && visited < maxStreamWalkNodes; visited++ {
		last := len(stack) - 1
		value := stack[last]
		stack = stack[:last]
		if streamWalkValueIsNil(value) {
			continue
		}

		rv := reflect.ValueOf(value)
		if rv.Comparable() {
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
		}

		if visit(value) {
			return true
		}
		next := children(value)
		// Push in reverse so children are visited in their declared order.
		for i := len(next) - 1; i >= 0; i-- {
			stack = append(stack, next[i])
		}
	}
	return false
}

func streamWalkValueIsNil(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func regularStreamChildren(value any, direction streamDirection) []any {
	if unwrapped, ok := value.(interface{ UnwrapStream() Stream }); ok {
		return []any{unwrapped.UnwrapStream()}
	}
	return splitStreamChildren(value, direction)
}

func splitStreamChildren(value any, direction streamDirection) []any {
	switch stream := value.(type) {
	case FDStream:
		switch direction {
		case streamRead:
			return []any{stream.R}
		case streamWrite:
			return []any{stream.W}
		default:
			return []any{stream.R, stream.W}
		}
	case NetStream:
		return []any{stream.Conn}
	case RWCStream:
		return []any{stream.ReadWriteCloser}
	default:
		return nil
	}
}

func zeroCopyStreamChildren(value any, direction streamDirection) []any {
	if unwrapped, ok := value.(interface{ UnwrapZeroCopyStream() Stream }); ok {
		return []any{unwrapped.UnwrapZeroCopyStream()}
	}
	return splitStreamChildren(value, direction)
}
