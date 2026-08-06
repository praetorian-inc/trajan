package detect

import (
	"fmt"

	"github.com/praetorian-inc/trajan/internal/dsl"
)

// Empty all_of → true, empty any_of → false, empty none_of → true; the keys that
// are present are conjoined.
func evaluateBlock(block *Block, subject any) (bool, error) {
	if block == nil {
		return true, nil
	}
	if !block.IsCombo {
		return dsl.EvaluatePredicate(block.Predicate, subject)
	}
	if block.AllOf == nil && block.AnyOf == nil && block.NoneOf == nil {
		return false, fmt.Errorf("block has no all_of/any_of/none_of")
	}
	result := true
	if block.AllOf != nil {
		for i := range block.AllOf {
			ok, err := evaluateBlock(&block.AllOf[i], subject)
			if err != nil {
				return false, err
			}
			if !ok {
				result = false
				break
			}
		}
	}
	if result && block.AnyOf != nil {
		matched := false
		for i := range block.AnyOf {
			ok, err := evaluateBlock(&block.AnyOf[i], subject)
			if err != nil {
				return false, err
			}
			if ok {
				matched = true
				break
			}
		}
		result = result && matched
	}
	if result && block.NoneOf != nil {
		none := true
		for i := range block.NoneOf {
			ok, err := evaluateBlock(&block.NoneOf[i], subject)
			if err != nil {
				return false, err
			}
			if ok {
				none = false
				break
			}
		}
		result = result && none
	}
	return result, nil
}
