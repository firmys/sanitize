package sanitize

import (
	"fmt"
	"reflect"
)

// sanitizeInt32Field sanitizes a int32 field. Requires the whole
// reflect.Value for the struct because it needs access to both the Value and
// Type of the struct.
func sanitizeInt32Field(s Sanitizer, structValue reflect.Value, idx int) error {
	fieldValue := GetUnexportedField(structValue.Field(idx))

	tags := s.fieldTags(structValue.Type().Field(idx).Tag)

	if fieldValue.Kind() == reflect.Ptr && !fieldValue.IsNil() {
		fieldValue = fieldValue.Elem()
	}

	isSlice := fieldValue.Kind() == reflect.Slice

	var fields []reflect.Value
	if !isSlice {
		fields = []reflect.Value{fieldValue}
	} else {
		for i := 0; i < fieldValue.Len(); i++ {
			fields = append(fields, fieldValue.Index(i))
		}
	}

	var err error

	// Minimum value
	_, hasMin := tags["min"]
	min := int32(0)
	if hasMin {
		min, err = parseInt32(tags["min"])
		if err != nil {
			return err
		}
	}

	// Maximum value
	_, hasMax := tags["max"]
	max := int32(0)
	if hasMax {
		max, err = parseInt32(tags["max"])
		if err != nil {
			return err
		}
	}

	// Checking if minimum is not higher than maximum
	if hasMax && hasMin && max < min {
		return fmt.Errorf(
			"max less than min on int32 field '%s' during struct sanitization",
			fieldValue.Type().Name(),
		)
	}
	// Checking if minimum and maximum are above 0
	if (hasMin && min < 0) || (hasMax && max < 0) {
		return fmt.Errorf(
			"min and max on int32 field '%s' can not be below 0",
			fieldValue.Type().Name(),
		)
	}

	// Default value
	_, hasDef := tags["def"]
	def := int32(0)
	if hasDef {
		def, err = parseInt32(tags["def"])
		if err != nil {
			return err
		}

		// Making sure default is not smaller than min or higher than max
		if hasMax && def > max {
			return fmt.Errorf(
				"incompatible def and max tag components, def (%+v) is "+
					"higher than max (%+v)",
				def,
				max,
			)
		}
		if hasMin && def < min {
			return fmt.Errorf(
				"incompatible def and min tag components, def (%+v) is "+
					"lower than min (%+v)",
				def,
				min,
			)
		}
	}

	for _, field := range fields {
		isPtr := field.Kind() == reflect.Ptr

		// Pointer, nil, and we have a default: set it
		if isPtr && field.IsNil() && hasDef {
			field.Set(reflect.ValueOf(&def))
			return nil
		}

		// Pointer, nil, and no default
		if isPtr && field.IsNil() && !hasDef {
			return nil
		}

		// Not nil pointer. Dereference then continue as normal
		if isPtr && !field.IsNil() {
			field = field.Elem()
		}

		// Apply min and max transforms
		if hasMin {
			oldNum := field.Int()
			if min > int32(oldNum) {
				field.SetInt(int64(min))
			}
		}
		if hasMax {
			oldNum := field.Int()
			if max < int32(oldNum) {
				field.SetInt(int64(max))
			}
		}
	}

	return nil
}
