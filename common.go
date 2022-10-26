package sanitize

import (
	"reflect"
	"unsafe"
)

func GetUnexportedField(field reflect.Value) reflect.Value {
	if !field.CanAddr() {
		return field
	}
	if field.Kind() == reflect.Ptr && !field.IsNil() {
		field = field.Elem()
	}
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
}

func SetField(field reflect.Value, value interface{}) {
	if !field.CanInterface() {
		field = GetUnexportedField(field)
	}
	field.Set(reflect.ValueOf(value))
}
