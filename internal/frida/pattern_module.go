package frida

/*
#include <stdlib.h>
#include <string.h>
#include <frida-core.h>

// g_str_equal cannot be referenced as a callback: since the Frida Core DevKit 17.23.3, its Linux headers rename
// GLib symbols with a '_frida_' prefix, yet '#undef g_str_equal' before defining the string comparison macro,
// so the bare name no longer resolves to the renamed function. A local comparator keeps this independent of the
// devkit.
static gboolean pattern_inputs_equal(gconstpointer a, gconstpointer b) {
  return strcmp((const gchar *) a, (const gchar *) b) == 0;
}

static GHashTable * pattern_inputs_new(void) {
  return g_hash_table_new_full(g_str_hash, pattern_inputs_equal, g_free, (GDestroyNotify) g_variant_unref);
}

static void pattern_inputs_insert(GHashTable * inputs, gchar * name, GVariant * value) {
  g_hash_table_insert(inputs, name, g_variant_ref_sink(value));
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// errPatternModuleClosed indicates that the pattern module is already closed.
var errPatternModuleClosed = errors.New("pattern module already closed")

const (
	// patternUnknown is returned for unrecognized native enum values.
	patternUnknown = "unknown"

	// maxPatternValueNodes caps the number of decoded value nodes converted per decode.
	maxPatternValueNodes = 4096
)

// PatternModule is a Pattern source compiled for one target platform and architecture.
type PatternModule struct {
	mu                sync.Mutex            // Guards module state.
	closed            bool                  // Whether native resources were released.
	handle            *C.FridaPatternModule // Native Frida Pattern module.
	typesLoaded       bool                  // Whether declared types were converted.
	types             []*PatternType        // Types declared by the compiled source.
	rootTypeLoaded    bool                  // Whether the root type name was converted.
	rootType          string                // Name of the root type, empty when absent.
	inputsLoaded      bool                  // Whether declared inputs were converted.
	inputs            []*PatternInput       // External in variables declared by the source.
	diagnosticsLoaded bool                  // Whether compiler diagnostics were converted.
	diagnostics       []*PatternDiagnostic  // Compiler diagnostics; a module is still returned despite diagnostics.
}

// newPatternModule creates a PatternModule instance around a native Pattern module handle.
func newPatternModule(handle *C.FridaPatternModule) *PatternModule {
	// Return PatternModule instance
	return &PatternModule{handle: handle}
}

// Close releases native Pattern module resources.
func (m *PatternModule) Close() {
	// Synchronize access
	m.mu.Lock()
	defer m.mu.Unlock()

	// Early exit if already closed
	if m.closed {
		return
	}

	m.closed = true

	// Clean up
	C.frida_unref(C.gpointer(unsafe.Pointer(m.handle)))
	m.handle = nil
}

// PatternType describes a type declared by a Pattern source.
type PatternType struct {
	Kind       string              `json:"kind"`                 // Declaration kind: struct, union, enum, bitfield, or alias.
	Name       string              `json:"name"`                 // Declared type name.
	Doc        string              `json:"doc,omitempty"`        // Doc comment from the source.
	File       string              `json:"file"`                 // Source file of the declaration.
	Line       uint                `json:"line"`                 // Zero-based line of the declaration.
	Character  uint                `json:"character"`            // Zero-based character (column) of the declaration.
	Size       int64               `json:"size"`                 // Computed size in bytes.
	Align      uint                `json:"align"`                // Alignment in bytes.
	Fields     []*PatternField     `json:"fields,omitempty"`     // Struct or union members.
	Underlying *PatternTypeRef     `json:"underlying,omitempty"` // Underlying reference, for example an alias's target or an enum's integer type.
	Values     []*PatternEnumValue `json:"values,omitempty"`     // Enum entries.
	Bits       []*PatternBit       `json:"bits,omitempty"`       // Bitfield members.
	Target     *PatternTypeRef     `json:"target,omitempty"`     // Target reference of the declaration, when applicable.
}

// Types returns the types declared by the compiled source, lazily converting them on first access.
func (m *PatternModule) Types() []*PatternType {
	// Synchronize access
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return nothing when the module is closed
	if m.closed {
		return nil
	}

	// Convert types on first access
	if !m.typesLoaded {
		// Get native type list
		list := C.frida_pattern_module_get_types(m.handle)

		// Convert a type for each entry
		if list != nil {
			count := int(C.frida_pattern_type_list_size(list))
			items := make([]*PatternType, 0, count)

			for index := range count {
				// Get type from list
				item := C.frida_pattern_type_list_get(list, C.gint(index))
				if item == nil {
					continue
				}

				// Append type to result slice
				items = append(items, &PatternType{
					Kind:       patternTypeKindFromNative(C.frida_pattern_type_get_kind(item)),
					Name:       C.GoString(C.frida_pattern_type_get_name(item)),
					Doc:        C.GoString(C.frida_pattern_type_get_doc(item)),
					File:       C.GoString(C.frida_pattern_type_get_file(item)),
					Line:       uint(C.frida_pattern_type_get_line(item)),
					Character:  uint(C.frida_pattern_type_get_character(item)),
					Size:       int64(C.frida_pattern_type_get_size(item)),
					Align:      uint(C.frida_pattern_type_get_align(item)),
					Fields:     patternFieldsFromNative(C.frida_pattern_type_get_fields(item)),
					Underlying: patternTypeRefFromNative(C.frida_pattern_type_get_underlying(item)),
					Values:     patternEnumValuesFromNative(C.frida_pattern_type_get_values(item)),
					Bits:       patternBitsFromNative(C.frida_pattern_type_get_bits(item)),
					Target:     patternTypeRefFromNative(C.frida_pattern_type_get_target(item)),
				})
			}

			m.types = items
		}

		m.typesLoaded = true
	}

	// Return types
	return m.types
}

// RootType returns the name of the root type, empty when absent, lazily converting it on first access.
func (m *PatternModule) RootType() string {
	// Synchronize access
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return nothing when the module is closed
	if m.closed {
		return ""
	}

	// Convert root type on first access
	if !m.rootTypeLoaded {
		m.rootType = C.GoString(C.frida_pattern_module_get_root_type(m.handle))
		m.rootTypeLoaded = true
	}

	// Return root type
	return m.rootType
}

// PatternInput describes a Pattern `in` variable.
type PatternInput struct {
	Name    string          `json:"name"`               // Name of the Pattern in variable.
	TypeRef *PatternTypeRef `json:"type_ref,omitempty"` // Declared type of the input, nil when untyped.
}

// Inputs returns the external in variables declared by the source, lazily converting them on first access.
func (m *PatternModule) Inputs() []*PatternInput {
	// Synchronize access
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return nothing when the module is closed
	if m.closed {
		return nil
	}

	// Convert inputs on first access
	if !m.inputsLoaded {
		// Get native input list
		list := C.frida_pattern_module_get_inputs(m.handle)

		// Convert an input for each entry
		if list != nil {
			count := int(C.frida_pattern_input_list_size(list))
			items := make([]*PatternInput, 0, count)

			for index := range count {
				// Get input from list
				item := C.frida_pattern_input_list_get(list, C.gint(index))
				if item == nil {
					continue
				}

				// Append input to result slice
				items = append(items, &PatternInput{
					Name:    C.GoString(C.frida_pattern_input_get_name(item)),
					TypeRef: patternTypeRefFromNative(C.frida_pattern_input_get_type_ref(item)),
				})
			}

			m.inputs = items
		}

		m.inputsLoaded = true
	}

	// Return inputs
	return m.inputs
}

// PatternDiagnostic describes a Pattern compilation problem.
type PatternDiagnostic struct {
	File      string `json:"file"`      // Relative source file of the diagnostic.
	Line      uint   `json:"line"`      // Zero-based line of the diagnostic.
	Character uint   `json:"character"` // Zero-based character (column) of the diagnostic.
	Message   string `json:"message"`   // Compiler message.
}

// Diagnostics returns the compiler diagnostics, lazily converting them on first access.
func (m *PatternModule) Diagnostics() []*PatternDiagnostic {
	// Synchronize access
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return nothing when the module is closed
	if m.closed {
		return nil
	}

	// Convert diagnostics on first access
	if !m.diagnosticsLoaded {
		// Get native diagnostic list
		list := C.frida_pattern_module_get_diagnostics(m.handle)

		// Convert a diagnostic for each entry
		if list != nil {
			count := int(C.frida_pattern_diagnostic_list_size(list))
			items := make([]*PatternDiagnostic, 0, count)

			for index := range count {
				// Get diagnostic from list
				item := C.frida_pattern_diagnostic_list_get(list, C.gint(index))
				if item == nil {
					continue
				}

				// Append diagnostic to result slice
				items = append(items, &PatternDiagnostic{
					File:      C.GoString(C.frida_pattern_diagnostic_get_file(item)),
					Line:      uint(C.frida_pattern_diagnostic_get_line(item)),
					Character: uint(C.frida_pattern_diagnostic_get_character(item)),
					Message:   C.GoString(C.frida_pattern_diagnostic_get_message(item)),
				})
			}

			m.diagnostics = items
		}

		m.diagnosticsLoaded = true
	}

	// Return diagnostics
	return m.diagnostics
}

// PatternDecodeOption configures a Pattern decode.
type PatternDecodeOption func(*patternDecodeOptions)

// patternDecodeOptions holds the options for a PatternModule.Decode call.
type patternDecodeOptions struct {
	maxNodes int // Maximum decoded value nodes converted, zero for the default.
}

// WithPatternDecodeMaxNodes sets the maximum number of value nodes converted per decode.
func WithPatternDecodeMaxNodes(maxNodes int) PatternDecodeOption {
	return func(options *patternDecodeOptions) { options.maxNodes = maxNodes }
}

// PatternValue is one node in a decoded Pattern tree.
type PatternValue struct {
	ID          uint            // Unique identifier of the node within the decoded tree.
	Name        string          // Field or element name.
	TypeName    string          // Name of the decoded type.
	Address     uint64          // Absolute target address of the value.
	Offset      uint64          // Byte offset within the decoded snapshot.
	Size        int64           // Size in bytes of the value.
	Value       any             // Decoded scalar value, nil for composite values.
	Label       string          // Presentation label from the source.
	DisplayName string          // Display name overriding the field name.
	Formatted   string          // Formatted rendering of the scalar value.
	Comment     string          // Comment from the source.
	Color       string          // Presentation color from the source.
	Hidden      bool            // Whether the value is hidden from presentation.
	Inlined     bool            // Whether the value is inlined into its parent.
	Sealed      bool            // Whether the value cannot be expanded further.
	BitOffset   int             // Bit offset within the storage unit, for bitfield members.
	Bits        uint            // Bit width, for bitfield members.
	Count       int64           // Number of elements, for arrays.
	Fields      []*PatternValue // Child values of struct or union members.
	Elements    []*PatternValue // Child values of array elements.
	Truncated   bool            // Whether the value's contents were truncated.
	Section     uint64          // Memory section identifier containing the value, zero when unknown.
	Capped      bool            // Whether decoding this subtree hit the node or data budget.
}

// Decode decodes data read from address as the requested Pattern type.
func (m *PatternModule) Decode(ctx context.Context, typeName string, data []byte, address uint64, inputs map[string]any, opts ...PatternDecodeOption) (*PatternValue, error) {
	// Validate input
	if typeName == "" {
		return nil, errors.New("pattern type required")
	}

	// Assemble options
	config := patternDecodeOptions{maxNodes: maxPatternValueNodes}

	for _, opt := range opts {
		opt(&config)
	}

	if config.maxNodes < 0 {
		return nil, errors.New("max nodes must not be negative")
	}

	// Synchronize access
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if pattern module is already closed
	if m.closed {
		return nil, errPatternModuleClosed
	}

	// Create native snapshot
	var rawData *C.GBytes

	if len(data) == 0 {
		rawData = C.g_bytes_new(nil, 0)
	} else {
		rawData = C.g_bytes_new(C.gconstpointer(unsafe.Pointer(&data[0])), C.gsize(len(data)))
	}

	defer C.g_bytes_unref(rawData)

	// Assemble decode options
	var options *C.FridaPatternDecodeOptions

	if len(inputs) != 0 {
		// Create decode options
		options = C.frida_pattern_decode_options_new()
		if options == nil {
			return nil, errors.New("failed to create pattern decode options")
		}

		defer C.frida_unref(C.gpointer(unsafe.Pointer(options)))

		// Create input table
		table := C.pattern_inputs_new()
		if table == nil {
			return nil, errors.New("failed to create pattern inputs")
		}

		defer C.g_hash_table_destroy(table)

		// Insert inputs
		for name, value := range inputs {
			// Validate input name
			if name == "" {
				return nil, errors.New("pattern input name required")
			}

			// Convert input value based on its Go type
			var variant *C.GVariant

			switch typed := value.(type) {
			case bool:
				// GVariant boolean
				if typed {
					variant = C.g_variant_new_boolean(1)
				} else {
					variant = C.g_variant_new_boolean(0)
				}
			case string:
				// GVariant string
				cValue := C.CString(typed)
				defer C.free(unsafe.Pointer(cValue))
				variant = C.g_variant_new_string(cValue)
			case int32:
				// GVariant int32
				variant = C.g_variant_new_int32(C.gint32(typed))
			case uint32:
				// GVariant uint32
				variant = C.g_variant_new_uint32(C.guint32(typed))
			case int64:
				// GVariant int64
				variant = C.g_variant_new_int64(C.gint64(typed))
			case uint64:
				// GVariant uint64
				variant = C.g_variant_new_uint64(C.guint64(typed))
			case float64:
				// GVariant double
				variant = C.g_variant_new_double(C.gdouble(typed))
			default:
				// Unsupported input type
				return nil, fmt.Errorf("unsupported pattern input [name=%s]: %T", name, value)
			}

			// Insert input
			C.pattern_inputs_insert(
				table,
				C.CString(name),
				variant,
			)
		}

		// Attach inputs
		C.frida_pattern_decode_options_set_inputs(options, table)
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Decode value
	var gErr *C.GError

	cTypeName := C.CString(typeName)
	defer C.free(unsafe.Pointer(cTypeName))

	value := C.frida_pattern_module_decode_sync(
		m.handle,
		cTypeName,
		rawData,
		C.guint64(address),
		options,
		cancellable,
		&gErr,
	)

	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("decode pattern: %w", err)
	}

	if value == nil {
		return nil, errors.New("decode pattern: empty")
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(value)))

	// Convert value
	result, _ := patternValueFromNative(value, &config.maxNodes)

	return result, nil
}

// PatternField describes a struct or union field.
type PatternField struct {
	Name            string          `json:"name"`                        // Field name.
	Doc             string          `json:"doc,omitempty"`               // Doc comment from the source.
	Hidden          bool            `json:"hidden,omitempty"`            // Whether the field is hidden from presentation.
	Conditional     bool            `json:"conditional,omitempty"`       // Whether the field's presence is conditional.
	NoUniqueAddress bool            `json:"no_unique_address,omitempty"` // Whether the field may share storage, like C++ [[no_unique_address]].
	TypeRef         *PatternTypeRef `json:"type_ref,omitempty"`          // Declared type of the field.
	Offset          int64           `json:"offset"`                      // Byte offset within the parent struct or union.
	Size            int64           `json:"size"`                        // Size in bytes of the field.
}

// patternFieldsFromNative converts a native field list into Pattern fields.
func patternFieldsFromNative(list *C.FridaPatternFieldList) []*PatternField {
	// Early exit on missing list
	if list == nil {
		return nil
	}

	// Create a field for each entry
	count := int(C.frida_pattern_field_list_size(list))
	items := make([]*PatternField, 0, count)

	for index := range count {
		// Get field from list
		item := C.frida_pattern_field_list_get(list, C.gint(index))
		if item == nil {
			continue
		}

		// Append field to result slice
		items = append(items, &PatternField{
			Name:            C.GoString(C.frida_pattern_field_get_name(item)),
			Doc:             C.GoString(C.frida_pattern_field_get_doc(item)),
			Hidden:          C.frida_pattern_field_get_hidden(item) != 0,
			Conditional:     C.frida_pattern_field_get_conditional(item) != 0,
			NoUniqueAddress: C.frida_pattern_field_get_no_unique_address(item) != 0,
			TypeRef:         patternTypeRefFromNative(C.frida_pattern_field_get_type_ref(item)),
			Offset:          int64(C.frida_pattern_field_get_offset(item)),
			Size:            int64(C.frida_pattern_field_get_size(item)),
		})
	}

	return items
}

// PatternEnumValue describes a named enum value or range.
type PatternEnumValue struct {
	Name  string `json:"name"`          // Entry name.
	Doc   string `json:"doc,omitempty"` // Doc comment from the source.
	Value int64  `json:"value"`         // First value of the entry.
	Last  int64  `json:"last"`          // Last value of the entry, for value ranges.
}

// patternEnumValuesFromNative converts a native enum value list into Pattern enum values.
func patternEnumValuesFromNative(list *C.FridaPatternEnumValueList) []*PatternEnumValue {
	// Early exit on missing list
	if list == nil {
		return nil
	}

	// Create an enum value for each entry
	count := int(C.frida_pattern_enum_value_list_size(list))
	items := make([]*PatternEnumValue, 0, count)

	for index := range count {
		// Get enum value from list
		item := C.frida_pattern_enum_value_list_get(list, C.gint(index))
		if item == nil {
			continue
		}

		// Append enum value to result slice
		items = append(items, &PatternEnumValue{
			Name:  C.GoString(C.frida_pattern_enum_value_get_name(item)),
			Doc:   C.GoString(C.frida_pattern_enum_value_get_doc(item)),
			Value: int64(C.frida_pattern_enum_value_get_value(item)),
			Last:  int64(C.frida_pattern_enum_value_get_last(item)),
		})
	}

	return items
}

// PatternBit describes a bitfield member.
type PatternBit struct {
	Name     string `json:"name"`                // Member name.
	Doc      string `json:"doc,omitempty"`       // Doc comment from the source.
	Kind     string `json:"kind"`                // Member kind: unsigned, signed, bool, or enum.
	Offset   uint   `json:"offset"`              // Bit offset within the storage unit.
	Bits     uint   `json:"bits"`                // Bit width of the member.
	EnumName string `json:"enum_name,omitempty"` // Referenced enum type name, for enum members.
}

// patternBitsFromNative converts a native bit list into Pattern bits.
func patternBitsFromNative(list *C.FridaPatternBitList) []*PatternBit {
	// Early exit on missing list
	if list == nil {
		return nil
	}

	// Create a bit for each entry
	count := int(C.frida_pattern_bit_list_size(list))
	items := make([]*PatternBit, 0, count)

	for index := range count {
		// Get bit from list
		item := C.frida_pattern_bit_list_get(list, C.gint(index))
		if item == nil {
			continue
		}

		// Append bit to result slice
		items = append(items, &PatternBit{
			Name:     C.GoString(C.frida_pattern_bit_get_name(item)),
			Doc:      C.GoString(C.frida_pattern_bit_get_doc(item)),
			Kind:     patternBitKindFromNative(C.frida_pattern_bit_get_kind(item)),
			Offset:   uint(C.frida_pattern_bit_get_offset(item)),
			Bits:     uint(C.frida_pattern_bit_get_bits(item)),
			EnumName: C.GoString(C.frida_pattern_bit_get_enum_name(item)),
		})
	}

	return items
}

// PatternTypeRef describes a type used by a Pattern declaration.
type PatternTypeRef struct {
	Kind           string          `json:"kind"`                      // Reference kind: primitive, named, pointer, array, or padding.
	Display        string          `json:"display"`                   // Human-readable rendering of the reference.
	Name           string          `json:"name,omitempty"`            // Type name, for primitive and named references.
	Order          string          `json:"order"`                     // Byte order: native, little, or big.
	Target         *PatternTypeRef `json:"target,omitempty"`          // Target reference, for example the pointee of a pointer.
	Width          *PatternTypeRef `json:"width,omitempty"`           // Width reference, for example the integer type backing a pointer.
	Element        *PatternTypeRef `json:"element,omitempty"`         // Element reference, for arrays.
	Length         int64           `json:"length"`                    // Number of elements, for arrays.
	NullTerminated bool            `json:"null_terminated,omitempty"` // Whether the array is null-terminated.
	Size           int64           `json:"size"`                      // Size in bytes of the referenced type.
}

// patternTypeRefFromNative converts a native type reference into a PatternTypeRef.
func patternTypeRefFromNative(value *C.FridaPatternTypeRef) *PatternTypeRef {
	// Early exit on missing list
	if value == nil {
		return nil
	}

	// Convert reference
	return &PatternTypeRef{
		Kind:           patternTypeRefKindFromNative(C.frida_pattern_type_ref_get_kind(value)),
		Display:        C.GoString(C.frida_pattern_type_ref_get_display(value)),
		Name:           C.GoString(C.frida_pattern_type_ref_get_name(value)),
		Order:          patternByteOrderFromNative(C.frida_pattern_type_ref_get_order(value)),
		Target:         patternTypeRefFromNative(C.frida_pattern_type_ref_get_target(value)),
		Width:          patternTypeRefFromNative(C.frida_pattern_type_ref_get_width(value)),
		Element:        patternTypeRefFromNative(C.frida_pattern_type_ref_get_element(value)),
		Length:         int64(C.frida_pattern_type_ref_get_length(value)),
		NullTerminated: C.frida_pattern_type_ref_get_null_terminated(value) != 0,
		Size:           int64(C.frida_pattern_type_ref_get_size(value)),
	}
}

// patternValueFromNative converts a native value node into a PatternValue, reporting whether the node budget
// was exhausted.
func patternValueFromNative(value *C.FridaPatternValue, budget *int) (*PatternValue, bool) {
	// Respect remaining budget
	if *budget == 0 {
		return &PatternValue{Capped: true}, true
	}

	*budget--

	// Convert fields
	fields, fieldsCapped := patternValueSliceFromNative(C.frida_pattern_value_get_fields(value), budget)
	if fieldsCapped {
		return &PatternValue{Capped: true}, true
	}

	// Convert elements
	elements, elementsCapped := patternValueSliceFromNative(C.frida_pattern_value_get_elements(value), budget)
	if elementsCapped {
		return &PatternValue{Capped: true}, true
	}

	// Convert value
	return &PatternValue{
		ID:          uint(C.frida_pattern_value_get_id(value)),
		Name:        C.GoString(C.frida_pattern_value_get_name(value)),
		TypeName:    C.GoString(C.frida_pattern_value_get_type_name(value)),
		Address:     uint64(C.frida_pattern_value_get_address(value)),
		Offset:      uint64(C.frida_pattern_value_get_offset(value)),
		Size:        int64(C.frida_pattern_value_get_size(value)),
		Value:       valueFromVariant(C.frida_pattern_value_get_value(value)),
		Label:       C.GoString(C.frida_pattern_value_get_label(value)),
		DisplayName: C.GoString(C.frida_pattern_value_get_display_name(value)),
		Formatted:   C.GoString(C.frida_pattern_value_get_formatted(value)),
		Comment:     C.GoString(C.frida_pattern_value_get_comment(value)),
		Color:       C.GoString(C.frida_pattern_value_get_color(value)),
		Hidden:      C.frida_pattern_value_get_hidden(value) != 0,
		Inlined:     C.frida_pattern_value_get_inlined(value) != 0,
		Sealed:      C.frida_pattern_value_get_sealed(value) != 0,
		BitOffset:   int(C.frida_pattern_value_get_bit_offset(value)),
		Bits:        uint(C.frida_pattern_value_get_bits(value)),
		Count:       int64(C.frida_pattern_value_get_count(value)),
		Fields:      fields,
		Elements:    elements,
		Truncated:   C.frida_pattern_value_get_truncated(value) != 0,
		Section:     uint64(C.frida_pattern_value_get_section(value)),
		Capped:      false,
	}, false
}

// patternValueSliceFromNative converts a native value list into Pattern values, reporting whether the node
// budget was exhausted.
func patternValueSliceFromNative(list *C.FridaPatternValueList, budget *int) ([]*PatternValue, bool) {
	// Early exit on missing list
	if list == nil {
		return nil, false
	}

	// Create a value for each entry within budget
	count := int(C.frida_pattern_value_list_size(list))
	items := make([]*PatternValue, 0)

	for index := range count {
		// Stop when the budget is exhausted
		if *budget == 0 {
			return items, true
		}

		// Get value from list
		item := C.frida_pattern_value_list_get(list, C.gint(index))
		if item != nil {
			// Convert value
			decoded, capped := patternValueFromNative(item, budget)
			items = append(items, decoded)
			if capped {
				return items, true
			}
		}
	}

	return items, false
}

// patternTypeKindFromNative converts a native Pattern type kind to its string representation.
func patternTypeKindFromNative(value C.FridaPatternTypeKind) string {
	switch value {
	case C.FRIDA_PATTERN_TYPE_KIND_STRUCT:
		return "struct"
	case C.FRIDA_PATTERN_TYPE_KIND_UNION:
		return "union"
	case C.FRIDA_PATTERN_TYPE_KIND_ENUM:
		return "enum"
	case C.FRIDA_PATTERN_TYPE_KIND_BITFIELD:
		return "bitfield"
	case C.FRIDA_PATTERN_TYPE_KIND_ALIAS:
		return "alias"
	default:
		return patternUnknown
	}
}

// patternTypeRefKindFromNative converts a native Pattern type reference kind to its string representation.
func patternTypeRefKindFromNative(value C.FridaPatternTypeRefKind) string {
	switch value {
	case C.FRIDA_PATTERN_TYPE_REF_KIND_PRIMITIVE:
		return "primitive"
	case C.FRIDA_PATTERN_TYPE_REF_KIND_NAMED:
		return "named"
	case C.FRIDA_PATTERN_TYPE_REF_KIND_POINTER:
		return "pointer"
	case C.FRIDA_PATTERN_TYPE_REF_KIND_ARRAY:
		return "array"
	case C.FRIDA_PATTERN_TYPE_REF_KIND_PADDING:
		return "padding"
	default:
		return patternUnknown
	}
}

// patternByteOrderFromNative converts a native byte order to its string representation.
func patternByteOrderFromNative(value C.FridaPatternByteOrder) string {
	switch value {
	case C.FRIDA_PATTERN_BYTE_ORDER_NATIVE:
		return "native"
	case C.FRIDA_PATTERN_BYTE_ORDER_LITTLE:
		return "little"
	case C.FRIDA_PATTERN_BYTE_ORDER_BIG:
		return "big"
	default:
		return patternUnknown
	}
}

// patternBitKindFromNative converts a native bitfield member kind to its string representation.
func patternBitKindFromNative(value C.FridaPatternBitKind) string {
	switch value {
	case C.FRIDA_PATTERN_BIT_KIND_UNSIGNED:
		return "unsigned"
	case C.FRIDA_PATTERN_BIT_KIND_SIGNED:
		return "signed"
	case C.FRIDA_PATTERN_BIT_KIND_BOOL:
		return "bool"
	case C.FRIDA_PATTERN_BIT_KIND_ENUM:
		return "enum"
	default:
		return patternUnknown
	}
}
