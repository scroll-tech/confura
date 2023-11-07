package types

import (
	"encoding/json"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

// Errors
var (
	ErrMissingPrefix = &decError{"hex string without 0x prefix"}
	ErrEmptyNumber   = &decError{"hex string \"0x\""}
)

type decError struct{ msg string }

func (err decError) Error() string { return err.msg }

var locationT = reflect.TypeOf((*Location)(nil))

// Location is the same as hexutil.Big but support numbers with leading zeros too.
type Location big.Int

// MarshalText implements encoding.TextMarshaler
func (l Location) MarshalText() ([]byte, error) {
	return []byte(hexutil.EncodeBig((*big.Int)(&l))), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (l *Location) UnmarshalJSON(input []byte) error {
	if !isString(input) {
		return errNonString(locationT)
	}
	return wrapTypeError(l.UnmarshalText(input[1:len(input)-1]), locationT)
}

// UnmarshalText implements encoding.TextUnmarshaler
func (l *Location) UnmarshalText(input []byte) error {
	raw, err := removeLeadingZeros(input)
	if err != nil {
		return err
	}

	var b hexutil.Big
	err = b.UnmarshalText(raw)
	if err != nil {
		return err
	}
	*l = (Location)(b)
	return nil
}

// ToInt converts l to a big.Int.
func (l *Location) ToInt() *big.Int {
	return (*big.Int)(l)
}

// String returns the hex encoding of l.
func (l *Location) String() string {
	return hexutil.EncodeBig(l.ToInt())
}

func isString(input []byte) bool {
	return len(input) >= 2 && input[0] == '"' && input[len(input)-1] == '"'
}

func bytesHave0xPrefix(input []byte) bool {
	return len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
}

func removeLeadingZeros(input []byte) (raw []byte, err error) {
	if len(input) == 0 {
		return nil, nil // empty strings are allowed
	}
	if !bytesHave0xPrefix(input) {
		return nil, ErrMissingPrefix
	}
	input = input[2:]
	if len(input) == 0 {
		return nil, ErrEmptyNumber
	}

	// remove leading zeros
	for len(input) > 1 && input[0] == '0' {
		input = input[1:]
	}

	input = append([]byte{'0', 'x'}, input...)
	return input, nil
}

func wrapTypeError(err error, typ reflect.Type) error {
	if _, ok := err.(*decError); ok {
		return &json.UnmarshalTypeError{Value: err.Error(), Type: typ}
	}
	return err
}

func errNonString(typ reflect.Type) error {
	return &json.UnmarshalTypeError{Value: "non-string", Type: typ}
}
