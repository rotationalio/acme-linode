package acme

import "errors"

var (
	ErrNoRecord               = errors.New("no matching DNS record found for the specified entry")
	ErrInvalidSecretReference = errors.New("invalid secret reference: must contain name and key values")
)
