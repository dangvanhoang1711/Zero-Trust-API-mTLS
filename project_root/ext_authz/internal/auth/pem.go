package auth

import (
	"encoding/pem"
	"errors"
)

func pemToDER(certPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("invalid pem")
	}
	return block.Bytes, nil
}
