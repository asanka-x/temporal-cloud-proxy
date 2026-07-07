//go:build !azure
// +build !azure

package crypto

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// AzCryptoAdapter stub used when built without the `azure` tag.
type AzCryptoAdapter struct{}

func NewAzCryptoAdapter(keyID string, logger *zap.Logger) (*AzCryptoAdapter, error) {
	_ = logger
	return nil, fmt.Errorf("azcrypto adapter not available: build with '-tags azure' to enable Azure Key Vault support")
}

func (a *AzCryptoAdapter) WrapKey(ctx context.Context, algorithm string, plaintext []byte) ([]byte, error) {
	return nil, fmt.Errorf("azcrypto adapter not available: build with '-tags azure' to enable Azure Key Vault support")
}

func (a *AzCryptoAdapter) UnwrapKey(ctx context.Context, algorithm string, ciphertext []byte) ([]byte, error) {
	return nil, fmt.Errorf("azcrypto adapter not available: build with '-tags azure' to enable Azure Key Vault support")
}
