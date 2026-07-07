//go:build azure
// +build azure

package crypto

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

type fakeAzClient struct{}

func (f *fakeAzClient) WrapKey(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	out := make([]byte, 5+len(parameters.Value))
	copy(out, []byte("wrap:"))
	copy(out[5:], parameters.Value)
	return azkeys.WrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: out}}, nil
}

func (f *fakeAzClient) UnwrapKey(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	if len(parameters.Value) < 5 {
		return azkeys.UnwrapKeyResponse{}, nil
	}
	return azkeys.UnwrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: parameters.Value[5:]}}, nil
}

func TestAzCryptoAdapter_WrapUnwrap(t *testing.T) {
	fake := &fakeAzClient{}
	adapter := &AzCryptoAdapter{client: fake, alg: azkeys.EncryptionAlgorithmA128CBCPAD}

	ctx := context.TODO()
	plaintext := []byte("01234567890123456789012345678901") // 32 bytes

	wrapped, err := adapter.WrapKey(ctx, "", plaintext)
	if err != nil {
		t.Fatalf("WrapKey error: %v", err)
	}

	if len(wrapped) <= 5 {
		t.Fatalf("wrapped too short")
	}

	unwrapped, err := adapter.UnwrapKey(ctx, "", wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey error: %v", err)
	}

	if len(unwrapped) != len(plaintext) {
		t.Fatalf("unwrapped length mismatch: got %d want %d", len(unwrapped), len(plaintext))
	}
}
