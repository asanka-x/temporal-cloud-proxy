package crypto

import (
	"context"
	"fmt"
	"testing"
)

type fakeAzureClient struct{}

func (f *fakeAzureClient) WrapKey(ctx context.Context, algorithm string, plaintext []byte) ([]byte, error) {
	// simple deterministic wrap: prefix with "wrap:"
	out := make([]byte, 5+len(plaintext))
	copy(out, []byte("wrap:"))
	copy(out[5:], plaintext)
	return out, nil
}

func (f *fakeAzureClient) UnwrapKey(ctx context.Context, algorithm string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 5 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return ciphertext[5:], nil
}

func TestAzureKMSProvider_GetAndDecrypt(t *testing.T) {
	ctx := context.TODO()

	fake := &fakeAzureClient{}
	provider := NewAzureKMSProvider(fake, AzureKMSOptions{KeyID: "test-key", Algorithm: "RSA-OAEP-256"})

	material, err := provider.GetMaterial(ctx, CryptoContext{"a": "b"})
	if err != nil {
		t.Fatalf("GetMaterial returned error: %v", err)
	}

	if len(material.PlaintextKey) != 32 {
		t.Fatalf("expected plaintext key length 32, got %d", len(material.PlaintextKey))
	}

	if material.EncryptedKey == nil || len(material.EncryptedKey) <= 5 {
		t.Fatalf("invalid encrypted key")
	}

	// Now decrypt
	decrypted, err := provider.DecryptMaterial(ctx, CryptoContext{"a": "b"}, material)
	if err != nil {
		t.Fatalf("DecryptMaterial returned error: %v", err)
	}

	if len(decrypted.PlaintextKey) != 32 {
		t.Fatalf("expected decrypted plaintext key length 32, got %d", len(decrypted.PlaintextKey))
	}

	// Ensure the decrypted plaintext matches the original plaintext
	for i := range material.PlaintextKey {
		if material.PlaintextKey[i] != decrypted.PlaintextKey[i] {
			t.Fatalf("decrypted key does not match original")
		}
	}
}
