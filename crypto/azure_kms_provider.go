package crypto

import (
	"context"
	"crypto/rand"
	"fmt"
)

// AzureKMSOptions contains configuration options for AzureKMSProvider
type AzureKMSOptions struct {
	// KeyID is the resource identifier (URL) of the Key Vault key to use
	KeyID string

	// Algorithm is the algorithm to use for wrapping/unwrapping keys.
	// Examples: "RSA-OAEP-256" or "A256KW". If empty, defaults to "RSA-OAEP-256".
	Algorithm string
}

// AzureKMSClient is a minimal interface that an Azure Key Vault crypto client
// adapter should implement. We keep it small to avoid pulling in the full
// Azure SDK here; callers can provide an adapter that wraps
// *azcrypto.Client or similar.
type AzureKMSClient interface {
	// WrapKey wraps (encrypts) the provided plaintext key using the configured
	// key in Key Vault and returns the ciphertext.
	WrapKey(ctx context.Context, algorithm string, plaintext []byte) ([]byte, error)

	// UnwrapKey unwraps (decrypts) the provided ciphertext and returns the
	// plaintext key.
	UnwrapKey(ctx context.Context, algorithm string, ciphertext []byte) ([]byte, error)
}

// AzureKMSProvider implements MaterialsManager using Azure Key Vault
type AzureKMSProvider struct {
	kmsClient AzureKMSClient
	keyID     string
	algorithm string
}

// NewAzureKMSProvider creates a new Azure Key Vault based provider.
func NewAzureKMSProvider(client AzureKMSClient, options AzureKMSOptions) *AzureKMSProvider {
	alg := options.Algorithm
	if alg == "" {
		alg = "RSA-OAEP-256"
	}

	return &AzureKMSProvider{
		kmsClient: client,
		keyID:     options.KeyID,
		algorithm: alg,
	}
}

// GetMaterial generates a new random data key and wraps it using Key Vault.
func (a *AzureKMSProvider) GetMaterial(ctx context.Context, cryptoCtx CryptoContext) (*Material, error) {
	// Generate a 32-byte (256-bit) random key
	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}

	// Wrap the plaintext using the provided Azure KMS client
	ciphertext, err := a.kmsClient.WrapKey(ctx, a.algorithm, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key with Azure Key Vault: %v", err)
	}

	return &Material{
		PlaintextKey: plaintext,
		EncryptedKey: ciphertext,
	}, nil
}

// DecryptMaterial unwraps the encrypted key via Key Vault
func (a *AzureKMSProvider) DecryptMaterial(ctx context.Context, cryptoCtx CryptoContext, material *Material) (*Material, error) {
	plaintext, err := a.kmsClient.UnwrapKey(ctx, a.algorithm, material.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key with Azure Key Vault: %v", err)
	}

	return &Material{
		PlaintextKey: plaintext,
		EncryptedKey: material.EncryptedKey,
	}, nil
}

/*
Adapter example (to be added in your code that wires up the provider):

import (
    "context"
    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    "github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcrypto"
)

type azcryptoAdapter struct {
    client *azcrypto.Client
}

func (a *azcryptoAdapter) WrapKey(ctx context.Context, algorithm string, plaintext []byte) ([]byte, error) {
    // Translate algorithm string to azcrypto.JSONWebKeyEncryptionAlgorithm
    // e.g. azcrypto.RSAOAEP256
    alg := azcrypto.RSAOAEP256
    // call a.client.WrapKey(ctx, alg, plaintext, nil)
    // return result.Result
}

func (a *azcryptoAdapter) UnwrapKey(ctx context.Context, algorithm string, ciphertext []byte) ([]byte, error) {
    // call a.client.UnwrapKey(ctx, alg, ciphertext, nil)
}

// To create the azcrypto client:
// cred, _ := azidentity.NewDefaultAzureCredential(nil)
// client, _ := azcrypto.NewClient("https://<your-vault-name>.vault.azure.net/keys/<key-name>", cred, nil)
// provider := NewAzureKMSProvider(&azcryptoAdapter{client: client}, AzureKMSOptions{KeyID: "..."})

*/
