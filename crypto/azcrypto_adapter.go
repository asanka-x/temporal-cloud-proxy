//go:build azure
// +build azure

package crypto

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"go.uber.org/zap"
)

// AzCryptoAdapter adapts the Azure SDK azkeys.Client to the AzureKMSClient.
type AzCryptoAdapter struct {
	client     azkeysClient
	alg        azkeys.EncryptionAlgorithm
	keyName    string
	keyVersion string
	logger     *zap.Logger
}

// azkeysClient defines the subset of azkeys.Client methods used by the
// adapter. Defining an interface makes testing with a fake client straightforward.
type azkeysClient interface {
	WrapKey(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error)
}

// NewAzCryptoAdapter constructs an adapter for the given Key Vault key URL.
// keyID should be the full key url, e.g. https://<vault-name>.vault.azure.net/keys/<key-name>
func NewAzCryptoAdapter(keyID string, logger *zap.Logger) (*AzCryptoAdapter, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	vaultURL, keyName, keyVersion, err := parseKeyID(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key ID: %w", err)
	}

	client, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create azkeys client: %w", err)
	}

	alg := azkeys.EncryptionAlgorithmRSAOAEP256 // Default algorithm for RSA key wrapping
	if logger != nil {
		logger.Info("created Azure Key Vault adapter",
			zap.String("key_id", keyID),
			zap.String("vault_url", vaultURL),
			zap.String("key_name", keyName),
			zap.String("key_version", keyVersion),
			zap.String("algorithm", string(alg)),
		)
	}

	return &AzCryptoAdapter{client: client, alg: alg, keyName: keyName, keyVersion: keyVersion, logger: logger}, nil
}

func (a *AzCryptoAdapter) resolveAlgorithm(algorithm string) azkeys.EncryptionAlgorithm {
	if algorithm != "" {
		return azkeys.EncryptionAlgorithm(algorithm)
	}
	return a.alg
}

// WrapKey wraps (encrypts) the plaintext using Key Vault.
func (a *AzCryptoAdapter) WrapKey(ctx context.Context, algorithm string, plaintext []byte) ([]byte, error) {
	alg := a.resolveAlgorithm(algorithm)
	if a.logger != nil {
		a.logger.Info("Azure Key Vault wrap key request",
			zap.String("key_name", a.keyName),
			zap.String("key_version", a.keyVersion),
			zap.String("algorithm", string(alg)),
			zap.Int("plaintext_length", len(plaintext)),
			zap.String("requested_algorithm", algorithm),
		)
	}

	params := azkeys.KeyOperationParameters{Algorithm: &alg, Value: plaintext}
	resp, err := a.client.WrapKey(ctx, a.keyName, a.keyVersion, params, nil)
	if err != nil {
		if a.logger != nil {
			a.logger.Error("Azure Key Vault wrap key failed",
				zap.String("key_name", a.keyName),
				zap.String("key_version", a.keyVersion),
				zap.String("algorithm", string(alg)),
				zap.Error(err),
			)
		}
		return nil, fmt.Errorf("azkeys WrapKey failed: %w", err)
	}

	if a.logger != nil {
		a.logger.Info("Azure Key Vault wrap key succeeded",
			zap.String("key_name", a.keyName),
			zap.String("key_version", a.keyVersion),
			zap.String("algorithm", string(alg)),
			zap.Int("ciphertext_length", len(resp.Result)),
		)
	}

	return resp.Result, nil
}

// UnwrapKey unwraps (decrypts) the ciphertext using Key Vault.
func (a *AzCryptoAdapter) UnwrapKey(ctx context.Context, algorithm string, ciphertext []byte) ([]byte, error) {
	alg := a.resolveAlgorithm(algorithm)
	if a.logger != nil {
		a.logger.Info("Azure Key Vault unwrap key request",
			zap.String("key_name", a.keyName),
			zap.String("key_version", a.keyVersion),
			zap.String("algorithm", string(alg)),
			zap.Int("ciphertext_length", len(ciphertext)),
			zap.String("requested_algorithm", algorithm),
		)
	}

	params := azkeys.KeyOperationParameters{Algorithm: &alg, Value: ciphertext}
	resp, err := a.client.UnwrapKey(ctx, a.keyName, a.keyVersion, params, nil)
	if err != nil {
		if a.logger != nil {
			a.logger.Error("Azure Key Vault unwrap key failed",
				zap.String("key_name", a.keyName),
				zap.String("key_version", a.keyVersion),
				zap.String("algorithm", string(alg)),
				zap.Error(err),
			)
		}
		return nil, fmt.Errorf("azkeys UnwrapKey failed: %w", err)
	}

	if a.logger != nil {
		a.logger.Info("Azure Key Vault unwrap key succeeded",
			zap.String("key_name", a.keyName),
			zap.String("key_version", a.keyVersion),
			zap.String("algorithm", string(alg)),
			zap.Int("plaintext_length", len(resp.Result)),
		)
	}

	return resp.Result, nil
}

func parseKeyID(keyID string) (string, string, string, error) {
	parsed, err := url.Parse(keyID)
	if err != nil {
		return "", "", "", err
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return "", "", "", fmt.Errorf("invalid key ID %q", keyID)
	}

	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) < 2 || segments[0] != "keys" {
		return "", "", "", fmt.Errorf("invalid key ID %q", keyID)
	}

	keyName := segments[1]
	keyVersion := ""
	if len(segments) > 2 {
		keyVersion = segments[2]
	}

	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host), keyName, keyVersion, nil
}
