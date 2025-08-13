// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"azugo.io/azugo"
	"azugo.io/core/cache"
	"azugo.io/core/cert"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

type SystemTokenClient struct {
	*SystemTokenConfiguration
	cache       cache.Instance[string]
	certificate *tls.Certificate
}

func NewSystemTokenClient(
	config *SystemTokenConfiguration,
) (*SystemTokenClient, error) {
	systemCache, err := cache.Create[string](cache.New(), "system-token", cache.MemoryCache)
	if err != nil {
		return nil, err
	}

	certificate, err := cert.ParseTLSCertificateFromReader(strings.NewReader(config.Certificate))
	if err != nil {
		return nil, err
	}

	return &SystemTokenClient{
		SystemTokenConfiguration: config,
		cache:                    systemCache,
		certificate:              certificate,
	}, nil
}

type TokenCache struct {
	ClientID  string
	Token     string
	ExpiresAt int64
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (c *SystemTokenClient) GetSystemToken(ctx *azugo.Context, scope string) (string, error) {
	token, err := c.cache.Get(ctx, scope)
	if err != nil {
		return "", err
	}

	if token != "" {
		return token, nil
	}

	return c.newSystemToken(ctx, scope)
}

func (c *SystemTokenClient) newSystemToken(ctx *azugo.Context, scope string) (string, error) {
	tokenURL := c.URL + "/api/1.0/token"

	// JTI
	jti := make([]byte, 24)

	_, err := rand.Read(jti)
	if err != nil {
		return "", err
	}

	jtiStr := base64.RawURLEncoding.EncodeToString(jti)

	now := time.Now().UTC()

	tok := &jwt.RegisteredClaims{
		ID:        jtiStr,
		Issuer:    c.ClientID,
		Subject:   c.ClientID,
		Audience:  jwt.ClaimStrings{tokenURL},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(60 * time.Second)),
	}

	var method jwt.SigningMethod

	switch c.certificate.PrivateKey.(type) {
	case *rsa.PrivateKey:
		method = jwt.SigningMethodRS256
	case *ecdsa.PrivateKey:
		method = jwt.SigningMethodES256
	default:
		return "", fmt.Errorf("unsupported private key type: %T", c.certificate.PrivateKey)
	}

	token, err := jwt.NewWithClaims(method, tok).SignedString(c.certificate.PrivateKey)
	if err != nil {
		return "", err
	}

	client := ctx.HTTPClient().WithBaseURL(tokenURL)

	var tokenResponse TokenResponse

	err = client.PostJSON(tokenURL, map[string]string{
		"grant_type":            "client_credentials",
		"client_id":             c.ClientID,
		"scope":                 scope,
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion":      token,
	}, &tokenResponse)
	if err != nil {
		ctx.Log().Error("failed to get token", zap.Error(err))

		return "", err
	}

	// Format the string
	tokenString := fmt.Sprintf("%s %s", tokenResponse.TokenType, tokenResponse.AccessToken)

	if err = c.cache.Set(ctx, scope, tokenString, cache.TTL[string](time.Duration(tokenResponse.ExpiresIn)*time.Second)); err != nil {
		ctx.Log().Error("failed to save token to cache", zap.Error(err))

		return tokenString, nil
	}

	return tokenString, nil
}
