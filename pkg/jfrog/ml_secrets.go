package jfrog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/praetorian-inc/trajan/pkg/jfrog/proto"
)

// ErrMLSecretsAuthFailed indicates ML secrets access requires a Federation token
var ErrMLSecretsAuthFailed = errors.New("ML secrets require a Federation token (created via JFrog UI). Username/password authentication cannot access ML secrets. Generate an Admin Token at: Identity & Access → Access Tokens → Generate Admin Token")

// tenantInfo represents the JFrog tenant information
type tenantInfo struct {
	ServerID string `json:"serverId"`
}

// GetMLSecrets retrieves secrets from JFrog ML Secret Management using gRPC
// Returns an empty slice if JFrog ML is not enabled or configured
func (p *Platform) GetMLSecrets(ctx context.Context) ([]JFrogMLSecret, error) {
	// Step 1: Get tenant ID from REST API
	tenantID, err := p.getTenantID(ctx)
	if err != nil {
		// Check if this is an authentication error
		if errors.Is(err, ErrMLSecretsAuthFailed) {
			return []JFrogMLSecret{}, err
		}
		// Log other errors for debugging (ML not enabled, network issues, etc.)
		log.Printf("[ML Secrets] getTenantID failed: %v", err)
		return []JFrogMLSecret{}, nil
	}
	log.Printf("[ML Secrets] Got tenant ID: %s", tenantID)

	// Step 2: List secrets from Admiral (control plane)
	secretMetadata, err := p.listSecretsFromAdmiral(ctx, tenantID)
	if err != nil {
		// Check if this is an authentication error
		if errors.Is(err, ErrMLSecretsAuthFailed) {
			return []JFrogMLSecret{}, err
		}
		// Log other errors for debugging (ML not enabled, network issues, etc.)
		log.Printf("[ML Secrets] listSecretsFromAdmiral failed: %v", err)
		return []JFrogMLSecret{}, nil
	}
	log.Printf("[ML Secrets] Got %d secrets from Admiral", len(secretMetadata))

	// Step 3: Get secret values from Edge service (per-environment)
	secrets := make([]JFrogMLSecret, 0, len(secretMetadata))
	for _, meta := range secretMetadata {
		secret := JFrogMLSecret{
			Name:          meta.Name,
			EnvironmentID: meta.EnvironmentID,
			CreatedAt:     meta.CreatedAt,
			LastUpdatedAt: meta.LastUpdatedAt,
		}

		// Get value from Edge service
		value, err := p.getSecretValueFromEdge(ctx, tenantID, meta.Name)
		if err != nil {
			secret.Error = err.Error()
		} else {
			secret.Value = value
		}

		secrets = append(secrets, secret)
	}

	return secrets, nil
}

// getTenantID retrieves the tenant ID (serverId) from the JFrog REST API
func (p *Platform) getTenantID(ctx context.Context) (string, error) {
	resp, err := p.client.Get(ctx, "/ui/api/v1/system/auth/screen/footer")
	if err != nil {
		return "", fmt.Errorf("failed to call footer API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		// Check for authentication errors
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return "", ErrMLSecretsAuthFailed
		}
		return "", fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	var info tenantInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if info.ServerID == "" {
		return "", fmt.Errorf("serverId not found in response")
	}

	return info.ServerID, nil
}

// secretMetadata represents metadata about a secret from Admiral
type secretMetadata struct {
	Name          string
	EnvironmentID string
	CreatedAt     int64
	LastUpdatedAt int64
}

// listSecretsFromAdmiral lists all secrets from the Admiral control plane
func (p *Platform) listSecretsFromAdmiral(ctx context.Context, tenantID string) ([]secretMetadata, error) {
	// Create gRPC connection to Admiral at grpc.qwak.ai
	conn, authCtx, err := p.createGRPCConnection(ctx, "grpc.qwak.ai:443", tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Admiral: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Create Admiral SecretService client
	client := proto.NewSecretServiceClient(conn)

	// Call ListAccountSecrets with the authenticated context
	req := &proto.ListAccountSecretsRequest{}
	resp, err := client.ListAccountSecrets(authCtx, req)
	if err != nil {
		// Check if this is an authentication error
		errStr := err.Error()
		if strings.Contains(errStr, "Unauthenticated") ||
			strings.Contains(errStr, "Token validation failed") ||
			strings.Contains(errStr, "authentication failed") {
			return nil, ErrMLSecretsAuthFailed
		}
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Convert response to metadata slice
	if resp.AccountSecrets == nil || len(resp.AccountSecrets.Secrets) == 0 {
		return []secretMetadata{}, nil
	}

	metas := make([]secretMetadata, 0, len(resp.AccountSecrets.Secrets))
	for _, s := range resp.AccountSecrets.Secrets {
		if s.Identifier == nil {
			continue
		}

		var createdAt, lastUpdatedAt int64
		if s.CreatedAt != nil {
			createdAt = s.CreatedAt.AsTime().Unix()
		}
		if s.LastUpdatedAt != nil {
			lastUpdatedAt = s.LastUpdatedAt.AsTime().Unix()
		}

		metas = append(metas, secretMetadata{
			Name:          s.Identifier.Name,
			EnvironmentID: s.Identifier.EnvironmentId,
			CreatedAt:     createdAt,
			LastUpdatedAt: lastUpdatedAt,
		})
	}

	return metas, nil
}

// getSecretValueFromEdge retrieves a secret value from the Edge service
func (p *Platform) getSecretValueFromEdge(ctx context.Context, tenantID, secretName string) (string, error) {
	// Create gRPC connection to Edge at grpc.{tenant}.qwak.ai
	edgeAddr := fmt.Sprintf("grpc.%s.qwak.ai:443", tenantID)

	conn, authCtx, err := p.createGRPCConnection(ctx, edgeAddr, tenantID)
	if err != nil {
		return "", fmt.Errorf("failed to connect to Edge: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Call GetSecret with correct method path (Edge uses qwak.secret.service.SecretService)
	req := &proto.GetSecretRequest{Name: secretName}
	resp := &proto.GetSecretResponse{}
	err = conn.Invoke(authCtx, "/qwak.secret.service.SecretService/GetSecret", req, resp)
	if err != nil {
		return "", fmt.Errorf("failed to get secret: %w", err)
	}

	return resp.Value, nil
}

// createGRPCConnection creates a gRPC connection with authentication
func (p *Platform) createGRPCConnection(ctx context.Context, addr, tenantID string) (*grpc.ClientConn, context.Context, error) {
	// Create context with auth metadata
	authCtx, err := p.addAuthMetadata(ctx, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("adding auth metadata: %w", err)
	}

	// Create connection with TLS
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(credentials.NewTLS(nil)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial: %w", err)
	}

	return conn, authCtx, nil
}

// addAuthMetadata adds authentication headers to the context
func (p *Platform) addAuthMetadata(ctx context.Context, tenantID string) (context.Context, error) {
	token, err := p.client.GetAccessToken(ctx)
	if err != nil {
		return ctx, fmt.Errorf("getting access token: %w", err)
	}

	md := metadata.New(map[string]string{
		"authorization":     "Bearer " + token,
		"x-jfrog-tenant-id": tenantID,
	})
	return metadata.NewOutgoingContext(ctx, md), nil
}
