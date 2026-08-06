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

// ML secrets require a Federation-issued token.
var ErrMLSecretsAuthFailed = errors.New("ML secrets require a Federation token (created via JFrog UI). Username/password authentication cannot access ML secrets. Generate an Admin Token at: Identity & Access → Access Tokens → Generate Admin Token")

type tenantInfo struct {
	ServerID string `json:"serverId"`
}

// Returns an empty slice when JFrog ML is not enabled or not configured.
func (p *Platform) GetMLSecrets(ctx context.Context) ([]JFrogMLSecret, error) {
	tenantID, err := p.getTenantID(ctx)
	if err != nil {
		if errors.Is(err, ErrMLSecretsAuthFailed) {
			return []JFrogMLSecret{}, err
		}
		// ML not being enabled is the common case, so degrade to empty instead of erroring.
		log.Printf("[ML Secrets] getTenantID failed: %v", err)
		return []JFrogMLSecret{}, nil
	}
	log.Printf("[ML Secrets] Got tenant ID: %s", tenantID)

	secretMetadata, err := p.listSecretsFromAdmiral(ctx, tenantID)
	if err != nil {
		if errors.Is(err, ErrMLSecretsAuthFailed) {
			return []JFrogMLSecret{}, err
		}
		log.Printf("[ML Secrets] listSecretsFromAdmiral failed: %v", err)
		return []JFrogMLSecret{}, nil
	}
	log.Printf("[ML Secrets] Got %d secrets from Admiral", len(secretMetadata))

	secrets := make([]JFrogMLSecret, 0, len(secretMetadata))
	for _, meta := range secretMetadata {
		secret := JFrogMLSecret{
			Name:          meta.Name,
			EnvironmentID: meta.EnvironmentID,
			CreatedAt:     meta.CreatedAt,
			LastUpdatedAt: meta.LastUpdatedAt,
		}

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

func (p *Platform) getTenantID(ctx context.Context) (string, error) {
	resp, err := p.client.Get(ctx, "/ui/api/v1/system/auth/screen/footer")
	if err != nil {
		return "", fmt.Errorf("failed to call footer API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
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

type secretMetadata struct {
	Name          string
	EnvironmentID string
	CreatedAt     int64
	LastUpdatedAt int64
}

func (p *Platform) listSecretsFromAdmiral(ctx context.Context, tenantID string) ([]secretMetadata, error) {
	conn, authCtx, err := p.createGRPCConnection(ctx, "grpc.qwak.ai:443", tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Admiral: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := proto.NewSecretServiceClient(conn)

	req := &proto.ListAccountSecretsRequest{}
	resp, err := client.ListAccountSecrets(authCtx, req)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "Unauthenticated") ||
			strings.Contains(errStr, "Token validation failed") ||
			strings.Contains(errStr, "authentication failed") {
			return nil, ErrMLSecretsAuthFailed
		}
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

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

func (p *Platform) getSecretValueFromEdge(ctx context.Context, tenantID, secretName string) (string, error) {
	edgeAddr := fmt.Sprintf("grpc.%s.qwak.ai:443", tenantID)

	conn, authCtx, err := p.createGRPCConnection(ctx, edgeAddr, tenantID)
	if err != nil {
		return "", fmt.Errorf("failed to connect to Edge: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Edge serves this under qwak.secret.service.SecretService, unlike Admiral.
	req := &proto.GetSecretRequest{Name: secretName}
	resp := &proto.GetSecretResponse{}
	err = conn.Invoke(authCtx, "/qwak.secret.service.SecretService/GetSecret", req, resp)
	if err != nil {
		return "", fmt.Errorf("failed to get secret: %w", err)
	}

	return resp.Value, nil
}

func (p *Platform) createGRPCConnection(ctx context.Context, addr, tenantID string) (*grpc.ClientConn, context.Context, error) {
	authCtx, err := p.addAuthMetadata(ctx, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("adding auth metadata: %w", err)
	}

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(credentials.NewTLS(nil)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial: %w", err)
	}

	return conn, authCtx, nil
}

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
