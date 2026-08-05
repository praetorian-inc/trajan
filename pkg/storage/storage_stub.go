//go:build !js
// +build !js

package storage

import (
	"context"
	"errors"
)

// This file provides stub implementations for non-WASM builds
// The actual IndexedDB implementation is in storage.go with +build js tag

// IndexedDBStorage stub for non-WASM builds
type IndexedDBStorage struct {
	dbName    string
	dbVersion int
}

// NewIndexedDBStorage creates a new IndexedDB storage adapter
func NewIndexedDBStorage(dbName string, dbVersion int) *IndexedDBStorage {
	return &IndexedDBStorage{
		dbName:    dbName,
		dbVersion: dbVersion,
	}
}

// Initialize returns an error indicating IndexedDB is only available in browser
func (s *IndexedDBStorage) Initialize(ctx context.Context) error {
	return errors.New("IndexedDB only available in WASM/browser environment")
}

// LogAudit returns an error indicating IndexedDB is only available in browser
func (s *IndexedDBStorage) LogAudit(ctx context.Context, entry *AuditEntry) error {
	return errors.New("IndexedDB only available in WASM/browser environment")
}

// SaveSession returns an error indicating IndexedDB is only available in browser
func (s *IndexedDBStorage) SaveSession(ctx context.Context, session *Session) error {
	return errors.New("IndexedDB only available in WASM/browser environment")
}

// LoadSession returns an error indicating IndexedDB is only available in browser
func (s *IndexedDBStorage) LoadSession(ctx context.Context, id string) (*Session, error) {
	return nil, errors.New("IndexedDB only available in WASM/browser environment")
}

// DeleteSession returns an error indicating IndexedDB is only available in browser
func (s *IndexedDBStorage) DeleteSession(ctx context.Context, id string) error {
	return errors.New("IndexedDB only available in WASM/browser environment")
}

// ListSessions returns an error indicating IndexedDB is only available in browser
func (s *IndexedDBStorage) ListSessions(ctx context.Context) ([]*Session, error) {
	return nil, errors.New("IndexedDB only available in WASM/browser environment")
}

// SaveScanCache returns an error indicating IndexedDB is only available in browser
func (s *IndexedDBStorage) SaveScanCache(ctx context.Context, cache *ScanCache) error {
	return errors.New("IndexedDB only available in WASM/browser environment")
}

// LoadScanCache returns an error indicating IndexedDB is only available in browser
func (s *IndexedDBStorage) LoadScanCache(ctx context.Context, key string) (*ScanCache, error) {
	return nil, errors.New("IndexedDB only available in WASM/browser environment")
}

// Close returns nil for non-WASM builds
func (s *IndexedDBStorage) Close() error {
	return nil
}
