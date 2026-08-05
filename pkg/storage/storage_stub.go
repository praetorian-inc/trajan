//go:build !js
// +build !js

package storage

import (
	"context"
	"errors"
)

type IndexedDBStorage struct {
	dbName    string
	dbVersion int
}

func NewIndexedDBStorage(dbName string, dbVersion int) *IndexedDBStorage {
	return &IndexedDBStorage{
		dbName:    dbName,
		dbVersion: dbVersion,
	}
}

func (s *IndexedDBStorage) Initialize(ctx context.Context) error {
	return errors.New("IndexedDB only available in WASM/browser environment")
}

func (s *IndexedDBStorage) LogAudit(ctx context.Context, entry *AuditEntry) error {
	return errors.New("IndexedDB only available in WASM/browser environment")
}

func (s *IndexedDBStorage) SaveSession(ctx context.Context, session *Session) error {
	return errors.New("IndexedDB only available in WASM/browser environment")
}

func (s *IndexedDBStorage) LoadSession(ctx context.Context, id string) (*Session, error) {
	return nil, errors.New("IndexedDB only available in WASM/browser environment")
}

func (s *IndexedDBStorage) DeleteSession(ctx context.Context, id string) error {
	return errors.New("IndexedDB only available in WASM/browser environment")
}

func (s *IndexedDBStorage) ListSessions(ctx context.Context) ([]*Session, error) {
	return nil, errors.New("IndexedDB only available in WASM/browser environment")
}

func (s *IndexedDBStorage) SaveScanCache(ctx context.Context, cache *ScanCache) error {
	return errors.New("IndexedDB only available in WASM/browser environment")
}

func (s *IndexedDBStorage) LoadScanCache(ctx context.Context, key string) (*ScanCache, error) {
	return nil, errors.New("IndexedDB only available in WASM/browser environment")
}

func (s *IndexedDBStorage) Close() error {
	return nil
}
