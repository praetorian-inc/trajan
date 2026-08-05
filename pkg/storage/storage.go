//go:build js
// +build js

// Package storage persists audit logs, sessions, and scan caches in browser
// IndexedDB, standing in for the file I/O a native build would use.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"syscall/js"
	"time"
)

type IndexedDBStorage struct {
	dbName      string
	dbVersion   int
	db          js.Value
	initialized bool
}

const (
	storeAuditLogs = "audit_logs"
	storeSessions  = "sessions"
	storeScanCache = "scan_cache"
)

func NewIndexedDBStorage(dbName string, dbVersion int) *IndexedDBStorage {
	return &IndexedDBStorage{
		dbName:    dbName,
		dbVersion: dbVersion,
	}
}

func (s *IndexedDBStorage) Initialize(ctx context.Context) error {
	if s.initialized {
		return nil
	}

	indexedDB := js.Global().Get("indexedDB")
	if indexedDB.IsUndefined() {
		return errors.New("IndexedDB not available in this browser")
	}

	done := make(chan error, 1)
	request := indexedDB.Call("open", s.dbName, s.dbVersion)

	request.Set("onupgradeneeded", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		db := event.Get("target").Get("result")

		if !db.Get("objectStoreNames").Call("contains", storeAuditLogs).Bool() {
			auditStore := db.Call("createObjectStore", storeAuditLogs, map[string]interface{}{
				"keyPath": "key",
			})
			auditStore.Call("createIndex", "sessionID", "sessionID", map[string]interface{}{"unique": false})
			auditStore.Call("createIndex", "timestamp", "timestamp", map[string]interface{}{"unique": false})
		}

		if !db.Get("objectStoreNames").Call("contains", storeSessions).Bool() {
			sessionsStore := db.Call("createObjectStore", storeSessions, map[string]interface{}{
				"keyPath": "id",
			})
			sessionsStore.Call("createIndex", "status", "status", map[string]interface{}{"unique": false})
			sessionsStore.Call("createIndex", "createdAt", "createdAt", map[string]interface{}{"unique": false})
		}

		if !db.Get("objectStoreNames").Call("contains", storeScanCache).Bool() {
			cacheStore := db.Call("createObjectStore", storeScanCache, map[string]interface{}{
				"keyPath": "key",
			})
			cacheStore.Call("createIndex", "expiresAt", "expiresAt", map[string]interface{}{"unique": false})
		}

		return nil
	}))

	request.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		s.db = event.Get("target").Get("result")
		s.initialized = true
		done <- nil
		return nil
	}))

	request.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		errorMsg := event.Get("target").Get("error").Get("message").String()
		done <- fmt.Errorf("failed to open IndexedDB: %s", errorMsg)
		return nil
	}))

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *IndexedDBStorage) LogAudit(ctx context.Context, entry *AuditEntry) error {
	if !s.initialized {
		return errors.New("storage not initialized")
	}

	entryMap := map[string]interface{}{
		"key":       fmt.Sprintf("%d_%s", entry.Timestamp.UnixNano(), entry.SessionID),
		"timestamp": entry.Timestamp.UnixNano() / int64(time.Millisecond),
		"sessionID": entry.SessionID,
		"plugin":    entry.Plugin,
		"action":    entry.Action,
		"target":    entry.Target,
		"result":    entry.Result,
		"metadata":  entry.Metadata,
	}

	entryJSON, err := json.Marshal(entryMap)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}
	jsObj := js.Global().Get("JSON").Call("parse", string(entryJSON))

	done := make(chan error, 1)

	transaction := s.db.Call("transaction", []interface{}{storeAuditLogs}, "readwrite")
	store := transaction.Call("objectStore", storeAuditLogs)
	request := store.Call("add", jsObj)

	request.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		done <- nil
		return nil
	}))

	request.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		errorMsg := event.Get("target").Get("error").Get("message").String()
		done <- fmt.Errorf("failed to store audit log: %s", errorMsg)
		return nil
	}))

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *IndexedDBStorage) SaveSession(ctx context.Context, session *Session) error {
	if !s.initialized {
		return errors.New("storage not initialized")
	}

	session.UpdatedAt = time.Now()

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	jsObj := js.Global().Get("JSON").Call("parse", string(sessionJSON))

	done := make(chan error, 1)

	transaction := s.db.Call("transaction", []interface{}{storeSessions}, "readwrite")
	store := transaction.Call("objectStore", storeSessions)
	request := store.Call("put", jsObj)

	request.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		done <- nil
		return nil
	}))

	request.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		errorMsg := event.Get("target").Get("error").Get("message").String()
		done <- fmt.Errorf("failed to save session: %s", errorMsg)
		return nil
	}))

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *IndexedDBStorage) LoadSession(ctx context.Context, id string) (*Session, error) {
	if !s.initialized {
		return nil, errors.New("storage not initialized")
	}

	type result struct {
		session *Session
		err     error
	}
	done := make(chan result, 1)

	transaction := s.db.Call("transaction", []interface{}{storeSessions}, "readonly")
	store := transaction.Call("objectStore", storeSessions)
	request := store.Call("get", id)

	request.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		resultValue := event.Get("target").Get("result")

		if resultValue.IsUndefined() || resultValue.IsNull() {
			done <- result{nil, fmt.Errorf("session not found: %s", id)}
			return nil
		}

		jsonString := js.Global().Get("JSON").Call("stringify", resultValue).String()

		var session Session
		if err := json.Unmarshal([]byte(jsonString), &session); err != nil {
			done <- result{nil, fmt.Errorf("failed to parse session: %w", err)}
			return nil
		}

		done <- result{&session, nil}
		return nil
	}))

	request.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		errorMsg := event.Get("target").Get("error").Get("message").String()
		done <- result{nil, fmt.Errorf("failed to load session: %s", errorMsg)}
		return nil
	}))

	select {
	case res := <-done:
		return res.session, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *IndexedDBStorage) DeleteSession(ctx context.Context, id string) error {
	if !s.initialized {
		return errors.New("storage not initialized")
	}

	done := make(chan error, 1)

	transaction := s.db.Call("transaction", []interface{}{storeSessions}, "readwrite")
	store := transaction.Call("objectStore", storeSessions)
	request := store.Call("delete", id)

	request.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		done <- nil
		return nil
	}))

	request.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		errorMsg := event.Get("target").Get("error").Get("message").String()
		done <- fmt.Errorf("failed to delete session: %s", errorMsg)
		return nil
	}))

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *IndexedDBStorage) ListSessions(ctx context.Context) ([]*Session, error) {
	if !s.initialized {
		return nil, errors.New("storage not initialized")
	}

	type result struct {
		sessions []*Session
		err      error
	}
	done := make(chan result, 1)

	transaction := s.db.Call("transaction", []interface{}{storeSessions}, "readonly")
	store := transaction.Call("objectStore", storeSessions)
	sessions := make([]*Session, 0)
	request := store.Call("openCursor")

	request.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		cursor := event.Get("target").Get("result")

		// A null cursor is IndexedDB's end-of-iteration signal.
		if cursor.IsNull() || cursor.IsUndefined() {
			done <- result{sessions, nil}
			return nil
		}

		value := cursor.Get("value")
		jsonString := js.Global().Get("JSON").Call("stringify", value).String()

		var session Session
		if err := json.Unmarshal([]byte(jsonString), &session); err != nil {
			done <- result{nil, fmt.Errorf("failed to parse session: %w", err)}
			return nil
		}

		sessions = append(sessions, &session)

		cursor.Call("continue")
		return nil
	}))

	request.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		errorMsg := event.Get("target").Get("error").Get("message").String()
		done <- result{nil, fmt.Errorf("failed to list sessions: %s", errorMsg)}
		return nil
	}))

	select {
	case res := <-done:
		return res.sessions, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *IndexedDBStorage) SaveScanCache(ctx context.Context, cache *ScanCache) error {
	if !s.initialized {
		return errors.New("storage not initialized")
	}

	cache.CachedAt = time.Now()
	cache.ExpiresAt = cache.CachedAt.Add(time.Duration(cache.TTL) * time.Second)

	cacheJSON, err := json.Marshal(cache)
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	jsObj := js.Global().Get("JSON").Call("parse", string(cacheJSON))

	done := make(chan error, 1)

	transaction := s.db.Call("transaction", []interface{}{storeScanCache}, "readwrite")
	store := transaction.Call("objectStore", storeScanCache)
	request := store.Call("put", jsObj)

	request.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		done <- nil
		return nil
	}))

	request.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		errorMsg := event.Get("target").Get("error").Get("message").String()
		done <- fmt.Errorf("failed to save scan cache: %s", errorMsg)
		return nil
	}))

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *IndexedDBStorage) LoadScanCache(ctx context.Context, key string) (*ScanCache, error) {
	if !s.initialized {
		return nil, errors.New("storage not initialized")
	}

	type result struct {
		cache *ScanCache
		err   error
	}
	done := make(chan result, 1)

	transaction := s.db.Call("transaction", []interface{}{storeScanCache}, "readonly")
	store := transaction.Call("objectStore", storeScanCache)
	request := store.Call("get", key)

	request.Set("onsuccess", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		resultValue := event.Get("target").Get("result")

		if resultValue.IsUndefined() || resultValue.IsNull() {
			done <- result{nil, fmt.Errorf("cache not found: %s", key)}
			return nil
		}

		jsonString := js.Global().Get("JSON").Call("stringify", resultValue).String()

		var cache ScanCache
		if err := json.Unmarshal([]byte(jsonString), &cache); err != nil {
			done <- result{nil, fmt.Errorf("failed to parse cache: %w", err)}
			return nil
		}

		if time.Now().After(cache.ExpiresAt) {
			done <- result{nil, fmt.Errorf("cache expired: %s", key)}
			return nil
		}

		done <- result{&cache, nil}
		return nil
	}))

	request.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		event := args[0]
		errorMsg := event.Get("target").Get("error").Get("message").String()
		done <- result{nil, fmt.Errorf("failed to load cache: %s", errorMsg)}
		return nil
	}))

	select {
	case res := <-done:
		return res.cache, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *IndexedDBStorage) Close() error {
	if !s.initialized {
		return nil
	}

	if !s.db.IsUndefined() && !s.db.IsNull() {
		s.db.Call("close")
	}

	s.initialized = false
	return nil
}
