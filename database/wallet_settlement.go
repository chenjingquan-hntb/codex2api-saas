package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	WalletSettlementInFlight       = "in_flight"
	WalletSettlementSettlePending  = "settle_pending"
	WalletSettlementReleasePending = "release_pending"
	WalletSettlementSettled        = "settled"
	WalletSettlementReleased       = "released"
)

// WalletSettlementIntent 持久化一次请求的结算义务。只要该记录存在，孤儿预留
// 回收器就不会自动释放对应预留；成功用量只能由幂等结算重试完成。
type WalletSettlementIntent struct {
	ID            int64
	UserID        int64
	ReferenceType string
	ReferenceID   string
	ReservedMicro int64
	ActualMicro   int64
	Status        string
	RetryCount    int
	LastError     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type WalletSettlementRetryResult struct {
	Settled  int
	Released int
	Failed   int
}

type WalletSettlementMetrics struct {
	InFlight       int64
	SettlePending  int64
	ReleasePending int64
	Retried        int64
	StaleInFlight  int64
}

func validateSettlementIdentity(userID, reservedMicro int64, refType, refID string) error {
	if userID <= 0 || reservedMicro <= 0 {
		return fmt.Errorf("wallet settlement: invalid user or reserved amount")
	}
	if strings.TrimSpace(refType) == "" || strings.TrimSpace(refID) == "" {
		return fmt.Errorf("wallet settlement: reference is required")
	}
	return nil
}

// CreateWalletSettlementIntent 必须在预留成功、调用上游之前执行。创建失败时调用方
// 必须释放预留并 fail-closed，确保不会出现已发送上游但无持久化结算跟踪的请求。
func (db *DB) CreateWalletSettlementIntent(ctx context.Context, userID, reservedMicro int64, refType, refID string) error {
	if err := validateSettlementIdentity(userID, reservedMicro, refType, refID); err != nil {
		return err
	}
	now := db.timeArg(time.Now().UTC())
	res, err := db.conn.ExecContext(ctx, `
		INSERT INTO wallet_settlement_intents
			(user_id, reference_type, reference_id, reserved_micro, actual_micro, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 0, $5, $6, $6)
		ON CONFLICT (reference_type, reference_id) DO NOTHING`,
		userID, refType, refID, reservedMicro, WalletSettlementInFlight, now)
	if err != nil {
		return fmt.Errorf("wallet settlement: create intent: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 1 {
		return nil
	}
	var existingUser, existingReserved int64
	err = db.conn.QueryRowContext(ctx, `
		SELECT user_id, reserved_micro FROM wallet_settlement_intents
		WHERE reference_type = $1 AND reference_id = $2`, refType, refID).
		Scan(&existingUser, &existingReserved)
	if err != nil {
		return fmt.Errorf("wallet settlement: verify replay: %w", err)
	}
	if existingUser != userID || existingReserved != reservedMicro {
		return fmt.Errorf("wallet settlement: reference collision")
	}
	return nil
}

func (db *DB) prepareWalletSettlementIntent(ctx context.Context, userID, actualMicro int64, refType, refID, status string) error {
	if userID <= 0 || actualMicro < 0 || strings.TrimSpace(refType) == "" || strings.TrimSpace(refID) == "" {
		return fmt.Errorf("wallet settlement: invalid prepare arguments")
	}
	if status != WalletSettlementSettlePending && status != WalletSettlementReleasePending {
		return fmt.Errorf("wallet settlement: invalid pending status %q", status)
	}
	res, err := db.conn.ExecContext(ctx, `
		UPDATE wallet_settlement_intents
		SET actual_micro = $1, status = $2, last_error = '', updated_at = $3
		WHERE user_id = $4 AND reference_type = $5 AND reference_id = $6
		  AND status NOT IN ($7, $8)`,
		actualMicro, status, db.timeArg(time.Now().UTC()), userID, refType, refID,
		WalletSettlementSettled, WalletSettlementReleased)
	if err != nil {
		return fmt.Errorf("wallet settlement: prepare: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var current string
	if err := db.conn.QueryRowContext(ctx, `SELECT status FROM wallet_settlement_intents WHERE user_id=$1 AND reference_type=$2 AND reference_id=$3`, userID, refType, refID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("wallet settlement: intent not found")
		}
		return err
	}
	if current == WalletSettlementSettled || current == WalletSettlementReleased {
		return nil
	}
	return fmt.Errorf("wallet settlement: intent not updated")
}

func (db *DB) PrepareWalletSettlement(ctx context.Context, userID, reservedMicro, actualMicro int64, refType, refID string) error {
	if err := validateSettlementIdentity(userID, reservedMicro, refType, refID); err != nil {
		return err
	}
	if actualMicro <= 0 {
		return fmt.Errorf("wallet settlement: actual amount must be positive")
	}
	return db.prepareWalletSettlementIntent(ctx, userID, actualMicro, refType, refID, WalletSettlementSettlePending)
}

func (db *DB) PrepareWalletRelease(ctx context.Context, userID, reservedMicro int64, refType, refID string) error {
	if err := validateSettlementIdentity(userID, reservedMicro, refType, refID); err != nil {
		return err
	}
	return db.prepareWalletSettlementIntent(ctx, userID, 0, refType, refID, WalletSettlementReleasePending)
}

func (db *DB) CompleteWalletSettlementIntent(ctx context.Context, userID int64, refType, refID, status string) error {
	if status != WalletSettlementSettled && status != WalletSettlementReleased {
		return fmt.Errorf("wallet settlement: invalid terminal status %q", status)
	}
	res, err := db.conn.ExecContext(ctx, `
		UPDATE wallet_settlement_intents SET status=$1, last_error='', updated_at=$2
		WHERE user_id=$3 AND reference_type=$4 AND reference_id=$5`,
		status, db.timeArg(time.Now().UTC()), userID, refType, refID)
	if err != nil {
		return fmt.Errorf("wallet settlement: complete: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("wallet settlement: intent not found")
	}
	return nil
}

func (db *DB) RecordWalletSettlementFailure(ctx context.Context, userID int64, refType, refID string, cause error) error {
	msg := "unknown error"
	if cause != nil {
		msg = cause.Error()
	}
	if len(msg) > 2000 {
		msg = msg[:2000]
	}
	_, err := db.conn.ExecContext(ctx, `
		UPDATE wallet_settlement_intents
		SET retry_count=retry_count+1, last_error=$1, updated_at=$2
		WHERE user_id=$3 AND reference_type=$4 AND reference_id=$5`,
		msg, db.timeArg(time.Now().UTC()), userID, refType, refID)
	return err
}

func (db *DB) ListPendingWalletSettlementIntents(ctx context.Context, limit int) ([]WalletSettlementIntent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, user_id, reference_type, reference_id, reserved_micro, actual_micro,
		       status, retry_count, COALESCE(last_error, ''), created_at, updated_at
		FROM wallet_settlement_intents
		WHERE status IN ($1, $2)
		ORDER BY updated_at, id
		LIMIT $3`, WalletSettlementSettlePending, WalletSettlementReleasePending, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]WalletSettlementIntent, 0)
	for rows.Next() {
		var item WalletSettlementIntent
		var createdRaw, updatedRaw interface{}
		if err := rows.Scan(&item.ID, &item.UserID, &item.ReferenceType, &item.ReferenceID,
			&item.ReservedMicro, &item.ActualMicro, &item.Status, &item.RetryCount,
			&item.LastError, &createdRaw, &updatedRaw); err != nil {
			return nil, err
		}
		item.CreatedAt = decodeTimeValue(createdRaw)
		item.UpdatedAt = decodeTimeValue(updatedRaw)
		out = append(out, item)
	}
	return out, rows.Err()
}

// RetryWalletSettlementIntents 幂等重试结算/释放。多节点同时执行是安全的：账本
// 幂等键确保只有一次余额变动，重放仍会把 intent 推进到终态。
func (db *DB) RetryWalletSettlementIntents(ctx context.Context, limit int) (WalletSettlementRetryResult, error) {
	items, err := db.ListPendingWalletSettlementIntents(ctx, limit)
	if err != nil {
		return WalletSettlementRetryResult{}, err
	}
	var result WalletSettlementRetryResult
	for _, item := range items {
		var opErr error
		var terminal string
		switch item.Status {
		case WalletSettlementSettlePending:
			_, opErr = db.WalletSettle(ctx, item.UserID, item.ReservedMicro, item.ActualMicro,
				item.ReferenceType, item.ReferenceID, "settle:"+item.ReferenceID)
			terminal = WalletSettlementSettled
		case WalletSettlementReleasePending:
			_, opErr = db.WalletRelease(ctx, item.UserID, item.ReservedMicro,
				item.ReferenceType, item.ReferenceID, "release:"+item.ReferenceID)
			terminal = WalletSettlementReleased
		}
		if opErr != nil {
			result.Failed++
			_ = db.RecordWalletSettlementFailure(ctx, item.UserID, item.ReferenceType, item.ReferenceID, opErr)
			continue
		}
		if err := db.CompleteWalletSettlementIntent(ctx, item.UserID, item.ReferenceType, item.ReferenceID, terminal); err != nil {
			result.Failed++
			continue
		}
		if terminal == WalletSettlementSettled {
			result.Settled++
		} else {
			result.Released++
		}
	}
	return result, nil
}

func (db *DB) GetWalletSettlementMetrics(ctx context.Context, staleAge time.Duration) (WalletSettlementMetrics, error) {
	if staleAge <= 0 {
		staleAge = 24 * time.Hour
	}
	var m WalletSettlementMetrics
	err := db.conn.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN status=$1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status=$2 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status=$3 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN retry_count > 0 AND status IN ($2,$3) THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status=$1 AND updated_at < $4 THEN 1 ELSE 0 END), 0)
		FROM wallet_settlement_intents`,
		WalletSettlementInFlight, WalletSettlementSettlePending, WalletSettlementReleasePending,
		db.timeArg(time.Now().UTC().Add(-staleAge))).
		Scan(&m.InFlight, &m.SettlePending, &m.ReleasePending, &m.Retried, &m.StaleInFlight)
	return m, err
}
