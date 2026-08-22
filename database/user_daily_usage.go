package database

import (
	"context"
	"fmt"
	"time"
)

// UserDailyUsage 用户某自然日（UTC 日界）的用量，供前端趋势图。
type UserDailyUsage struct {
	Date       string  `json:"date"` // YYYY-MM-DD (UTC)
	Requests   int64   `json:"requests"`
	Tokens     int64   `json:"tokens"`
	UserBilled float64 `json:"user_billed"`
}

// GetUserDailyUsage 返回用户最近 days 天的逐日用量（新在前）。
func (db *DB) GetUserDailyUsage(ctx context.Context, userID int64, days int) ([]UserDailyUsage, error) {
	if days <= 0 || days > 90 {
		days = 30
	}
	now := time.Now().UTC()
	base := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	out := make([]UserDailyUsage, 0, days)
	for i := days - 1; i >= 0; i-- {
		dayStart := base.AddDate(0, 0, -i)
		dayEnd := dayStart.AddDate(0, 0, 1)
		item := UserDailyUsage{Date: dayStart.Format("2006-01-02")}
		err := db.conn.QueryRowContext(ctx, `
			SELECT
				COUNT(*),
				COALESCE(SUM(total_tokens), 0),
				COALESCE(SUM(user_billed), 0)
			FROM usage_logs
			WHERE api_key_id IN (SELECT id FROM api_keys WHERE user_id = $1)
			  AND created_at >= $2 AND created_at < $3
			  AND status_code <> 499`,
			userID, db.timeArg(dayStart), db.timeArg(dayEnd)).Scan(
			&item.Requests, &item.Tokens, &item.UserBilled)
		if err != nil {
			return nil, fmt.Errorf("daily usage %s: %w", item.Date, err)
		}
		out = append(out, item)
	}
	return out, nil
}
