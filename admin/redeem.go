package admin

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/database"
	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
)

// 兑换码（P6）：管理员批次管理 + 用户核销。
//
// 安全基线：
//   - 明文码只在批次创建响应里返回一次（「只显示一次」交互由前端配合）；
//   - 列表/详情接口一律不返回明文；
//   - 核销端点强制邮箱已验证，且码本身一次性（条件更新 + 账本幂等键双保险）。

// ==================== 用户侧 ====================

// RedeemCode POST /api/auth/redeem
// 请求：{"code": "XXXX-XXXX-XXXX-XXXX"}
// 响应：{"credited_micro": <金额>, "balance_micro": <核销后余额>}
func (h *Handler) RedeemCode(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	code := database.NormalizeRedeemCode(req.Code)
	if code == "" {
		writeError(c, http.StatusBadRequest, "兑换码不能为空")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// 强制邮箱已验证才能兑换（与充值一致）。
	user, err := h.db.GetUserByID(ctx, sess.UserID)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if !user.EmailVerified() {
		writeError(c, http.StatusForbidden, "请先完成邮箱验证后再兑换")
		return
	}

	credited, err := h.db.RedeemCode(ctx, sess.UserID, code)
	if err != nil {
		switch {
		case err == database.ErrRedeemCodeInvalid:
			writeError(c, http.StatusBadRequest, "兑换码格式不正确")
		case err == database.ErrRedeemCodeNotFound:
			writeError(c, http.StatusNotFound, "兑换码不存在")
		case err == database.ErrRedeemCodeUsed:
			writeError(c, http.StatusConflict, "兑换码已被使用")
		case err == database.ErrRedeemCodeRevoked:
			writeError(c, http.StatusConflict, "兑换码已被撤销")
		case err == database.ErrRedeemCodeExpired:
			writeError(c, http.StatusConflict, "兑换码已过期")
		case err == database.ErrRedeemBatchClosed:
			writeError(c, http.StatusConflict, "该兑换码所属批次已关闭")
		default:
			writeInternalError(c, err)
		}
		return
	}

	acc, err := h.db.GetWalletAccount(ctx, sess.UserID)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	balance := int64(0)
	if acc != nil {
		balance = acc.AvailableMicro
	}
	security.SecurityAuditLog("WALLET_REDEEM_CODE",
		fmt.Sprintf("user_id=%d credited_micro=%d", sess.UserID, credited))
	c.JSON(http.StatusOK, gin.H{
		"credited_micro": credited,
		"balance_micro":  balance,
	})
}

// ==================== 管理员侧 ====================

// CreateRedeemBatch POST /api/admin/redeem/batches
// 请求：{"name": "...", "amount_micro": <正数>, "count": 1..10000, "expires_at": RFC3339(可选)}
// 响应：批次信息 + codes（明文，只返回这一次）。
func (h *Handler) CreateRedeemBatch(c *gin.Context) {
	var req struct {
		Name        string `json:"name"`
		AmountMicro int64  `json:"amount_micro"`
		Count       int    `json:"count"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(c, http.StatusBadRequest, "批次名称必填")
		return
	}
	if req.AmountMicro <= 0 {
		writeError(c, http.StatusBadRequest, "amount_micro 必须是正数")
		return
	}
	if req.Count <= 0 || req.Count > 10000 {
		writeError(c, http.StatusBadRequest, "count 必须在 1 ~ 10000 之间")
		return
	}
	var expiresAt time.Time
	if strings.TrimSpace(req.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeError(c, http.StatusBadRequest, "expires_at 必须是 RFC3339 格式")
			return
		}
		expiresAt = t
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	batch, codes, err := h.db.CreateRedeemBatch(ctx, req.Name, req.AmountMicro, req.Count, expiresAt, 0)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	security.SecurityAuditLog("REDEEM_BATCH_CREATED",
		fmt.Sprintf("batch_id=%d name=%q amount_micro=%d count=%d", batch.ID, batch.Name, batch.AmountMicro, batch.TotalCount))

	c.JSON(http.StatusCreated, gin.H{
		"batch": redeemBatchJSON(*batch),
		// 明文码只在此响应中出现一次；之后任何接口都不再返回明文。
		"codes": codes,
	})
}

// ListRedeemBatches GET /api/admin/redeem/batches?limit=&offset=
func (h *Handler) ListRedeemBatches(c *gin.Context) {
	limit, _ := strconv.Atoi(strings.TrimSpace(c.Query("limit")))
	offset, _ := strconv.Atoi(strings.TrimSpace(c.Query("offset")))
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	batches, err := h.db.ListRedeemBatches(ctx, limit, offset)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	out := make([]gin.H, 0, len(batches))
	for _, b := range batches {
		out = append(out, redeemBatchJSON(b))
	}
	c.JSON(http.StatusOK, gin.H{"batches": out})
}

// GetRedeemBatch GET /api/admin/redeem/batches/:id
func (h *Handler) GetRedeemBatch(c *gin.Context) {
	batchID, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || batchID <= 0 {
		writeError(c, http.StatusBadRequest, "批次 ID 无效")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	b, err := h.db.GetRedeemBatch(ctx, batchID)
	if err != nil {
		if err == database.ErrRedeemBatchNotFound {
			writeError(c, http.StatusNotFound, "批次不存在")
			return
		}
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, redeemBatchJSON(*b))
}

// ListRedeemCodes GET /api/admin/redeem/batches/:id/codes?limit=&offset=
func (h *Handler) ListRedeemCodes(c *gin.Context) {
	batchID, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || batchID <= 0 {
		writeError(c, http.StatusBadRequest, "批次 ID 无效")
		return
	}
	limit, _ := strconv.Atoi(strings.TrimSpace(c.Query("limit")))
	offset, _ := strconv.Atoi(strings.TrimSpace(c.Query("offset")))
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	codes, err := h.db.ListRedeemCodesByBatch(ctx, batchID, limit, offset)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	out := make([]gin.H, 0, len(codes))
	for _, code := range codes {
		row := gin.H{
			"id":            code.ID,
			"prefix":        code.CodePrefix,
			"amount_micro":  code.AmountMicro,
			"status":        code.Status,
			"used_by_user":  code.UsedByUserID,
			"created_at":    code.CreatedAt.UTC().Format(time.RFC3339),
		}
		if code.UsedAt != nil {
			row["used_at"] = code.UsedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, row)
	}
	c.JSON(http.StatusOK, gin.H{"codes": out})
}

// RevokeRedeemBatch POST /api/admin/redeem/batches/:id/revoke
// 撤销批次内所有未核销码（已核销的不受影响），批次置为 closed。
func (h *Handler) RevokeRedeemBatch(c *gin.Context) {
	batchID, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || batchID <= 0 {
		writeError(c, http.StatusBadRequest, "批次 ID 无效")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	revoked, err := h.db.RevokeRedeemBatch(ctx, batchID)
	if err != nil {
		if err == database.ErrRedeemBatchNotFound {
			writeError(c, http.StatusNotFound, "批次不存在")
			return
		}
		writeInternalError(c, err)
		return
	}
	security.SecurityAuditLog("REDEEM_BATCH_REVOKED",
		fmt.Sprintf("batch_id=%d revoked_codes=%d", batchID, revoked))
	c.JSON(http.StatusOK, gin.H{"batch_id": batchID, "revoked_codes": revoked})
}

func redeemBatchJSON(b database.RedeemCodeBatch) gin.H {
	expiresAt := ""
	if b.ExpiresAt != nil {
		expiresAt = b.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return gin.H{
		"id":            b.ID,
		"name":          b.Name,
		"amount_micro":  b.AmountMicro,
		"total_count":   b.TotalCount,
		"used_count":    b.UsedCount,
		"revoked_count": b.RevokedCount,
		"status":        b.Status,
		"expires_at":    expiresAt,
		"created_at":    b.CreatedAt.UTC().Format(time.RFC3339),
	}
}
