package database

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// 金额与货币的权威表示：一律使用整数「微元」。
//
// 业务约束：钱包余额/充值以「分」(0.01 元) 为对外单位，但单次请求的扣费粒度
// 可到 0.0000000 元（7 位小数）。「分」只有 2 位小数，无法精确表达 7 位小数，
// 因此账本权威单位取两者的最小公倍精度：1 微元 = 0.0000001 元（1e-7 元）。
// 这样「分」是微元的整数倍，扣费也能精确到 1 微元，全程整数运算、零浮点误差。
const (
	// CNYMicroPerYuan 是 1 元对应的微元数（1e7）。
	CNYMicroPerYuan int64 = 10_000_000
	// CNYMicroPerFen 是 1 分对应的微元数（1e5）。
	CNYMicroPerFen int64 = 100_000
	// CNYMicroMaxDecimalPlaces 是微元能表达的最大小数位（元的小数位）。
	CNYMicroMaxDecimalPlaces = 7
)

var (
	// ErrMoneyOverflow 表示金额整数运算溢出（超出 int64 可表达范围）。
	ErrMoneyOverflow = errors.New("money: amount overflow")
	// ErrMoneyInvalid 表示金额输入非法（格式错误或精度超限）。
	ErrMoneyInvalid = errors.New("money: invalid amount")
	// ErrMoneyPrecision 表示金额小数位超过账本精度（> 7 位），拒绝以避免静默丢失精度。
	ErrMoneyPrecision = errors.New("money: amount exceeds 7 decimal places")
)

// FenToMicro 把「分」转换为微元。fen 为负表示支出/退款方向由调用方语义决定。
func FenToMicro(fen int64) (int64, error) {
	if fen > math.MaxInt64/CNYMicroPerFen || fen < math.MinInt64/CNYMicroPerFen {
		return 0, fmt.Errorf("%w: %d 分超出范围", ErrMoneyOverflow, fen)
	}
	return fen * CNYMicroPerFen, nil
}

// YuanToMicro 把「元」转换为微元（1 元 = 1e7 微元），带溢出检查。
func YuanToMicro(yuan int64) (int64, error) {
	if yuan > math.MaxInt64/CNYMicroPerYuan || yuan < math.MinInt64/CNYMicroPerYuan {
		return 0, fmt.Errorf("%w: %d 元超出范围", ErrMoneyOverflow, yuan)
	}
	return yuan * CNYMicroPerYuan, nil
}

// ParseYuanToMicro 把十进制「元」字符串精确解析为微元（不经过浮点）。
//
// 支持可选正负号、整数部分与最多 7 位小数；超过 7 位小数直接报
// ErrMoneyPrecision，绝不静默截断。空串或非法输入返回 ErrMoneyInvalid。
func ParseYuanToMicro(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, ErrMoneyInvalid
	}

	neg := false
	switch s[0] {
	case '-':
		neg = true
		s = s[1:]
	case '+':
		s = s[1:]
	}
	if s == "" {
		return 0, ErrMoneyInvalid
	}

	intPart := s
	fracPart := ""
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		intPart = s[:dot]
		fracPart = s[dot+1:]
		if strings.IndexByte(fracPart, '.') >= 0 {
			return 0, ErrMoneyInvalid
		}
	}
	if intPart == "" {
		intPart = "0"
	}
	if len(fracPart) > CNYMicroMaxDecimalPlaces {
		return 0, fmt.Errorf("%w: %q 小数位超过 %d 位", ErrMoneyPrecision, s, CNYMicroMaxDecimalPlaces)
	}
	if intPart != "0" && strings.HasPrefix(intPart, "0") {
		return 0, ErrMoneyInvalid
	}
	for _, r := range intPart + fracPart {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%w: %q", ErrMoneyInvalid, s)
		}
	}

	whole, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q 整数部分溢出", ErrMoneyOverflow, s)
	}
	wholeMicro, err := YuanToMicro(whole)
	if err != nil {
		return 0, err
	}

	// 小数部分补齐到 7 位后按整数解析，避免逐位乘除。
	fracPadded := fracPart + strings.Repeat("0", CNYMicroMaxDecimalPlaces-len(fracPart))
	fracMicro, err := strconv.ParseInt(fracPadded, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q 小数部分溢出", ErrMoneyOverflow, s)
	}

	total, err := addMicro(wholeMicro, fracMicro)
	if err != nil {
		return 0, err
	}
	if neg {
		return negMicro(total)
	}
	return total, nil
}

// FormatMicroAsYuan 把微元格式化为「元」字符串，最多 7 位小数，去掉尾部多余 0。
// 例如 100000000 -> "10"、123456789 -> "12.3456789"、0 -> "0"。
func FormatMicroAsYuan(micro int64) string {
	neg := micro < 0
	abs := micro
	if neg {
		// 仅最小 int64 会在这里溢出，但账本金额不会接近该边界；防御性处理。
		if micro == math.MinInt64 {
			abs = math.MaxInt64
		} else {
			abs = -micro
		}
	}
	whole := abs / CNYMicroPerYuan
	frac := abs % CNYMicroPerYuan
	if frac == 0 {
		if neg {
			return "-" + strconv.FormatInt(whole, 10)
		}
		return strconv.FormatInt(whole, 10)
	}
	fracStr := fmt.Sprintf("%07d", frac)
	fracStr = strings.TrimRight(fracStr, "0")
	out := strconv.FormatInt(whole, 10) + "." + fracStr
	if neg {
		return "-" + out
	}
	return out
}

// FormatMicroAsFen 把微元格式化为「分」字符串（向下取整到分，舍弃分以下余数）。
// 仅用于余额展示；权威账本仍以微元为准。
func FormatMicroAsFen(micro int64) string {
	neg := micro < 0
	abs := micro
	if neg {
		if micro == math.MinInt64 {
			abs = math.MaxInt64
		} else {
			abs = -micro
		}
	}
	fen := abs / CNYMicroPerFen
	out := strconv.FormatInt(fen, 10)
	if neg {
		return "-" + out
	}
	return out
}

// addMicro 带溢出检查的加法。
func addMicro(a, b int64) (int64, error) {
	if (b > 0 && a > math.MaxInt64-b) || (b < 0 && a < math.MinInt64-b) {
		return 0, ErrMoneyOverflow
	}
	return a + b, nil
}

// subMicro 带溢出检查的减法。
func subMicro(a, b int64) (int64, error) {
	if b == math.MinInt64 {
		return 0, ErrMoneyOverflow
	}
	return addMicro(a, -b)
}

// negMicro 带溢出检查的取负。
func negMicro(a int64) (int64, error) {
	if a == math.MinInt64 {
		return 0, ErrMoneyOverflow
	}
	return -a, nil
}
