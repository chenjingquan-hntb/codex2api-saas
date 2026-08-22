package database

import "testing"

func TestFenToMicro(t *testing.T) {
	cases := []struct {
		fen  int64
		want int64
	}{
		{0, 0},
		{1, 100_000},
		{100, 10_000_000}, // 1 元
		{-1, -100_000},
		{12345, 1_234_500_000},
	}
	for _, c := range cases {
		got, err := FenToMicro(c.fen)
		if err != nil {
			t.Fatalf("FenToMicro(%d) error: %v", c.fen, err)
		}
		if got != c.want {
			t.Errorf("FenToMicro(%d) = %d, want %d", c.fen, got, c.want)
		}
	}
}

func TestYuanToMicro(t *testing.T) {
	got, err := YuanToMicro(1)
	if err != nil {
		t.Fatalf("YuanToMicro: %v", err)
	}
	if got != 10_000_000 {
		t.Errorf("YuanToMicro(1) = %d, want 10000000", got)
	}
}

func TestParseYuanToMicro(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr error
	}{
		{"0", 0, nil},
		{"1", 10_000_000, nil},
		{"0.01", 100_000, nil},
		{"0.0000001", 1, nil},
		{"0.0000000", 0, nil},
		{"12.3456789", 123_456_789, nil},
		{"-1.5", -15_000_000, nil},
		{"+0.5", 5_000_000, nil},
		{"1.23456789", 0, ErrMoneyPrecision}, // 8 位小数，拒绝
		{"", 0, ErrMoneyInvalid},
		{"abc", 0, ErrMoneyInvalid},
		{"1.2.3", 0, ErrMoneyInvalid},
		{"01", 0, ErrMoneyInvalid}, // 前导零拒绝
	}
	for _, c := range cases {
		got, err := ParseYuanToMicro(c.in)
		if c.wantErr != nil {
			if err == nil {
				t.Errorf("ParseYuanToMicro(%q) = %d, want error %v", c.in, got, c.wantErr)
				continue
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseYuanToMicro(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseYuanToMicro(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestFormatMicroAsYuan(t *testing.T) {
	cases := []struct {
		micro int64
		want  string
	}{
		{0, "0"},
		{1, "0.0000001"},
		{100_000, "0.01"},
		{10_000_000, "1"},
		{123_456_789, "12.3456789"},
		{100_000_000, "10"},
		{-100_000, "-0.01"},
		{-10_000_000, "-1"},
	}
	for _, c := range cases {
		if got := FormatMicroAsYuan(c.micro); got != c.want {
			t.Errorf("FormatMicroAsYuan(%d) = %q, want %q", c.micro, got, c.want)
		}
	}
}

func TestFormatMicroAsFen(t *testing.T) {
	cases := []struct {
		micro int64
		want  string
	}{
		{0, "0"},
		{100_000, "1"},
		{10_000_000, "100"},
		{199_999, "1"},  // 1.99999 分，向下取整为 1 分
		{-100_000, "-1"},
	}
	for _, c := range cases {
		if got := FormatMicroAsFen(c.micro); got != c.want {
			t.Errorf("FormatMicroAsFen(%d) = %q, want %q", c.micro, got, c.want)
		}
	}
}

func TestParseFormatRoundTrip(t *testing.T) {
	for _, s := range []string{"0.0000001", "0.01", "1", "999999.9999999"} {
		micro, err := ParseYuanToMicro(s)
		if err != nil {
			t.Fatalf("ParseYuanToMicro(%q): %v", s, err)
		}
		if got := FormatMicroAsYuan(micro); got != s {
			t.Errorf("roundtrip(%q) = %q", s, got)
		}
	}
}
