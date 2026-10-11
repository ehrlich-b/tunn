package store

import (
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
)

func TestDeviceCodeOwnerNormalization(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewDeviceCodeStore(db)
	for _, email := range []string{" Owner@Example.COM ", "Ｏｗｎｅｒ@Example.COM"} {
		code, err := s.Create()
		if err != nil {
			t.Fatal(err)
		}
		if !s.Authorize(code.Code, email) {
			t.Fatal("authorization failed")
		}
		var stored string
		if err := db.QueryRow(`SELECT email FROM device_codes WHERE code=?`, code.Code).Scan(&stored); err != nil || stored != common.NormalizeEmail(email) {
			t.Errorf("stored owner=%q, error=%v", stored, err)
		}
		// A pre-fix authorized code must also be canonical on both lookups.
		if _, err := db.Exec(`UPDATE device_codes SET email=? WHERE code=?`, email, code.Code); err != nil {
			t.Fatal(err)
		}
		for _, got := range []*DeviceCode{s.Get(code.Code), s.GetByUserCode(code.UserCode)} {
			if got == nil || got.Email != common.NormalizeEmail(email) {
				t.Errorf("noncanonical code lookup: %+v", got)
			}
		}
	}
}
