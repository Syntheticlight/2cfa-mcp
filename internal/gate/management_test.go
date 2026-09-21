package gate

import (
	"testing"
	"time"
)

func TestManagementRequiresCurrentAuthorization(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	mgr := NewManager(Config{Enabled: true, TOTPSecret: secret})
	code, err := GenerateCurrentTOTP(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := mgr.CreateLease(code, 0, "test", "TEST")
	if err != nil {
		t.Fatal(err)
	}
	credentials := ManagementCredentials{LeaseToken: lease}
	if _, err := mgr.BeginSetup2FA("reset", ManagementCredentials{}); err == nil {
		t.Fatal("unauthorized rotation accepted")
	}
	if err := mgr.Disable2FA(ManagementCredentials{}); err == nil {
		t.Fatal("unauthorized disable accepted")
	}
	pending, err := mgr.BeginSetup2FA("reset", credentials)
	if err != nil {
		t.Fatal(err)
	}
	mgr.Lock()
	if err := mgr.Disable2FA(credentials); err == nil {
		t.Fatal("revoked lease disabled gate")
	}
	if _, err := mgr.BeginSetup2FA("reset", credentials); err == nil {
		t.Fatal("revoked lease rotated gate")
	}
	newCode, err := GenerateCurrentTOTP(pending, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := mgr.ConfirmSetup2FA(newCode, "test", "TEST"); err == nil {
		t.Fatal("pending rotation survived emergency lock")
	}
	if !mgr.IsEnabled() || mgr.totpSecret != secret {
		t.Fatal("rejected management changed security state")
	}
}
