package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

func main() {
	ctx := context.Background()
	storage := memory.New()

	var sentOTPCode string

	// 1. Initialize GoModularAuth with EmailPassword and TwoFactor plugins
	app, err := auth.New(
		config.WithPlugins(
			plugins.EmailPassword(storage, emailpassword.WithMinPasswordLength(8)),
			plugins.TwoFactor(
				storage,
				twofactor.WithIssuer("Go Modular Auth"),
				twofactor.WithTOTPOptions(6, 30),
				twofactor.WithBackupCodeOptions(5, 10),
				twofactor.WithSendOTP(func(ctx context.Context, userID string, otp string) error {
					sentOTPCode = otp
					fmt.Printf("📲 [SMS/Email Service] Sent OTP %s to User %s\n", otp, userID)
					return nil
				}),
			),
		),
	)
	if err != nil {
		panic(err)
	}

	// 2. Subscribe to EventBus lifecycle events
	app.Events().Subscribe(emailpassword.EventSignUpBefore, func(c context.Context, payload *emailpassword.SignUpEventPayload) {
		if payload != nil && payload.Params != nil {
			payload.Params.Set(emailpassword.ExtraKeyRole, "admin")
			payload.Params.Set(emailpassword.ExtraKeyOrgID, "org_enterprise")
		}
	})

	app.Events().Subscribe(emailpassword.EventSignUpAfter, func(c context.Context, payload *emailpassword.SignUpEventPayload) {
		role, _ := payload.Params.Get(emailpassword.ExtraKeyRole)
		fmt.Printf("📢 [Global EventBus] New user registered: %s (ID: %s, Role: %v)\n", payload.User.Email, payload.User.ID, role)
	})

	app.Events().Subscribe(twofactor.EventEnableTwoFactorAfter, func(c context.Context, payload *twofactor.EnableTwoFactorAfterEventPayload) {
		fmt.Printf("📢 [Global EventBus] User %s enabled 2FA with %d backup codes\n", payload.UserID, payload.BackupCodesCount)
	})

	// 3. User registration via EmailPassword plugin
	epPlugin := auth.Plugin[emailpassword.Plugin](app)
	user, err := epPlugin.SignUp(ctx, dto.SignUpParams{
		Name:     "Gopher Go",
		Email:    "gopher@golang.org",
		Password: "SecurePassword123!",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ User created: %s (%s)\n", user.Name, user.ID)

	// 4. User authentication (Sign-in)
	signedInUser, err := epPlugin.SignIn(ctx, dto.SignInParams{
		Email:    "gopher@golang.org",
		Password: "SecurePassword123!",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ Session started for: %s (%s)\n", signedInUser.Name, signedInUser.ID)

	// 5. Two-Factor Authentication (2FA) Enrollment
	tfPlugin := auth.Plugin[twofactor.Plugin](app)
	enableRes, err := tfPlugin.Enable(ctx, twofactor.EnableParams{
		UserID: user.ID,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ 2FA Setup URI: %s\n", enableRes.TOTPURI)
	fmt.Printf("✔ Backup Codes generated: %v\n", enableRes.BackupCodes)

	// 6. Fetch stored record to compute current RFC 6238 TOTP code
	tfRecord, err := storage.FindByUserID(ctx, user.ID)
	if err != nil {
		panic(err)
	}
	currentTOTP := generateTOTPCode(tfRecord.Secret, 30, 6)
	fmt.Printf("✔ Generated current TOTP code: %s\n", currentTOTP)

	// 7. Verify TOTP code
	validTOTP, err := tfPlugin.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{
		UserID: user.ID,
		Code:   currentTOTP,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ TOTP verification result: %v\n", validTOTP)

	// 8. Verify and consume a single-use backup code
	firstBackupCode := enableRes.BackupCodes[0]
	validBackup, err := tfPlugin.VerifyBackupCode(ctx, twofactor.VerifyBackupCodeParams{
		UserID: user.ID,
		Code:   firstBackupCode,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ Backup code (%s) consumed: %v\n", firstBackupCode, validBackup)

	// 9. Challenge-based OTP (SMS / Email) flow
	if err := tfPlugin.SendOTP(ctx, twofactor.SendOTPParams{UserID: user.ID}); err != nil {
		panic(err)
	}
	validOTP, err := tfPlugin.VerifyOTP(ctx, twofactor.VerifyOTPParams{
		UserID: user.ID,
		Code:   sentOTPCode,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("✔ Out-of-band OTP verification result: %v\n", validOTP)
	fmt.Println("\n🎉 All GoModularAuth authentication flows completed successfully!")
}

// Helper to compute RFC 6238 TOTP code for testing/demo
func generateTOTPCode(secret string, period int, digits int) string {
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}

	counter := uint64(time.Now().Unix() / int64(period))
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, secretBytes)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	binCode := (int32(sum[offset]&0x7f) << 24) |
		(int32(sum[offset+1]&0xff) << 16) |
		(int32(sum[offset+2]&0xff) << 8) |
		(int32(sum[offset+3] & 0xff))

	mod := int32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, binCode%mod)
}
