package goauth

import (
	"testing"
)

func TestValidateAllDynamicConfigs_NullRedirectURI_NoManualOverride(t *testing.T) {
	sdkConfig := &SdkConfiguration{
		LoginURL:    "https://app.wristband.dev/login",
		RedirectURI: "",
	}
	cr := &ConfigResolver{
		AuthConfig: &AuthConfig{},
	}
	err := cr.validateAllDynamicConfigs(sdkConfig)
	if err == nil {
		t.Fatal("Expected error when redirect_uri is empty with no manual override")
	}
	if !containsStr(err.Error(), "redirect_uri") {
		t.Errorf("Expected redirect_uri in error, got: %v", err)
	}
}

func TestValidateAllDynamicConfigs_NullRedirectURI_WithManualOverride(t *testing.T) {
	sdkConfig := &SdkConfiguration{
		LoginURL:    "https://app.wristband.dev/login",
		RedirectURI: "",
	}
	cr := &ConfigResolver{
		AuthConfig: &AuthConfig{
			SdkConfiguration: &SdkConfiguration{
				RedirectURI: "https://app.example.com/callback",
			},
		},
	}
	err := cr.validateAllDynamicConfigs(sdkConfig)
	if err != nil {
		t.Errorf("Expected no error when manual redirect_uri overrides null, got: %v", err)
	}
}

func TestValidateAllDynamicConfigs_ValidRedirectURI(t *testing.T) {
	sdkConfig := &SdkConfiguration{
		LoginURL:    "https://app.wristband.dev/login",
		RedirectURI: "https://app.example.com/callback",
	}
	cr := &ConfigResolver{
		AuthConfig: &AuthConfig{},
	}
	err := cr.validateAllDynamicConfigs(sdkConfig)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
