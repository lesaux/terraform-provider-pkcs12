package pkcs12

import (
	"encoding/base64"
	"testing"

	goPkcs12 "software.sslmate.com/src/go-pkcs12"
)

func assertValidPkcs12Nopass(t *testing.T, b64result string) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64result)
	if err != nil {
		t.Fatalf("result is not valid base64: %s", err)
	}
	// Passwordless PKCS12 uses an empty password
	_, _, _, err = goPkcs12.DecodeChain(raw, "")
	if err != nil {
		t.Fatalf("result is not a valid passwordless PKCS12 bundle: %s", err)
	}
}

// TestResourcePkcs12Nopass_WithPrivateKeyPem tests the original private_key_pem attribute.
func TestResourcePkcs12Nopass_WithPrivateKeyPem(t *testing.T) {
	d := testResourceData(t, resourcePkcs12Nopass(), map[string]interface{}{
		"cert_pem":        string(certificateExample),
		"private_key_pem": string(privateKeyExample),
		"ca_pem":          string(caCert),
		"encoding":        "modern2023",
	})

	diags := resourcePkcs12NopassCreate(nil, d, nil)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}

	result := d.Get("result").(string)
	if result == "" {
		t.Fatal("expected non-empty result")
	}
	assertValidPkcs12Nopass(t, result)
}

// TestResourcePkcs12Nopass_WithPrivateKeyPemWo tests the write-only private_key_pem_wo attribute.
func TestResourcePkcs12Nopass_WithPrivateKeyPemWo(t *testing.T) {
	d := testResourceData(t, resourcePkcs12Nopass(), map[string]interface{}{
		"cert_pem":                   string(certificateExample),
		"private_key_pem_wo":         string(privateKeyExample),
		"private_key_pem_wo_version": "1",
		"ca_pem":                     string(caCert),
		"encoding":                   "modern2023",
	})

	diags := resourcePkcs12NopassCreate(nil, d, nil)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}

	result := d.Get("result").(string)
	if result == "" {
		t.Fatal("expected non-empty result")
	}
	assertValidPkcs12Nopass(t, result)
}

// TestResourcePkcs12Nopass_NoKeyProvided tests that an error is returned when no key is set.
func TestResourcePkcs12Nopass_NoKeyProvided(t *testing.T) {
	d := testResourceData(t, resourcePkcs12Nopass(), map[string]interface{}{
		"cert_pem": string(certificateExample),
		"encoding": "modern2023",
	})

	diags := resourcePkcs12NopassCreate(nil, d, nil)
	if !diags.HasError() {
		t.Fatal("expected an error when no private key is provided")
	}
}

// TestResourcePkcs12Nopass_NoCaPem tests that ca_pem is optional.
func TestResourcePkcs12Nopass_NoCaPem(t *testing.T) {
	d := testResourceData(t, resourcePkcs12Nopass(), map[string]interface{}{
		"cert_pem":        string(certificateExample),
		"private_key_pem": string(privateKeyExample),
		"encoding":        "modern2023",
	})

	diags := resourcePkcs12NopassCreate(nil, d, nil)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}

	result := d.Get("result").(string)
	if result == "" {
		t.Fatal("expected non-empty result")
	}
	assertValidPkcs12Nopass(t, result)
}

// TestResourcePkcs12Nopass_ResultHasNoPassword verifies the bundle cannot be opened with a non-empty password.
func TestResourcePkcs12Nopass_ResultHasNoPassword(t *testing.T) {
	d := testResourceData(t, resourcePkcs12Nopass(), map[string]interface{}{
		"cert_pem":        string(certificateExample),
		"private_key_pem": string(privateKeyExample),
		"encoding":        "modern2023",
	})

	diags := resourcePkcs12NopassCreate(nil, d, nil)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}

	result := d.Get("result").(string)
	raw, _ := base64.StdEncoding.DecodeString(result)

	_, _, _, err := goPkcs12.DecodeChain(raw, "somepassword")
	if err == nil {
		t.Fatal("expected decoding with a non-empty password to fail for a passwordless PKCS12")
	}
}

// TestResourcePkcs12NopassSchema_WriteOnlyFieldExists verifies the schema has the write-only attribute.
func TestResourcePkcs12NopassSchema_WriteOnlyFieldExists(t *testing.T) {
	res := resourcePkcs12Nopass()

	woAttr, ok := res.Schema["private_key_pem_wo"]
	if !ok {
		t.Fatal("expected private_key_pem_wo to exist in schema")
	}
	if !woAttr.WriteOnly {
		t.Error("expected private_key_pem_wo to have WriteOnly: true")
	}
	if !woAttr.Sensitive {
		t.Error("expected private_key_pem_wo to have Sensitive: true")
	}
	// SDK forbids WriteOnly + ForceNew together; replacement is driven by _wo_version
	if woAttr.ForceNew {
		t.Error("expected private_key_pem_wo to have ForceNew: false (WriteOnly and ForceNew are mutually exclusive)")
	}

	versionAttr, ok := res.Schema["private_key_pem_wo_version"]
	if !ok {
		t.Fatal("expected private_key_pem_wo_version to exist in schema")
	}
	if !versionAttr.ForceNew {
		t.Error("expected private_key_pem_wo_version to have ForceNew: true")
	}
}
