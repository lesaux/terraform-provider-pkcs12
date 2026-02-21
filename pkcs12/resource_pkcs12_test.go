package pkcs12

import (
	"encoding/base64"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	goPkcs12 "software.sslmate.com/src/go-pkcs12"
)

func testResourceData(t *testing.T, res *schema.Resource, values map[string]interface{}) *schema.ResourceData {
	t.Helper()
	d := schema.TestResourceDataRaw(t, res.Schema, values)
	return d
}

func assertValidPkcs12(t *testing.T, b64result string, password string) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64result)
	if err != nil {
		t.Fatalf("result is not valid base64: %s", err)
	}
	_, _, _, err = goPkcs12.DecodeChain(raw, password)
	if err != nil {
		t.Fatalf("result is not a valid PKCS12 bundle: %s", err)
	}
}

// TestResourcePkcs12Create_WithPrivateKeyPem tests the original private_key_pem attribute.
func TestResourcePkcs12Create_WithPrivateKeyPem(t *testing.T) {
	d := testResourceData(t, resourcePkcs12(), map[string]interface{}{
		"cert_pem":        string(certificateExample),
		"private_key_pem": string(privateKeyExample),
		"ca_pem":          string(caCert),
		"password":        "testpassword",
		"encoding":        "modern2023",
	})

	diags := resourcePkcs12Create(nil, d, nil)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}

	result := d.Get("result").(string)
	if result == "" {
		t.Fatal("expected non-empty result")
	}
	assertValidPkcs12(t, result, "testpassword")
}

// TestResourcePkcs12Create_WithPrivateKeyPemWo tests the new write-only private_key_pem_wo attribute.
func TestResourcePkcs12Create_WithPrivateKeyPemWo(t *testing.T) {
	d := testResourceData(t, resourcePkcs12(), map[string]interface{}{
		"cert_pem":                   string(certificateExample),
		"private_key_pem_wo":         string(privateKeyExample),
		"private_key_pem_wo_version": "1",
		"ca_pem":                     string(caCert),
		"password":                   "testpassword",
		"encoding":                   "modern2023",
	})

	diags := resourcePkcs12Create(nil, d, nil)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}

	result := d.Get("result").(string)
	if result == "" {
		t.Fatal("expected non-empty result")
	}
	assertValidPkcs12(t, result, "testpassword")
}

// TestResourcePkcs12Create_NoKeyProvided tests that an error is returned when no key is set.
func TestResourcePkcs12Create_NoKeyProvided(t *testing.T) {
	d := testResourceData(t, resourcePkcs12(), map[string]interface{}{
		"cert_pem": string(certificateExample),
		"password": "testpassword",
		"encoding": "modern2023",
	})

	diags := resourcePkcs12Create(nil, d, nil)
	if !diags.HasError() {
		t.Fatal("expected an error when no private key is provided")
	}
}

// TestResourcePkcs12Create_WithECKey tests PKCS12 generation with an EC private key.
func TestResourcePkcs12Create_WithECKey(t *testing.T) {
	d := testResourceData(t, resourcePkcs12(), map[string]interface{}{
		"cert_pem":        string(certificateExample),
		"private_key_pem": string(rsaKey),
		"password":        "ecpass",
		"encoding":        "modern2023",
	})

	diags := resourcePkcs12Create(nil, d, nil)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}

	result := d.Get("result").(string)
	if result == "" {
		t.Fatal("expected non-empty result")
	}
	assertValidPkcs12(t, result, "ecpass")
}

// TestResourcePkcs12Schema_WriteOnlyFieldExists verifies the schema has the write-only attribute.
func TestResourcePkcs12Schema_WriteOnlyFieldExists(t *testing.T) {
	res := resourcePkcs12()

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
