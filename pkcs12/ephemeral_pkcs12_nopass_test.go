package pkcs12

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	goPkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestAccEphemeralPkcs12Nopass_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
ephemeral "pkcs12_nopass_from_pem" "test" {
  cert_pem = <<EOT
` + string(certificateExample) + `
EOT
  private_key_pem = <<EOT
` + string(privateKeyExample) + `
EOT
}

output "result" {
  value = ephemeral.pkcs12_nopass_from_pem.test.result
  sensitive = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckPkcs12NopassValidFromOutput("result"),
				),
			},
		},
	})
}

func TestAccEphemeralPkcs12Nopass_privateKeyPemWo(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
ephemeral "pkcs12_nopass_from_pem" "test" {
  cert_pem = <<EOT
` + string(certificateExample) + `
EOT
  private_key_pem_wo = <<EOT
` + string(privateKeyExample) + `
EOT
  private_key_pem_wo_version = "1"
}

output "result" {
  value = ephemeral.pkcs12_nopass_from_pem.test.result
  sensitive = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckPkcs12NopassValidFromOutput("result"),
				),
			},
		},
	})
}

func testAccCheckPkcs12NopassValidFromOutput(outputName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		o, ok := s.RootModule().Outputs[outputName]
		if !ok {
			return fmt.Errorf("output %s not found", outputName)
		}
		
		val, ok := o.Value.(string)
		if !ok {
			return fmt.Errorf("output %s is not a string", outputName)
		}
		if val == "" {
			return fmt.Errorf("output %s is empty", outputName)
		}

		raw, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return fmt.Errorf("output %s is not valid base64: %w", outputName, err)
		}
		
		// Passwordless PKCS12 uses an empty password
		_, _, _, err = goPkcs12.DecodeChain(raw, "")
		if err != nil {
			return fmt.Errorf("output %s is not a valid passwordless PKCS12 bundle: %w", outputName, err)
		}

		return nil
	}
}
