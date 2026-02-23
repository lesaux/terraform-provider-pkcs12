package pkcs12

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	goPkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestAccPkcs12FromPem_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pkcs12_from_pem" "test" {
  password        = "testpassword"
  cert_pem        = <<EOT
` + string(certificateExample) + `
EOT
  private_key_pem = <<EOT
` + string(privateKeyExample) + `
EOT
}

output "result" {
  value     = pkcs12_from_pem.test.result
  sensitive = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckPkcs12ValidFromOutput("result", "testpassword"),
				),
			},
		},
	})
}

func testAccCheckPkcs12ValidFromOutput(outputName, password string) resource.TestCheckFunc {
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

		// Password-protected PKCS12
		_, _, _, err = goPkcs12.DecodeChain(raw, password)
		if err != nil {
			return fmt.Errorf("output %s is not a valid password-protected PKCS12 bundle: %w", outputName, err)
		}

		return nil
	}
}

