package pkcs12

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	//"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccEphemeralPkcs12FromPem_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
ephemeral "pkcs12_from_pem" "test" {
  password        = "testpassword"
  cert_pem        = <<EOT
` + string(certificateExample) + `
EOT
  private_key_pem = <<EOT
` + string(privateKeyExample) + `
EOT
}

output "result" {
  value = ephemeral.pkcs12_from_pem.test.result
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

// This function is already defined in resource_pkcs12_test.go, so we should remove it here or rename it.
// Leaving it commented out to avoid redeclaration error.
/*
func testAccCheckPkcs12ValidFromOutput(outputName, password string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ms := s.RootModule()
		rs, ok := ms.Outputs[outputName]
		if !ok {
			return fmt.Errorf("Not found: %s", outputName)
		}

		pfxData, err := base64.StdEncoding.DecodeString(rs.Value.(string))
		if err != nil {
			return fmt.Errorf("Base64 decode failed: %s", err)
		}

		_, _, _, err = goPkcs12.DecodeChain(pfxData, password)
		if err != nil {
			return fmt.Errorf("PKCS12 decode failed: %s", err)
		}

		return nil
	}
}
*/
