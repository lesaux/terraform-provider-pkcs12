package pkcs12

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ ephemeral.EphemeralResource = &ephemeralPkcs12Nopass{}
)

// NewEphemeralPkcs12Nopass is a helper function to simplify the provider implementation.
func NewEphemeralPkcs12Nopass() ephemeral.EphemeralResource {
	return &ephemeralPkcs12Nopass{}
}

// ephemeralPkcs12Nopass is the resource implementation.
type ephemeralPkcs12Nopass struct{}

// Metadata returns the ephemeral resource type name.
func (e *ephemeralPkcs12Nopass) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_nopass_from_pem"
}

// Schema defines the schema for the ephemeral resource.
func (e *ephemeralPkcs12Nopass) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Creates a PKCS12 file without a password from a certificate and private key.",
		Attributes: map[string]schema.Attribute{
			"cert_pem": schema.StringAttribute{
				Description: "The certificate in PEM format.",
				Required:    true,
			},
			"private_key_pem": schema.StringAttribute{
				Description: "The private key in PEM format.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRoot("private_key_pem_wo")),
				},
			},
			"private_key_pem_wo": schema.StringAttribute{
				Description: "The write-only private key in PEM format.",
				Optional:    true,
				Sensitive:   true,
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRoot("private_key_pem")),
				},
			},
			"private_key_pem_wo_version": schema.StringAttribute{
				Description: "Version of the write-only private key.",
				Optional:    true,
			},
			"result": schema.StringAttribute{
				Description: "The base64 encoded PKCS12 file.",
				Computed:    true,
				Sensitive:   true,
			},
		},
	}
}

// Open calculates the ephemeral resource state.
func (e *ephemeralPkcs12Nopass) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var config struct {
		CertPem                 types.String `tfsdk:"cert_pem"`
		PrivateKeyPem           types.String `tfsdk:"private_key_pem"`
		PrivateKeyPemWO         types.String `tfsdk:"private_key_pem_wo"`
		PrivateKeyPemWOVersion  types.String `tfsdk:"private_key_pem_wo_version"`
		Result                  types.String `tfsdk:"result"`
	}

	// Read configuration
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Determine which private key to use
	var privateKeyPem string
	if !config.PrivateKeyPem.IsNull() && !config.PrivateKeyPem.IsUnknown() {
		privateKeyPem = config.PrivateKeyPem.ValueString()
	} else if !config.PrivateKeyPemWO.IsNull() && !config.PrivateKeyPemWO.IsUnknown() {
		privateKeyPem = config.PrivateKeyPemWO.ValueString()
	}

	if privateKeyPem == "" {
		resp.Diagnostics.AddError(
			"Missing Private Key",
			"Either private_key_pem or private_key_pem_wo must be provided.",
		)
		return
	}

	// Decode Private Key
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		resp.Diagnostics.AddError("Error decoding private key PEM", "Failed to parse private key PEM block")
		return
	}

	var privateKey interface{}
	var err error
	if block.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "EC PRIVATE KEY" {
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	} else {
		resp.Diagnostics.AddError("Unsupported private key type", fmt.Sprintf("Unsupported private key type: %s", block.Type))
		return
	}

	if err != nil {
		resp.Diagnostics.AddError("Error parsing private key", fmt.Sprintf("Could not parse private key: %v", err))
		return
	}

	// Decode Certificate
	certBlock, _ := pem.Decode([]byte(config.CertPem.ValueString()))
	if certBlock == nil {
		resp.Diagnostics.AddError("Error decoding certificate PEM", "Failed to parse certificate PEM block")
		return
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		resp.Diagnostics.AddError("Error parsing certificate", fmt.Sprintf("Could not parse certificate: %v", err))
		return
	}

	// Generate PKCS12
	// Using empty password as requested for "nopass" scenario
	pfxData, err := pkcs12.Encode(rand.Reader, privateKey, cert, nil, "")
	if err != nil {
		resp.Diagnostics.AddError("Error encoding PKCS12", fmt.Sprintf("Could not encode PKCS12: %v", err))
		return
	}

	// Encode result to Base64
	encodedResult := base64.StdEncoding.EncodeToString(pfxData)

	config.Result = types.StringValue(encodedResult)

	// Set the result
	resp.Result.Set(ctx, &config)
}
