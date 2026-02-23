package pkcs12

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"software.sslmate.com/src/go-pkcs12"
)

// Ensure implementation satisfies the expected interfaces.
var (
	_ resource.Resource = &pkcs12FromPemResource{}
)

func NewPkcs12FromPemResource() resource.Resource {
	return &pkcs12FromPemResource{}
}

type pkcs12FromPemResource struct{}

type pkcs12FromPemResourceModel struct {
	ID                      types.String `tfsdk:"id"`
	Result                  types.String `tfsdk:"result"`
	CertPem                 types.String `tfsdk:"cert_pem"`
	PrivateKeyPem           types.String `tfsdk:"private_key_pem"`
	PrivateKeyPemWO         types.String `tfsdk:"private_key_pem_wo"`
	PrivateKeyPemWOVersion  types.String `tfsdk:"private_key_pem_wo_version"`
	PrivateKeyPass          types.String `tfsdk:"private_key_pass"`
	Password                types.String `tfsdk:"password"`
	CaPem                   types.String `tfsdk:"ca_pem"`
	Encoding                types.String `tfsdk:"encoding"`
}

func (r *pkcs12FromPemResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_from_pem"
}

func (r *pkcs12FromPemResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Creates a PKCS12 archive from PEM encoded certificates and keys.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"result": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cert_pem": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Certificate or certificate chain in PEM format.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"private_key_pem": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Private Key in PEM format.",
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRoot("private_key_pem_wo"), path.MatchRoot("private_key_pem_wo_version")),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"private_key_pem_wo": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Private Key (Write Only) in PEM format.",
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRoot("private_key_pem")),
					stringvalidator.AlsoRequires(path.MatchRoot("private_key_pem_wo_version")),
				},
				// WriteOnly is handled by not including it in state usually, 
				// but here we just mark it sensitive and maybe not return it in Read if possible?
				// Framework doesn't have explicit WriteOnly on schema.Attribute yet in the same way.
				// We can mark it sensitive.
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"private_key_pem_wo_version": schema.StringAttribute{
				Optional:    true,
				Description: "Private Key Version (Write Only).",
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRoot("private_key_pem")),
					stringvalidator.AlsoRequires(path.MatchRoot("private_key_pem_wo")),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"private_key_pass": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Private Key password.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"password": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Keystore password.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ca_pem": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "CA (or list of CAs) in PEM format.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"encoding": schema.StringAttribute{
				Optional:    true,
				Description: "Set encoding (e.g. 'Modern2023', 'LegacyRC2'). Defaults to 'Modern2023'.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				// If not set, we default in Create logic or use a Default value here if desired.
				// SDKv2 had Default: "modern2023".
			},
		},
	}
}

func (r *pkcs12FromPemResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan pkcs12FromPemResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	certStr := plan.CertPem.ValueString()
	privateKeyStr := plan.PrivateKeyPem.ValueString()
	if privateKeyStr == "" {
		privateKeyStr = plan.PrivateKeyPemWO.ValueString()
	}
	if privateKeyStr == "" {
		resp.Diagnostics.AddError(
			"Missing Private Key",
			"One of private_key_pem or private_key_pem_wo must be set.",
		)
		return
	}

	privateKeyPass := plan.PrivateKeyPass.ValueString()
	password := plan.Password.ValueString()
	caStr := plan.CaPem.ValueString()

	encoding := "Modern2023"
	if !plan.Encoding.IsNull() && !plan.Encoding.IsUnknown() {
		encoding = plan.Encoding.ValueString()
	}

	// Case-insensitive lookup or mapping? original SDKv2 used lowercase keys in map but allowed mixed case maybe?
	// The map had "modern", "modern2023", "legacyDES", "legacyRC2".
	// Let's normalize to match existing logic if possible.
	// But `resource_pkcs12.go` had strict keys.
	encoder := encodingMapLocal[encoding]
	// Try lowercase if not found, to be nice? existing code used exact match on `d.Get("encoding")`.
	if encoder == nil {
		resp.Diagnostics.AddError(
			"Unsupported Encoding",
			fmt.Sprintf("Unsupported encoding: %q. Supported: %q", encoding, toKeysLocal(encodingMapLocal)),
		)
		return
	}

	certificate, caListAndIntermediate, err := decodeCertsLocal([]byte(certStr))
	if err != nil {
		resp.Diagnostics.AddError("Error decoding attributes", err.Error())
		return
	}

	privateKeys, err := decodePrivateKeysFromPem([]byte(privateKeyStr), []byte(privateKeyPass))
	if err != nil {
		resp.Diagnostics.AddError("Error decoding private key", err.Error())
		return
	}
	if len(privateKeys) != 1 {
		resp.Diagnostics.AddError("Invalid private key", "private_key_pem must contain exactly one private key")
		return
	}

	if caStr != "" {
		list, err := decodePemCA([]byte(caStr))
		if err != nil {
			resp.Diagnostics.AddError("Error decoding CA", err.Error())
			return
		}
		caListAndIntermediate = append(caListAndIntermediate, list...)
	}

	res, err := encoder.Encode(privateKeys[0], certificate, caListAndIntermediate, password)
	if err != nil {
		resp.Diagnostics.AddError("Error encoding PKCS12", err.Error())
		return
	}

	// Compute ID
	hashStr := "pkcs12_" + password + certStr + privateKeyStr + caStr + encoding
	id := hashForState(hashStr)

	plan.ID = types.StringValue(id)
	plan.Result = types.StringValue(base64.StdEncoding.EncodeToString(res))

	// Write back to state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *pkcs12FromPemResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Since all fields are ForceNew or Computed, and the resource is logical (transforms data),
	// there is no external API to read from. We just keep the state.
	var state pkcs12FromPemResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *pkcs12FromPemResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Should not happen because of RequiresReplace modifiers, but logic is same as Create if we supported update.
	// For now, adhere to ForceNew behavior.
}

func (r *pkcs12FromPemResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// No-op
}

func decodeCertsLocal(certStr []byte) (*x509.Certificate, []*x509.Certificate, error) {
	certificates, err := decodeCertificates(certStr)
	if err != nil {
		return nil, nil, err
	}
	if len(certificates) == 0 {
		return nil, nil, fmt.Errorf("cert_pem must contain at least one certificate")
	}
	certificate := certificates[0]
	caListAndIntermediate := []*x509.Certificate{}
	if len(certificates) > 1 {
		caListAndIntermediate = certificates[1:]
	}
	return certificate, caListAndIntermediate, nil
}

var (
	encodingMapLocal = map[string]*pkcs12.Encoder{
		"Modern":     pkcs12.Modern,
		"Modern2023": pkcs12.Modern2023,
		"LegacyDES":  pkcs12.LegacyDES,
		"LegacyRC2":  pkcs12.LegacyRC2,
		// Case insensitive aliases to match old provider if needed,
		// or strict mapping. Old provider had: "modern", "modern2023", "legacyDES", "legacyRC2"
		"modern":     pkcs12.Modern,
		"modern2023": pkcs12.Modern2023,
		"legacyDES":  pkcs12.LegacyDES,
		"legacyRC2":  pkcs12.LegacyRC2,
	}
)

func toKeysLocal(m map[string]*pkcs12.Encoder) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}
