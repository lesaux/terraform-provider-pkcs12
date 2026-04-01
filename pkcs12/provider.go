package pkcs12

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ provider.Provider = &pkcs12Provider{}
)

// New is a helper function to simplify provider server and testing implementation.
func New() provider.Provider {
	return &pkcs12Provider{}
}

// pkcs12Provider is the provider implementation.
type pkcs12Provider struct{}

// Metadata returns the provider type name.
func (p *pkcs12Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pkcs12"
}

// Schema defines the provider-level schema for configuration data.
func (p *pkcs12Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

// Configure prepares a pkcs12Provider for data sources and resources.
func (p *pkcs12Provider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
}

// DataSources defines the data sources implemented in the provider.
func (p *pkcs12Provider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

// Resources defines the resources implemented in the provider.
func (p *pkcs12Provider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewPkcs12FromPemResource,
	}
}

// EphemeralResources defines the ephemeral resources implemented in the provider.
func (p *pkcs12Provider) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		NewEphemeralPkcs12Nopass,
		NewEphemeralPkcs12,
	}
}
