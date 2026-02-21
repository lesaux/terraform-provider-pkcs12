package pkcs12

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePkcs12Nopass() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourcePkcs12NopassCreate,
		ReadContext:   resourcePkcs12NopassRead,
		UpdateContext: resourcePkcs12NopassUpdate,
		DeleteContext: resourcePkcs12NopassDelete,
		Schema: map[string]*schema.Schema{
			"cert_pem": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "Certificate or certificate chain in PEM format",
			},
			"private_key_pem": {
				Type:          schema.TypeString,
				Optional:      true,
				Sensitive:     true,
				ForceNew:      true,
				Description:   "Private Key in PEM format",
				ConflictsWith: []string{"private_key_pem_wo", "private_key_pem_wo_version"},
			},
			"private_key_pem_wo": {
				Type:          schema.TypeString,
				Optional:      true,
				Sensitive:     true,
				WriteOnly:     true,
				Description:   "Private Key in PEM format (Write Only, accepts ephemeral values)",
				ConflictsWith: []string{"private_key_pem"},
				RequiredWith:  []string{"private_key_pem_wo_version"},
			},
			"private_key_pem_wo_version": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				Description:   "Version token for private_key_pem_wo. Changing this forces re-creation.",
				ConflictsWith: []string{"private_key_pem"},
				RequiredWith:  []string{"private_key_pem_wo"},
			},
			"private_key_pass": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Default:     "",
				Description: "Password to decrypt the private key PEM, if encrypted",
			},
			"ca_pem": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Default:     "",
				ForceNew:    true,
				Description: "CA certificate(s) in PEM format",
			},
			"encoding": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "modern2023",
				ForceNew:    true,
				Description: "PKCS12 encoding format. Supported: modern, modern2023, legacyDES, legacyRC2",
			},
			"result": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
				Description: "The passwordless PKCS12 bundle encoded as base64",
			},
		},
	}
}

func resourcePkcs12NopassCreate(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	var err error

	certStr := d.Get("cert_pem").(string)

	privatekeyStr := d.Get("private_key_pem").(string)
	if privatekeyStr == "" {
		privatekeyStr = d.Get("private_key_pem_wo").(string)
	}
	if privatekeyStr == "" {
		return diag.Errorf("one of private_key_pem or private_key_pem_wo must be set")
	}

	privatekeyPass := d.Get("private_key_pass").(string)
	caStr := d.Get("ca_pem").(string)

	encoding := d.Get("encoding").(string)
	encoder := encodingMap[encoding]
	if encoder == nil {
		return diag.FromErr(fmt.Errorf("unsupported encoding: %q. Supported: %q", encoding, toKeys(encodingMap)))
	}

	certificate, caListAndIntermediate, err := decodeCerts([]byte(certStr))
	if err != nil {
		return diag.FromErr(err)
	}

	privateKeys, err := decodePrivateKeysFromPem([]byte(privatekeyStr), []byte(privatekeyPass))
	if err != nil {
		return diag.FromErr(err)
	}
	if len(privateKeys) != 1 {
		return diag.FromErr(fmt.Errorf("private_key_pem must contain exactly one private key"))
	}

	if caStr != "" {
		list, err := decodePemCA([]byte(caStr))
		if err != nil {
			return diag.FromErr(err)
		}
		caListAndIntermediate = append(caListAndIntermediate, list...)
	}

	// Encode with empty password (passwordless)
	res, err := encoder.Encode(privateKeys[0], certificate, caListAndIntermediate, "")
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(hashForState("pkcs12_nopass_" + certStr + privatekeyStr + caStr + encoding))
	d.Set("result", base64.StdEncoding.EncodeToString(res))
	return diags
}

func resourcePkcs12NopassRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourcePkcs12NopassUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourcePkcs12NopassDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}


