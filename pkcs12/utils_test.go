package pkcs12

import (
	"testing"
)

var (
	privateKeysExamplePass      = []byte("testpass")
	privateKeysEncryptedExample = []byte(`
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1DB3F6C25F244D3250C9FE4EC7EDBA76

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
-----END RSA PRIVATE KEY-----
`)

	allInOnePem = []byte(
		string(certificateExample) + "\n" + string(caCert) + "\n",
	)

	caCert = []byte(`
-----BEGIN CERTIFICATE-----
MIICGTCCAZ+gAwIBAgIQCeCTZaz32ci5PhwLBCou8zAKBggqhkjOPQQDAzBOMQsw
CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xJjAkBgNVBAMTHURp
Z2lDZXJ0IFRMUyBFQ0MgUDM4NCBSb290IEc1MB4XDTIxMDExNTAwMDAwMFoXDTQ2
MDExNDIzNTk1OVowTjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
bmMuMSYwJAYDVQQDEx1EaWdpQ2VydCBUTFMgRUNDIFAzODQgUm9vdCBHNTB2MBAG
ByqGSM49AgEGBSuBBAAiA2IABMFEoc8Rl1Ca3iOCNQfN0MsYndLxf3c1TzvdlHJS
7cI7+Oz6e2tYIOyZrsn8aLN1udsJ7MgT9U7GCh1mMEy7H0cKPGEQQil8pQgO4CLp
0zVozptjn4S1mU1YoI71VOeVyaNCMEAwHQYDVR0OBBYEFMFRRVBZqz7nLFr6ICIS
B4CIfBFqMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
BAMDA2gAMGUCMQCJao1H5+z8blUD2WdsJk6Dxv3J+ysTvLd6jLRl0mlpYxNjOyZQ
LgGheQaRnUi/wr4CMEfDFXuxoJGZSZOoPHzoRgaLLPIxAJSdYsiJvRmEFOml+wG4
DXZDjC5Ty3zfDBeWUA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICHDCCAaOgAwIBAgIQBT9uoAYBcn3tP8OjtqPW7zAKBggqhkjOPQQDAzBQMQsw
CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xKDAmBgNVBAMTH0Rp
Z2lDZXJ0IFNNSU1FIEVDQyBQMzg0IFJvb3QgRzUwHhcNMjEwMTE1MDAwMDAwWhcN
NDYwMTE0MjM1OTU5WjBQMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
IEluYy4xKDAmBgNVBAMTH0RpZ2lDZXJ0IFNNSU1FIEVDQyBQMzg0IFJvb3QgRzUw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQWnVXlttT7+2drGtShqtJ3lT6I5QeftnBm
ICikiOxwNa+zMv83E0qevAED3oTBuMbmZUeJ8hNVv82lHghgf61/6GGSKc8JR14L
HMAfpL/yW7yY75lMzHBrtrrQKB2/vgSjQjBAMB0GA1UdDgQWBBRzemuW20IHi1Jm
wmQyF/7gZ5AurTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAwNnADBkAjA3RPUygONx6/Rtz3zMkZrDbnHY0iNdkk2CQm1cYZX2kfWn
CPZql+mclC2YcP0ztgkCMAc8L7lYgl4Po2Kok2fwIMNpvwMsO1CnO69BOMlSSJHW
Dvu8YDB8ZD8SHkV/UT70pg==
-----END CERTIFICATE-----
`)

	ecPrivateKey = []byte(`
-----BEGIN EC PARAMETERS-----
MIGiAgEBMCwGByqGSM49AQECIQD////////////////////////////////////+
///8LzAGBAEABAEHBEEEeb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hI
Otp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuAIhAP//////////////////
//66rtzmr0igO7/SXozQNkFBAgEB
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIIBEwIBAQQgTT3OMYeuQZDjn3zE88wT6Kr+bM3b4rL++lJFa+80M2yggaUwgaIC
AQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wv
MAYEAQAEAQcEQQR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEg62ncm
o8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA/////////////////////rqu
3OavSKA7v9JejNA2QUECAQGhRANCAAQqk8ptTVDVDURvuxHug5DUAm50IdoNKSdQ
hczq27UIZwO/WqvmllOZ1EKkTAQUNzWS/wQpNa/5fGMDD6qUNdW3
-----END EC PRIVATE KEY-----

`)

	rsaKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA72ObzM8bnHTCJj50djkEdF+TVlg8z7CkwSPjPANjXNhBWHVB
8HBUtUKLJsoHGTj35+9Uq6CuGymB3d0s5r5LBa3ywF0QeP57Qa1f9gkEupFArgek
FYgXXi8u5HNoaT7FCgNum6fkXF7DsjSidGe0Z1VYj2HKavah51r8URv38QTswUqq
icXLlPD5K27PNNYRUUhZ54q2VwyZMgeLPHTYBAyC99OY8KlnVjkzqir8B2pGKsAO
iBaoc6FJ+0C6CR32rU3hfdBnbh8+c4S5i5lYaQz+iP6dU+CMxq39JGFQuao66UnK
gpUgiKVvT5QYI/92oofCahD88RM3HXejTO+TXwIDAQABAoIBAQCSXW627LJPGLxU
Mb93QSlOFdm54z1bJv+070JSQSgRbk+VzCvC3IuOP99gmgl5DHHWp2g3f4i0Js62
XjLD6flowZA4uS4HLGEkKOMRRTZU89Z+EUHrwEe5WFPtbfqazrwegTaxiReAupgg
bzocvgN5Yp9BG2NtvtoC4IiA9v7DpzZVPFKbpVlEYWMle+RGBtzD/9h0u2k3Psux
MTU9YcRyvej5+3yyri/YV+mzve3QXaZdACR8AfQbFT3bV9M50rsGOFt+3VsH0gwr
2IrdQNLgxqON9NIHlW6ORe5TbAXhwTiAkKEJcHjjRVROtNnerdRWtZSTDxk7d/d2
bv012WZRAoGBAP9PQpHVdEvqPV2L1WRSKCaSqaHwJFimuQCM0KDJytgdD9Rzlz8B
GAjv0k1zreZj7Ap4vGsxNBYGY4k5HpPWI5HvQ00zXxgPX4uSkYCVE2U7RjODuJq0
KzFLDGDOELW6sIj299Yx4mCnCYW8vHNmYiZCbOugWTV5yjYUWbOJA4LbAoGBAPAJ
U9SgFC+NgCE7z+PgoK/iouGXnpnHHy0o8ju1vX/XbzJbXrF5btPSuDP+Fyj+sMbg
xvKSlFIsk+gVjEBH0ZbP1O2CXWp6DDldMf6YlYMiXoM7ZaxfSXmQOcneNzH3GOjD
lcfV+N8CXphfGSnfuE5+YCZGCJvQXPt5i2RhqH7NAoGAbVvd/+mWrw3eyzsiZJ5s
ZFleH+dlKjP/+qRWmQjWwktwhGge2PX2/Zz8UADE9HLIoJOm4aNp1CVYbWbyGhEX
m2MJSQBAM2YiXv6hJJq2fB4vq9E4OcwC1FJ5Mt4RekZFZ+WhszYa6ZujEI4Pir7I
O+soDKXakHVikFeXNLfzsRECgYEAyocUNFLctUKu2VueDKd67OxMggtrxlQ7+d6S
g87UFQmwyMxPGW9cE124DiZVZEGA5kzBj+odOzhhk3Ca5aGzNYwmHD/ikfRoW/5G
MIqNnBdjp1Z2cvnzBJ6sI6da6s2SNtLPjcz8Ly3Qor+ae7pHx/LZLXHp0Y385jGn
awr7IAECgYEA/U6FebKQOADU8mdjo6ir1ghTzJD/nivjeYi4rNH7ObTW1JbmjF9D
AB3dJTEmWSgUTDaCpY1aFR0NFMfdkOsPwT2tHtUBddx3Em5dZc3CNlI3j5CJ9x2C
ogrIU+Z+JyIPd47DI8acKlzGeR2Wn5hQrdQApC0Ve2Lvmbz8Hj67pJ4=
-----END RSA PRIVATE KEY-----

`)
)

func TestDecodeCertificateAllInOne(t *testing.T) {
	cert, list, err := decodeCerts(allInOnePem)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if len(list) != 2 {
		t.Log(len(list))
		t.Error("certificate list must a certificate and ca's")
		t.FailNow()
	}

	if cert.IsCA {
		t.Error("certificate[0] must not be a CA")
	}

	if !list[0].IsCA {
		t.Error("certificate[0] must be a CA")
	}
	if !list[1].IsCA {
		t.Error("certificate[1] must be a CA")
	}
}

func TestDecodeCertificate(t *testing.T) {
	cert, list, err := decodeCerts(certificateExample)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if len(list) != 0 {
		t.Error("certificateExample must not contain any CAs")
		t.FailNow()
	}

	if cert.IsCA {
		t.Error("certificate must not ba a CA")
	}
}

func TestDecodeCA(t *testing.T) {
	c, err := decodePemCA(caCert)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if len(c) != 2 {
		t.Error("must return one CA")
		t.FailNow()
	}

	for i, ca := range c {
		if !ca.IsCA {
			t.Errorf("certificate[%d] must be a CA", i)
		}
	}

}

func TestDecodePrivateKeysEncypted(t *testing.T) {
	keys, err := decodePrivateKeysFromPem(privateKeysEncryptedExample, privateKeysExamplePass)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if len(keys) != 1 {
		t.Error("result must contain one private key")
		t.FailNow()
	}
}

func TestDecodePrivateKeys(t *testing.T) {
	keys, err := decodePrivateKeysFromPem(privateKeyExample, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if len(keys) != 1 {
		t.Error("result must contain one private key")
		t.FailNow()
	}
}

func TestDecodePrivateKeysEC(t *testing.T) {

	_, err := decodePrivateKeysFromPem(ecPrivateKey, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

}

func TestDecodePrivateKeysRSA(t *testing.T) {

	_, err := decodePrivateKeysFromPem(rsaKey, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}

func TestDecodePrivateBadString(t *testing.T) {

	_, err := decodePrivateKeysFromPem([]byte("cdcdklmcdlkmcd\nxxsx\ncdcdc"), nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

}
