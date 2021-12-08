package main

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"html/template"
	"image"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"

	_ "image/jpeg"
	_ "image/png"

	"github.com/aaronarduino/goqrsvg"
	svg "github.com/ajstarks/svgo"
	"github.com/boombuler/barcode/qr"
	"github.com/dasio/base45"
	"github.com/fxamacker/cbor/v2"
	"github.com/icedream/fancy-vaccert/schema"
	"github.com/liyue201/goqr"
	"github.com/voicera/gooseberry/urn"
	"go.mozilla.org/cose"
)

var errMultipleCodesDetected = errors.New("multiple codes detected")
var errInvalidQRNotText = errors.New("invalid QR: not text")
var errInvalidQRNotHealthCertificateV1 = errors.New("invalid QR: not a health certificate v1")

func main() {
	if len(os.Args) < 2 {
		panic("missing file name")
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()

	img, _, err := image.Decode(f)
	if err != nil {
		panic(err)
	}

	if err = createFromImage(img); err != nil {
		panic(err)
	}
}

var rxX509NameSplit = regexp.MustCompile(`[^\\],\s*`)

type subjectParsePhase byte

const (
	subjectParsePhaseKey = iota
	subjectParsePhaseValue
)

func matchIssuer(name string, subject string) bool {
	var value string
	var key string
	var phase subjectParsePhase

	for len(subject) > 0 {
		index := strings.IndexAny(subject, `\,=`)

		if index >= 1 {
			value += subject[0:index]
		}
		if index > 0 {
			char := subject[index]
			subject = subject[index+1:]
			switch {
			case char == '\\':
				value += string(subject[0]) // add next character without processing it
				subject = subject[1:]       // continue after that character

			case char == '=' && phase == subjectParsePhaseKey:
				value = strings.TrimSpace(value)
				key = value
				value = ""
				phase = subjectParsePhaseValue

			case char == ',' && phase == subjectParsePhaseValue:
				value = strings.TrimSpace(value)
				if strings.ToUpper(key) == "CN" && value == name {
					return true
				}
				value = ""
				phase = subjectParsePhaseKey

			default: // second =?
				value += string(char)
			}
		} else {
			value += subject
			break
		}
	}
	return false
}

// TODO - create from webcam

// Signed CWT is defined in RFC 8392
type signedCWT struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected coseHeader
	Payload     []byte
	Signature   []byte
}

// Part of COSE header definition
type coseHeader struct {
	Alg int    `cbor:"1,keyasint,omitempty"`
	Kid []byte `cbor:"4,keyasint,omitempty"`
	IV  []byte `cbor:"5,keyasint,omitempty"`
}

// HCERT payload from https://github.com/ehn-dcc-development/hcert-spec/blob/main/hcert_spec.md
type healthCertificate struct {
	EUDigitalCovidCertificate1 *schema.DCCCombinedSchemaJson `cbor:"1,keyasint"`
}

// Common Payload Values from https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-certificates_v3_en.pdf, Section 2.6.3
type dgcPayload struct {
	Issuer            string            `cbor:"1,keyasint"`
	IssueDate         uint64            `cbor:"6,keyasint"`
	ExpiryDate        uint64            `cbor:"4,keyasint"`
	HealthCertificate healthCertificate `cbor:"-260,keyasint"`
}

func createFromImage(img image.Image) (err error) {
	detectedCodes, err := goqr.Recognize(img)
	if err != nil {
		return
	}

	if len(detectedCodes) > 1 {
		return errMultipleCodesDetected
	}

	detectedCode := detectedCodes[0]

	// Is this a valid text QR code?
	if detectedCode.DataType != 2 &&
		detectedCode.DataType != 4 /* TODO - delete type 4 */ {
		err = errInvalidQRNotText
		return
	}

	// Is this a valid health certificate that we support? (Starts with HC1:)
	if len(detectedCode.Payload) < 4 || string(detectedCode.Payload[0:4]) != "HC1:" {
		err = errInvalidQRNotHealthCertificateV1
		return
	}

	// Transform base45-encoded data to COSE/CBOR
	b45Decoder := base45.NewDecoder(bytes.NewReader(detectedCode.Payload[4:]))

	// Decompress COSE/CBOR
	decompressor, err := zlib.NewReader(b45Decoder)
	if err != nil {
		return
	}
	defer decompressor.Close()
	decompressedBytes, err := io.ReadAll(decompressor)

	// Create TagSet (safe for concurrency).
	tags := cbor.NewTagSet()
	// Register tag COSE_Sign1 18 with signedCWT type.
	tags.Add(
		cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(signedCWT{}),
		18)

	// Create DecMode with immutable tags.
	dm, _ := cbor.DecOptions{}.DecModeWithTags(tags)

	// Unmarshal to signedCWT with tag support.
	var cwt signedCWT
	if err := dm.Unmarshal(decompressedBytes, &cwt); err != nil {
		return err
	}

	// Extract protected header, unprotected header, payload and signature
	msg := cose.NewSignMessage()
	msg.Payload = cwt.Payload
	// msg.Signatures[0].Decode(cwt.Signature)
	sh := &cose.Headers{}
	err = sh.Decode([]interface{}{cwt.Protected, msg.Headers.Unprotected})
	if err != nil {
		return fmt.Errorf("cbor: %s", err.Error())
	}
	msg.Signatures = []cose.Signature{
		{
			Headers:        sh,
			SignatureBytes: cwt.Signature,
		},
	}
	msg.Headers.Unprotected = map[interface{}]interface{}{
		"alg": cwt.Unprotected.Alg,
		"kid": cwt.Unprotected.Kid,
		"IV":  cwt.Unprotected.IV,
	}
	msg.Headers.DecodeProtected(cwt.Protected)

	// TODO - Unmarshal the payload into our data structure
	payload := dgcPayload{}
	if err = cbor.Unmarshal(msg.Payload, &payload); err != nil {
		return
	}

	qrsvg := new(bytes.Buffer)

	cleanQRCode, err := qr.Encode(string(detectedCode.Payload), qr.H, qr.AlphaNumeric)

	s := svg.New(qrsvg)

	qs := goqrsvg.NewQrSVG(cleanQRCode, 1)
	s.Startraw("width=\"6cm\"", "height=\"6cm\"", "class=\"qrimg\"", "shape-rendering=\"crispEdges\"", fmt.Sprintf("viewBox=\"%d %d %d %d\"", 0, 0, 97, 97))
	qs.WriteQrSVG(s)

	funcMap := template.FuncMap{
		"parseURN": func(urnValue interface{}) string {
			var urnStr string
			switch v := urnValue.(type) {
			case string:
				urnStr = v
			case schema.CertificateId:
				urnStr = string(v)
			default:
				panic("passed non-string to parseURN which expects a string")
			}

			// fix URN: prefix for the urn package which only checks for lowercase
			if strings.HasPrefix(strings.ToUpper(urnStr), "URN:") {
				urnStr = "urn:" + urnStr[4:]
			}

			u, ok := urn.TryParseString(urnStr)
			if !ok {
				panic("could not parse URN " + urnStr)
			}

			return u.GetNamespaceSpecificString()
		},
	}

	html := template.Must(template.New("html").Funcs(funcMap).Parse(`<!doctype html>
<html>
	<head>
		<style>
		body {
			/* !important is to avoid Dark Reader trying to invert colors */
			background: #fff !important;
			color: #000 !important;
			font-family: "Open Sans", sans-serif;
			font-size: 0.4cm;
		}
		.container {
			border: gold .33em solid;
			border-radius: 10px;
			margin: 0.33cm;
			padding: 0.33cm;
			display: flex;
			max-width: 14cm;
			width: 14cm;
			max-height: 7cm;
			height: 7cm;
			flex-direction: row;
			justify-content: center;
			align-items: center;
		}
		.container .meta {
			flex-grow: 1;
			margin-left: 0.33cm;
		}
		.meta .name {
			font-weight: bold;
			font-size: 1.8em;
			margin-bottom: 0.5em;
		}
		.meta .name .first::after {
			content: ', ';
		}
		.meta .certificate {
			font-size: 0.66em;
		}
		</style>
	</head>
	<body>
		<div class="container">
			<div class="qr">
				{{ $.qrsvg }}
			</div>
			<div class="meta">
				<div class="name">
					<span class="first">{{ $.payload.HealthCertificate.EUDigitalCovidCertificate1.Nam.Fn }}</span>
					<span class="last">{{ $.payload.HealthCertificate.EUDigitalCovidCertificate1.Nam.Gn }}</span>
				</div>
				<div class="birthdate">
					<b>Geburtsdatum:</b>
					{{ $.payload.HealthCertificate.EUDigitalCovidCertificate1.Dob }}
				</div>
				{{ range .payload.HealthCertificate.EUDigitalCovidCertificate1.V }}
				<div class="certificate">
					<span class="certificate-identifier">
						{{ parseURN .Ci }}
					</span>
				</div>
				{{ end }}
			</div>
		</div>
	</body>
</html>
`))

	err = html.Execute(os.Stdout, map[string]interface{}{
		"qrsvg":   template.HTML(qrsvg.String()),
		"payload": payload,
	})

	return
}
