package esxi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"lldp_scanner/modules"
)

// vimClient talks the vSphere Web Services API (SOAP, urn:vim25) of one
// ESXi host at https://IP/sdk. The host's certificate is its own
// self-signed one, so it is not checked: the scanner only talks to hosts
// of the local network that answered as ESXi.
type vimClient struct {
	http    *http.Client
	url     string
	action  string // the SOAPAction header, "urn:vim25/<apiVersion>"
	content serviceContent
}

// sdkURL gives the API address of a host (a variable for tests).
var sdkURL = func(ip string) string { return "https://" + net.JoinHostPort(ip, "443") + "/sdk" }

func newVimClient(ip string) *vimClient {
	jar, _ := cookiejar.New(nil)
	return &vimClient{
		http: &http.Client{
			Jar:     jar,
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				TLSHandshakeTimeout: 10 * time.Second,
				DisableKeepAlives:   true,
			},
		},
		url:    sdkURL(ip),
		action: "urn:vim25/6.5",
	}
}

// vimFault is a SOAP fault of the API: its fault type (InvalidLogin,
// RestrictedVersion, ...) and text.
type vimFault struct {
	Text   string `xml:"faultstring"`
	Detail struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"detail"`
}

func (f *vimFault) Error() string { return f.Text }

// Kind is the fault's type: the xsi:type of its detail, else the detail's
// element name without "Fault" ("InvalidLogin").
func (f *vimFault) Kind() string {
	d := xml.NewDecoder(bytes.NewReader(f.Detail.Inner))
	for {
		tok, err := d.Token()
		if err != nil {
			return ""
		}
		if start, ok := tok.(xml.StartElement); ok {
			for _, a := range start.Attr {
				if a.Name.Local == "type" {
					return a.Value[strings.LastIndex(a.Value, ":")+1:]
				}
			}
			return strings.TrimSuffix(start.Name.Local, "Fault")
		}
	}
}

// faultKind is the fault type of err, "" when it is no API fault.
func faultKind(err error) string {
	var f *vimFault
	if errors.As(err, &f) {
		return f.Kind()
	}
	return ""
}

// text escapes s for an XML element.
func text(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// call posts one request (its body element) and decodes the answer's body
// element into out (nil: the answer is not read). A SOAP fault is a
// *vimFault.
func (c *vimClient) call(ctx context.Context, body string, out any) error {
	envelope := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
		`<soapenv:Body>` + body + `</soapenv:Body></soapenv:Envelope>`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, strings.NewReader(envelope))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `"`+c.action+`"`)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	var env struct {
		Body struct {
			Fault *vimFault `xml:"Fault"`
			Inner []byte    `xml:",innerxml"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("HTTP %d from %s, no SOAP answer: %w", resp.StatusCode, c.url, err)
	}
	if env.Body.Fault != nil {
		return env.Body.Fault
	}
	if out == nil {
		return nil
	}
	return xml.Unmarshal(env.Body.Inner, out)
}

// serviceContent is the API's entry point (RetrieveServiceContent).
type serviceContent struct {
	About struct {
		FullName   string `xml:"fullName"`
		Version    string `xml:"version"`
		Build      string `xml:"build"`
		APIType    string `xml:"apiType"` // "HostAgent" on an ESXi host, "VirtualCenter" on vCenter
		APIVersion string `xml:"apiVersion"`
	} `xml:"about"`
	PropertyCollector string `xml:"propertyCollector"`
	SessionManager    string `xml:"sessionManager"`
	LicenseManager    string `xml:"licenseManager"`
}

// connect reads the service content, with no login, and speaks the host's
// API version from then on.
func (c *vimClient) connect(ctx context.Context) error {
	var resp struct {
		Returnval serviceContent `xml:"returnval"`
	}
	err := c.call(ctx, `<RetrieveServiceContent xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent>`, &resp)
	if err != nil {
		return fmt.Errorf("no vSphere API at %s: %w", c.url, err)
	}
	c.content = resp.Returnval
	if c.content.About.APIType != "" && c.content.About.APIType != "HostAgent" {
		return fmt.Errorf("%s is a %s (%s), not an ESXi host", c.url, c.content.About.APIType, c.content.About.FullName)
	}
	if v := c.content.About.APIVersion; v != "" {
		c.action = "urn:vim25/" + v
	}
	return nil
}

// login logs in; a refused login wraps modules.ErrLoginRejected.
func (c *vimClient) login(ctx context.Context, l modules.Login) error {
	err := c.call(ctx, fmt.Sprintf(`<Login xmlns="urn:vim25"><_this type="SessionManager">%s</_this><userName>%s</userName><password>%s</password></Login>`,
		text(c.content.SessionManager), text(l.Username), text(l.Password)), nil)
	if kind := faultKind(err); kind == "InvalidLogin" || kind == "NoPermission" {
		return fmt.Errorf("%w: %v", modules.ErrLoginRejected, err)
	}
	return err
}

func (c *vimClient) logout(ctx context.Context) {
	c.call(ctx, fmt.Sprintf(`<Logout xmlns="urn:vim25"><_this type="SessionManager">%s</_this></Logout>`, text(c.content.SessionManager)), nil)
}

// moRef is a managed object reference.
type moRef struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

// rawValue is a property value as the API sent it.
type rawValue struct {
	Inner []byte `xml:",innerxml"`
}

// decode reads the value into out (a struct of the value's fields, or a
// string).
func (v rawValue) decode(out any) error {
	wrapped := append(append([]byte(`<val xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">`), v.Inner...), "</val>"...)
	return xml.Unmarshal(wrapped, out)
}

// objectContent is one object's properties (RetrieveProperties).
type objectContent struct {
	Obj     moRef `xml:"obj"`
	PropSet []struct {
		Name string   `xml:"name"`
		Val  rawValue `xml:"val"`
	} `xml:"propSet"`
}

// props maps the object's properties by path.
func (o objectContent) props() map[string]rawValue {
	m := make(map[string]rawValue, len(o.PropSet))
	for _, p := range o.PropSet {
		m[p.Name] = p.Val
	}
	return m
}

// retrieve reads properties of objects: of obj itself, or with traverse
// ("vm" of a HostSystem) of the objects it lists, of type kind.
func (c *vimClient) retrieve(ctx context.Context, obj moRef, kind, traverse string, paths []string) ([]objectContent, error) {
	var b strings.Builder
	fmt.Fprintf(&b, `<RetrieveProperties xmlns="urn:vim25"><_this type="PropertyCollector">%s</_this><specSet><propSet><type>%s</type>`,
		text(c.content.PropertyCollector), text(kind))
	for _, p := range paths {
		fmt.Fprintf(&b, `<pathSet>%s</pathSet>`, text(p))
	}
	fmt.Fprintf(&b, `</propSet><objectSet><obj type="%s">%s</obj>`, text(obj.Type), text(obj.Value))
	if traverse != "" {
		fmt.Fprintf(&b, `<skip>true</skip><selectSet xsi:type="TraversalSpec"><name>traverse</name><type>%s</type><path>%s</path><skip>false</skip></selectSet>`,
			text(obj.Type), text(traverse))
	}
	b.WriteString(`</objectSet></specSet></RetrieveProperties>`)
	var resp struct {
		Returnval []objectContent `xml:"returnval"`
	}
	if err := c.call(ctx, b.String(), &resp); err != nil {
		return nil, err
	}
	return resp.Returnval, nil
}

// retrieveOne reads properties of one object.
func (c *vimClient) retrieveOne(ctx context.Context, obj moRef, paths ...string) (map[string]rawValue, error) {
	objs, err := c.retrieve(ctx, obj, obj.Type, "", paths)
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return map[string]rawValue{}, nil
	}
	return objs[0].props(), nil
}
