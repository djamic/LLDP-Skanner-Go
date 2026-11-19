// Package vsphere talks the vSphere Web Services API (SOAP, urn:vim25) of
// an ESXi host or a vCenter Server, for the device modules of both
// (modules/esxi, modules/vcenter): the client, and what both read and
// change of an ESXi host (host.go).
package vsphere

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"lldp_scanner/modules"
	"lldp_scanner/modules/kit"
)

// Client talks the vSphere Web Services API (SOAP, urn:vim25) of one ESXi
// host or vCenter Server at https://IP/sdk. Its certificate is its own
// self-signed one, so it is not checked: the scanner only talks to devices
// of the local network that answered as vSphere.
type Client struct {
	http    *http.Client
	url     string
	action  string // the SOAPAction header, "urn:vim25/<apiVersion>"
	Content ServiceContent
}

// SDKURL gives the API address of a device (a variable for tests).
var SDKURL = func(ip string) string { return "https://" + net.JoinHostPort(ip, "443") + "/sdk" }

// NewClient is a client of the API at ip, not yet connected.
func NewClient(ip string) *Client {
	return &Client{
		http: kit.NewHTTPClient(kit.HTTPOptions{Timeout: 60 * time.Second, HandshakeTimeout: 10 * time.Second,
			Cookies: true, NoKeepAlives: true}),
		url:    SDKURL(ip),
		action: "urn:vim25/6.5",
	}
}

// Fault is a SOAP fault of the API: its fault type (InvalidLogin,
// RestrictedVersion, ...) and text.
type Fault struct {
	Text   string `xml:"faultstring"`
	Detail struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"detail"`
}

func (f *Fault) Error() string { return f.Text }

// Kind is the fault's type: the xsi:type of its detail, else the detail's
// element name without "Fault" ("InvalidLogin").
func (f *Fault) Kind() string {
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

// FaultKind is the fault type of err, "" when it is no API fault.
func FaultKind(err error) string {
	var f *Fault
	if errors.As(err, &f) {
		return f.Kind()
	}
	return ""
}

// text escapes s for an XML element.
func Text(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// Call posts one request (its body element) and decodes the answer's body
// element into out (nil: the answer is not read). A SOAP fault is a
// *Fault.
func (c *Client) Call(ctx context.Context, body string, out any) error {
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
			Fault *Fault `xml:"Fault"`
			Inner []byte `xml:",innerxml"`
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

// ServiceContent is the API's entry point (RetrieveServiceContent).
type ServiceContent struct {
	About struct {
		FullName   string `xml:"fullName"`
		Version    string `xml:"version"`
		Build      string `xml:"build"`
		APIType    string `xml:"apiType"` // "HostAgent" on an ESXi host, "VirtualCenter" on vCenter
		APIVersion string `xml:"apiVersion"`
	} `xml:"about"`
	RootFolder        string `xml:"rootFolder"`
	PropertyCollector string `xml:"propertyCollector"`
	ViewManager       string `xml:"viewManager"` // vCenter only
	SessionManager    string `xml:"sessionManager"`
	LicenseManager    string `xml:"licenseManager"`
}

// Connect reads the service content, with no login, and speaks the API
// version of the device from then on. Which kind of device it is, is
// Content.About.APIType.
func (c *Client) Connect(ctx context.Context) error {
	var resp struct {
		Returnval ServiceContent `xml:"returnval"`
	}
	err := c.Call(ctx, `<RetrieveServiceContent xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent>`, &resp)
	if err != nil {
		return fmt.Errorf("no vSphere API at %s: %w", c.url, err)
	}
	c.Content = resp.Returnval
	if v := c.Content.About.APIVersion; v != "" {
		c.action = "urn:vim25/" + v
	}
	return nil
}

// URL is the API's address.
func (c *Client) URL() string { return c.url }

// Login logs in; a refused login wraps modules.ErrLoginRejected.
func (c *Client) Login(ctx context.Context, l modules.Login) error {
	err := c.Call(ctx, fmt.Sprintf(`<Login xmlns="urn:vim25"><_this type="SessionManager">%s</_this><userName>%s</userName><password>%s</password></Login>`,
		Text(c.Content.SessionManager), Text(l.Username), Text(l.Password)), nil)
	if kind := FaultKind(err); kind == "InvalidLogin" || kind == "NoPermission" {
		return fmt.Errorf("%w: %v", modules.ErrLoginRejected, err)
	}
	return err
}

// Logout ends the session.
func (c *Client) Logout(ctx context.Context) {
	c.Call(ctx, fmt.Sprintf(`<Logout xmlns="urn:vim25"><_this type="SessionManager">%s</_this></Logout>`, Text(c.Content.SessionManager)), nil)
}

// MoRef is a managed object reference.
type MoRef struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

// RawValue is a property value as the API sent it.
type RawValue struct {
	Inner []byte `xml:",innerxml"`
}

// Decode reads the value into out (a struct of the value's fields, or a
// string).
func (v RawValue) Decode(out any) error {
	wrapped := append(append([]byte(`<val xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">`), v.Inner...), "</val>"...)
	return xml.Unmarshal(wrapped, out)
}

// ObjectContent is one object's properties (RetrieveProperties).
type ObjectContent struct {
	Obj     MoRef `xml:"obj"`
	PropSet []struct {
		Name string   `xml:"name"`
		Val  RawValue `xml:"val"`
	} `xml:"propSet"`
}

// Props maps the object's properties by path.
func (o ObjectContent) Props() map[string]RawValue {
	m := make(map[string]RawValue, len(o.PropSet))
	for _, p := range o.PropSet {
		m[p.Name] = p.Val
	}
	return m
}

// Retrieve reads properties of objects: of obj itself, or with traverse
// ("vm" of a HostSystem, "view" of a ContainerView) of the objects it
// lists, of type kind.
func (c *Client) Retrieve(ctx context.Context, obj MoRef, kind, traverse string, paths []string) ([]ObjectContent, error) {
	var b strings.Builder
	fmt.Fprintf(&b, `<RetrieveProperties xmlns="urn:vim25"><_this type="PropertyCollector">%s</_this><specSet><propSet><type>%s</type>`,
		Text(c.Content.PropertyCollector), Text(kind))
	for _, p := range paths {
		fmt.Fprintf(&b, `<pathSet>%s</pathSet>`, Text(p))
	}
	fmt.Fprintf(&b, `</propSet><objectSet><obj type="%s">%s</obj>`, Text(obj.Type), Text(obj.Value))
	if traverse != "" {
		fmt.Fprintf(&b, `<skip>true</skip><selectSet xsi:type="TraversalSpec"><name>traverse</name><type>%s</type><path>%s</path><skip>false</skip></selectSet>`,
			Text(obj.Type), Text(traverse))
	}
	b.WriteString(`</objectSet></specSet></RetrieveProperties>`)
	var resp struct {
		Returnval []ObjectContent `xml:"returnval"`
	}
	if err := c.Call(ctx, b.String(), &resp); err != nil {
		return nil, err
	}
	return resp.Returnval, nil
}

// RetrieveOne reads properties of one object.
func (c *Client) RetrieveOne(ctx context.Context, obj MoRef, paths ...string) (map[string]RawValue, error) {
	objs, err := c.Retrieve(ctx, obj, obj.Type, "", paths)
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return map[string]RawValue{}, nil
	}
	return objs[0].Props(), nil
}

// ContainerView makes a view of every object of type kind below the root
// folder (a vCenter's hosts, its virtual machines), for Retrieve with
// traverse "view"; DestroyView removes it.
func (c *Client) ContainerView(ctx context.Context, kind string) (MoRef, error) {
	if c.Content.ViewManager == "" {
		return MoRef{}, fmt.Errorf("%s has no view manager", c.url)
	}
	var resp struct {
		Returnval MoRef `xml:"returnval"`
	}
	err := c.Call(ctx, fmt.Sprintf(`<CreateContainerView xmlns="urn:vim25"><_this type="ViewManager">%s</_this><container type="Folder">%s</container>`+
		`<type>%s</type><recursive>true</recursive></CreateContainerView>`, Text(c.Content.ViewManager), Text(c.Content.RootFolder), Text(kind)), &resp)
	if err != nil {
		return MoRef{}, err
	}
	if resp.Returnval.Type == "" {
		resp.Returnval.Type = "ContainerView"
	}
	return resp.Returnval, nil
}

// DestroyView removes a view of ContainerView.
func (c *Client) DestroyView(ctx context.Context, view MoRef) {
	c.Call(ctx, fmt.Sprintf(`<DestroyView xmlns="urn:vim25"><_this type="ContainerView">%s</_this></DestroyView>`, Text(view.Value)), nil)
}
