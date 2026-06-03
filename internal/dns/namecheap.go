package dns

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"uvoo-certctl/internal/util"
)

type NamecheapProvider struct {
	apiUser    string
	apiKey     string
	clientIP   string
	httpClient *http.Client
	baseURL    string
}

type ncAPIResponse struct {
	XMLName         xml.Name          `xml:"ApiResponse"`
	Status          string            `xml:"Status,attr"`
	Errors          []ncError         `xml:"Errors>Error"`
	CommandResponse ncCommandResponse `xml:"CommandResponse"`
}

type ncError struct {
	Number string `xml:"Number,attr"`
	Text   string `xml:",chardata"`
}

type ncCommandResponse struct {
	GetHostsResult *ncGetHostsResult `xml:"DomainDNSGetHostsResult"`
}

type ncGetHostsResult struct {
	Domain         string   `xml:"Domain,attr"`
	IsUsingOurDNS  string   `xml:"IsUsingOurDNS,attr"`
	Hosts          []ncHost `xml:"host"`
	HostsUpperCase []ncHost `xml:"Host"`
}

type ncHost struct {
	HostID string `xml:"HostId,attr"`
	Name   string `xml:"Name,attr"`
	Type   string `xml:"Type,attr"`
	Data   string `xml:"Address,attr"`
	MXPref int    `xml:"MXPref,attr"`
	TTL    int    `xml:"TTL,attr"`
}

func NewNamecheapProvider(cfg Config) (*NamecheapProvider, error) {
	apiUser := util.FirstNonEmpty(cfg.APIUser)
	apiKey := util.FirstNonEmpty(cfg.APIKey)
	clientIP := util.FirstNonEmpty(cfg.ClientIP)
	if err := util.Require("namecheap api user", apiUser); err != nil {
		return nil, err
	}
	if err := util.Require("namecheap api key", apiKey); err != nil {
		return nil, err
	}
	if err := util.Require("namecheap client ip", clientIP); err != nil {
		return nil, err
	}
	return &NamecheapProvider{
		apiUser:    apiUser,
		apiKey:     apiKey,
		clientIP:   clientIP,
		httpClient: util.NewHTTPClient(cfg.HTTPTimeout),
		baseURL:    "https://api.namecheap.com/xml.response",
	}, nil
}

func (p *NamecheapProvider) Name() string { return "namecheap" }

func (p *NamecheapProvider) params(command string) url.Values {
	v := url.Values{}
	v.Set("ApiUser", p.apiUser)
	v.Set("ApiKey", p.apiKey)
	v.Set("UserName", p.apiUser)
	v.Set("ClientIp", p.clientIP)
	v.Set("Command", command)
	return v
}

func parseZone(domain string) (sld, tld string, err error) {
	zone, err := util.RootZone(domain)
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(zone, ".", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid zone %q", zone)
	}
	return parts[0], parts[1], nil
}

func (p *NamecheapProvider) do(ctx context.Context, vals url.Values) (*ncAPIResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"?"+vals.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("namecheap http status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out ncAPIResponse
	if err := xml.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode namecheap xml: %w", err)
	}
	if strings.ToUpper(out.Status) != "OK" || len(out.Errors) > 0 {
		parts := make([]string, 0, len(out.Errors))
		for _, e := range out.Errors {
			parts = append(parts, strings.TrimSpace(e.Number+": "+e.Text))
		}
		return nil, fmt.Errorf("namecheap api error: %s", strings.Join(parts, "; "))
	}
	return &out, nil
}

func (p *NamecheapProvider) CheckCredentials(ctx context.Context) error {
	vals := p.params("namecheap.users.getBalances")
	_, err := p.do(ctx, vals)
	return err
}

func (p *NamecheapProvider) CheckZoneAccess(ctx context.Context, domain string) error {
	_, err := p.getHosts(ctx, domain)
	return err
}

func (p *NamecheapProvider) getHosts(ctx context.Context, domain string) ([]ncHost, error) {
	sld, tld, err := parseZone(domain)
	if err != nil {
		return nil, err
	}
	vals := p.params("namecheap.domains.dns.getHosts")
	vals.Set("SLD", sld)
	vals.Set("TLD", tld)
	resp, err := p.do(ctx, vals)
	if err != nil {
		return nil, err
	}
	if resp.CommandResponse.GetHostsResult == nil {
		return nil, fmt.Errorf("namecheap response missing getHosts result")
	}
	r := resp.CommandResponse.GetHostsResult
	hosts := r.Hosts
	if len(hosts) == 0 && len(r.HostsUpperCase) > 0 {
		hosts = r.HostsUpperCase
	}
	return hosts, nil
}

func (p *NamecheapProvider) ListRecords(ctx context.Context, domain string) ([]Record, error) {
	hosts, err := p.getHosts(ctx, domain)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, Record{Name: h.Name, Type: h.Type, TTL: h.TTL, Data: h.Data})
	}
	return out, nil
}

func (p *NamecheapProvider) setHosts(ctx context.Context, domain string, hosts []ncHost) error {
	sld, tld, err := parseZone(domain)
	if err != nil {
		return err
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		if hosts[i].Name == hosts[j].Name {
			if hosts[i].Type == hosts[j].Type {
				return hosts[i].Data < hosts[j].Data
			}
			return hosts[i].Type < hosts[j].Type
		}
		return hosts[i].Name < hosts[j].Name
	})
	vals := p.params("namecheap.domains.dns.setHosts")
	vals.Set("SLD", sld)
	vals.Set("TLD", tld)
	for i, h := range hosts {
		n := i + 1
		vals.Set(fmt.Sprintf("HostName%d", n), h.Name)
		vals.Set(fmt.Sprintf("RecordType%d", n), strings.ToUpper(h.Type))
		vals.Set(fmt.Sprintf("Address%d", n), h.Data)
		if h.MXPref != 0 {
			vals.Set(fmt.Sprintf("MXPref%d", n), strconv.Itoa(h.MXPref))
		}
		if h.TTL > 0 {
			vals.Set(fmt.Sprintf("TTL%d", n), strconv.Itoa(h.TTL))
		}
	}
	_, err = p.do(ctx, vals)
	return err
}

func (p *NamecheapProvider) CreateRecord(ctx context.Context, domain, name, typ, value string, ttl int) error {
	zone, err := util.RootZone(domain)
	if err != nil {
		return err
	}
	name = util.RelativeRecordName(zone, name)
	hosts, err := p.getHosts(ctx, zone)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = 60
	}
	for _, h := range hosts {
		if strings.EqualFold(h.Name, name) && strings.EqualFold(h.Type, typ) && h.Data == value {
			return nil
		}
	}
	hosts = append(hosts, ncHost{Name: name, Type: strings.ToUpper(typ), Data: value, TTL: ttl})
	return p.setHosts(ctx, zone, hosts)
}

func (p *NamecheapProvider) DeleteRecord(ctx context.Context, domain, name, typ, value string) error {
	zone, err := util.RootZone(domain)
	if err != nil {
		return err
	}
	name = util.RelativeRecordName(zone, name)
	hosts, err := p.getHosts(ctx, zone)
	if err != nil {
		return err
	}
	filtered := make([]ncHost, 0, len(hosts))
	for _, h := range hosts {
		if strings.EqualFold(h.Name, name) && strings.EqualFold(h.Type, typ) {
			if value == "" || h.Data == value {
				continue
			}
		}
		filtered = append(filtered, h)
	}
	return p.setHosts(ctx, zone, filtered)
}
