package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"uvoocertctl/internal/util"
)

type godaddyRecord struct {
	Data string `json:"data"`
	TTL  int    `json:"ttl,omitempty"`
}

type GoDaddyProvider struct {
	apiKey     string
	apiSecret  string
	httpClient *http.Client
	baseURL    string
}

func NewGoDaddyProvider(cfg Config) (*GoDaddyProvider, error) {
	apiKey := util.FirstNonEmpty(cfg.APIUser)
	apiSecret := util.FirstNonEmpty(cfg.APIKey)
	if err := util.Require("godaddy api key", apiKey); err != nil {
		return nil, err
	}
	if err := util.Require("godaddy api secret", apiSecret); err != nil {
		return nil, err
	}
	return &GoDaddyProvider{
		apiKey:     apiKey,
		apiSecret:  apiSecret,
		httpClient: util.NewHTTPClient(cfg.HTTPTimeout),
		baseURL:    "https://api.godaddy.com/v1",
	}, nil
}

func (p *GoDaddyProvider) Name() string { return "godaddy" }

func (p *GoDaddyProvider) auth(req *http.Request) {
	req.Header.Set("Authorization", "sso-key "+p.apiKey+":"+p.apiSecret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
}

func (p *GoDaddyProvider) do(req *http.Request, out any) error {
	p.auth(req)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("godaddy api %s %s failed: status=%d body=%s", req.Method, req.URL.String(), resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return err
		}
	}
	return nil
}

func (p *GoDaddyProvider) CheckCredentials(ctx context.Context) error {
	u := p.baseURL + "/domains?limit=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	return p.do(req, nil)
}

func (p *GoDaddyProvider) CheckZoneAccess(ctx context.Context, domain string) error {
	zone, err := util.RootZone(domain)
	if err != nil {
		return err
	}
	u := fmt.Sprintf("%s/domains/%s", p.baseURL, url.PathEscape(zone))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	return p.do(req, nil)
}

func (p *GoDaddyProvider) ListRecords(ctx context.Context, domain string) ([]Record, error) {
	zone, err := util.RootZone(domain)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Type string `json:"type"`
		Name string `json:"name"`
		Data string `json:"data"`
		TTL  int    `json:"ttl"`
	}
	u := fmt.Sprintf("%s/domains/%s/records", p.baseURL, url.PathEscape(zone))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if err := p.do(req, &raw); err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(raw))
	for _, r := range raw {
		out = append(out, Record{Name: r.Name, Type: r.Type, TTL: r.TTL, Data: r.Data})
	}
	return out, nil
}

func (p *GoDaddyProvider) CreateRecord(ctx context.Context, domain, name, typ, value string, ttl int) error {
	zone, err := util.RootZone(domain)
	if err != nil {
		return err
	}
	name = util.RelativeRecordName(zone, name)
	if ttl <= 0 {
		ttl = 600
	}
	payload := []godaddyRecord{{Data: value, TTL: ttl}}
	body, _ := json.Marshal(payload)
	u := fmt.Sprintf("%s/domains/%s/records/%s/%s", p.baseURL, url.PathEscape(zone), url.PathEscape(strings.ToUpper(typ)), url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	return p.do(req, nil)
}

func (p *GoDaddyProvider) DeleteRecord(ctx context.Context, domain, name, typ, value string) error {
	zone, err := util.RootZone(domain)
	if err != nil {
		return err
	}
	name = util.RelativeRecordName(zone, name)
	u := fmt.Sprintf("%s/domains/%s/records/%s/%s", p.baseURL, url.PathEscape(zone), url.PathEscape(strings.ToUpper(typ)), url.PathEscape(name))
	if strings.TrimSpace(value) != "" {
		q := url.Values{}
		q.Set("value", value)
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	return p.do(req, nil)
}
