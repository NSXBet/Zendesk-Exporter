package zendesk

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	baseURLFormat = "https://%s.zendesk.com/api/v2"
)

// Client Zendesk Client
type Client struct {
	baseURL    string // ....zendesk.com/api/v2
	credential string
	client     http.Client
}

// NewClientByPassword Return Client With Information by Password Auth
func NewClientByPassword(baseURL, userAgent, passWD string) (*Client, error) {

	baseURLString := fmt.Sprintf(baseURLFormat, baseURL)
	u, err := url.Parse(baseURLString)
	if err != nil {
		return nil, err
	}
	baseURL = u.String()

	credential := base64.StdEncoding.EncodeToString([]byte(userAgent + ":" + passWD))

	return &Client{
		baseURL:    baseURL,
		credential: credential,
		client:     http.Client{},
	}, nil
}

// NewClientByToken Return Client With Information by Token Auth
func NewClientByToken(baseURL, userAgent, token string) (*Client, error) {
	baseURL = strings.TrimSuffix(baseURL, ".zendesk.com")
	baseURLString := fmt.Sprintf("https://%s.zendesk.com/api/v2", baseURL)

	auth := fmt.Sprintf("%s/token:%s", userAgent, token)
	credential := base64.StdEncoding.EncodeToString([]byte(auth))

	return &Client{
		baseURL:    baseURLString,
		credential: credential,
		client:     http.Client{},
	}, nil
}

// Get Get Request to Url
func (c *Client) Get(path string) ([]byte, error) {
	fullURL := c.baseURL + path
	fmt.Printf("DEBUG: Makingrequest to: %s\n", fullURL)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Add("Authorization", "Basic "+c.credential)

	resp, err := c.client.Do(req)
	if err != nil {
		return []byte{}, fmt.Errorf("executing request to %s: %w", c.baseURL+path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return []byte{}, fmt.Errorf("bad response from api: status=%d body=%s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("reading response body: %w", err)
	}
	return body, nil
}
