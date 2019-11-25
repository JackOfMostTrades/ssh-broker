package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/jackofmosttrades/ssh-broker/common"
	"net/http"
)

type SshBrokerClient struct {
	hostname string
	tlsConfig *tls.Config
}

func (c *SshBrokerClient) doRequest(ctx context.Context, path string, request interface{}, response interface{}) (interface{}, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: c.tlsConfig,
		},
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://%s%s", c.hostname, path), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("unable to build reques; %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("remote request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("got non-2xx status code: %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("unable to decode response body: %w", err)
	}

	return response, nil
}

func (c *SshBrokerClient) Sign(ctx context.Context, request *common.SignRequest) (*common.SignResponse, error) {
	resp, err := c.doRequest(ctx, "/REST/v1/sign", request, new(common.SignResponse))
	if err != nil {
		return nil, err
	}
	return resp.(*common.SignResponse), nil
}

func (c *SshBrokerClient) ListKeys(ctx context.Context, request *common.ListKeysRequest) (*common.ListKeysResponse, error) {
	resp, err := c.doRequest(ctx, "/REST/v1/listKeys", request, new(common.ListKeysResponse))
	if err != nil {
		return nil, err
	}
	return resp.(*common.ListKeysResponse), nil
}


