package oidc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func httpRequest(client *http.Client, req *http.Request, response any) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = cerr
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var oidcErr Error
		err = json.Unmarshal(body, &oidcErr)
		if err != nil || oidcErr.ErrorType == "" {
			return fmt.Errorf("http status not ok: %s %s", resp.Status, body)
		}
		return &oidcErr
	}

	err = json.Unmarshal(body, response)
	if err != nil {
		if req.Header.Get("Accept") != "application/json" {
			// assume the response is a plain JWT or other non-JSON format
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("failed to read response body: %v", err)
			}
			response = body
			return nil
		}
		return fmt.Errorf("failed to unmarshal response: %v %s", err, body)
	}

	return nil
}
