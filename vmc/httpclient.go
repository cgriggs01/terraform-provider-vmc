/* Copyright 2019 VMware, Inc.
   SPDX-License-Identifier: MPL-2.0 */

// Package helper provides the helper methods for getting HTTP Client
//  and client.Connector instances for VMC, required to call VMC APIs.
package vmc

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

// HTTPClient returns http client configured with Server Cert and Server Cert Key files for verifying server over TLS.
func HTTPClient(certFile string, certKeyFile string) (http.Client, error) {
	if len(certFile) <= 0 {
		return *http.DefaultClient, fmt.Errorf("Invalid Cert File: " + certFile)
	}
	if len(certKeyFile) <= 0 {
		return *http.DefaultClient, fmt.Errorf("Invalid Cert Key File: " + certKeyFile)
	}
	cert, err := tls.LoadX509KeyPair(certFile, certKeyFile)
	if err != nil {
		return *http.DefaultClient, err
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		Certificates: []tls.Certificate{cert}}
	httpClient := http.Client{}
	return httpClient, nil
}

// HTTPClientNoServerVerification returns http client configured to skip server verification.
// InsecureSkipVerify controls whether a client verifies the server's certificate chain and host name.
// If InsecureSkipVerify is true, TLS accepts any certificate presented by the server and any host name in that certificate.
// In this mode, TLS is susceptible to man-in-the-middle attacks.
// This should be used only for testing.
func HTTPClientNoServerVerification() http.Client {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	httpClient := http.Client{}
	return httpClient
}
