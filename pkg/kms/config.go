// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package kms

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"strings"

	"github.com/minio/kes"
)

func newCertPool(CAFiles []string) (*x509.CertPool, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		certPool = x509.NewCertPool()
	}

	for _, CAFile := range CAFiles {
		if CAFile == "" {
			continue
		}
		pemByte, err := ioutil.ReadFile(CAFile)
		if err != nil {
			return nil, err
		}

		for {
			var block *pem.Block
			block, pemByte = pem.Decode(pemByte)
			if block == nil {
				break
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}

			certPool.AddCert(cert)
		}
	}

	return certPool, nil
}

// etcd server KMS settings.
const (
	EnvKMSSecretKey  = "MCC_KMS_SECRET_KEY"
	EnvKESEndpoint   = "MCC_KMS_KES_ENDPOINT"
	EnvKESKeyName    = "MCC_KMS_KES_KEY_NAME"
	EnvKESClientKey  = "MCC_KMS_KES_KEY_FILE"
	EnvKESClientCert = "MCC_KMS_KES_CERT_FILE"
	EnvKESServerCA   = "MCC_KMS_KES_CAPATH"
)

// NewFromEnv initializes KMS from environment values.
func NewFromEnv() (KMS, error) {
	if v, ok := os.LookupEnv(EnvKMSSecretKey); ok {
		return Parse(v)
	}
	v, ok := os.LookupEnv(EnvKESEndpoint)
	if !ok {
		return nil, nil
	}
	var endpoints []string
	for _, endpoint := range strings.Split(v, ",") {
		if strings.TrimSpace(endpoint) == "" {
			continue
		}
		endpoints = append(endpoints, endpoint)
	}

	certificate, err := tls.LoadX509KeyPair(os.Getenv(EnvKESClientCert), os.Getenv(EnvKESClientKey))
	if err != nil {
		return nil, err
	}

	rootCAs, err := newCertPool(strings.Split(os.Getenv(EnvKESServerCA), ","))
	if err != nil {
		return nil, err
	}

	var defaultKeyID = os.Getenv(EnvKESKeyName)
	KMS, err := NewWithConfig(Config{
		Endpoints:    endpoints,
		DefaultKeyID: defaultKeyID,
		Certificate:  certificate,
		RootCAs:      rootCAs,
	})
	if err != nil {
		return nil, err
	}

	// We check that the default key ID exists or try to create it otherwise.
	// This implicitly checks that we can communicate to KES. We don't treat
	// a policy error as failure condition since MinIO may not have the permission
	// to create keys - just to generate/decrypt data encryption keys.
	if err = KMS.CreateKey(defaultKeyID); err != nil && !errors.Is(err, kes.ErrKeyExists) && !errors.Is(err, kes.ErrNotAllowed) {
		return nil, err
	}

	return KMS, nil
}
