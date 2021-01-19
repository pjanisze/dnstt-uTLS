/*
 * Copyright (c) 2019 Yawning Angel <yawning at schwanenlied dot me>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	utls "github.com/refraction-networking/utls"
	"gitlab.com/yawning/obfs4.git/transports/base"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"golang.org/x/net/http2"
)

var (
	errProtocolNegotiated = errors.New("protocol negotiated")

	// This should be kept in sync with what is available in utls.
	clientHelloIDMap = map[string]*utls.ClientHelloID{
		"hellogolang":           nil, // Don't bother with utls.
		"hellorandomized":       &utls.HelloRandomized,
		"hellorandomizedalpn":   &utls.HelloRandomizedALPN,
		"hellorandomizednoalpn": &utls.HelloRandomizedNoALPN,
		"hellofirefox_auto":     &utls.HelloFirefox_Auto,
		"hellofirefox_55":       &utls.HelloFirefox_55,
		"hellofirefox_56":       &utls.HelloFirefox_56,
		"hellofirefox_63":       &utls.HelloFirefox_63,
		"hellofirefox_65":       &utls.HelloFirefox_65,
		"hellochrome_auto":      &utls.HelloChrome_Auto,
		"hellochrome_58":        &utls.HelloChrome_58,
		"hellochrome_62":        &utls.HelloChrome_62,
		"hellochrome_70":        &utls.HelloChrome_70,
		"hellochrome_72":        &utls.HelloChrome_72,
		"helloios_auto":         &utls.HelloIOS_Auto,
		"helloios_11_1":         &utls.HelloIOS_11_1,
		"helloios_12_1":         &utls.HelloIOS_12_1,
	}
	defaultClientHello = &utls.HelloFirefox_Auto
)

type httpClientWrapper struct {
	sync.Mutex

	clientHelloID *utls.ClientHelloID
	dialFn        base.DialFunc
	transport     http.RoundTripper
	client        *http.Client
	initConn      net.Conn
}

func (wrap *httpClientWrapper) Do(req *http.Request) (*http.Response, error) {
	// This assumes that req.URL.Host will remain constant for the
	// lifetime of the httpClientWrapper, which is a valid assumption for dnstt.
	if wrap.client == nil {
		wrap.client = newHTTPClient(nil, wrap.dialTLS)
	}
	return wrap.client.Do(req)
}

func (wrap *httpClientWrapper) dialTLS(network, addr string) (net.Conn, error) {
	// Unlike wrap.transport, this is protected by a critical section
	// since past the initial manual call from getTransport, the HTTP
	// client will be the caller.
	wrap.Lock()
	defer wrap.Unlock()

	// If we have the connection from when we determined the HTTPS
	// transport to use, return that.
	if conn := wrap.initConn; conn != nil {
		wrap.initConn = nil
		return conn, nil
	}

	rawConn, err := wrap.dialFn(network, addr)
	if err != nil {
		return nil, err
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	conn := utls.UClient(rawConn, &utls.Config{
		ServerName: host,
		// VerifyPeerCertificate: verifyPeerCertificateFn,

		// `crypto/tls` gradually ramps up the record size.  While this is
		// a good optimization and is a relatively common server feature,
		// neither Firefox nor Chromium appear to use such optimizations.
		DynamicRecordSizingDisabled: true,
	}, *wrap.clientHelloID)
	if err = conn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	if wrap.transport != nil {
		return conn, nil
	}

	// No http.Transport constructed yet, create one based on the results
	// of ALPN.
	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		// The remote peer is speaking HTTP 2 + TLS.
		wrap.transport = &http2.Transport{DialTLS: wrap.dialTLSHTTP2}
	default:
		// Assume the remote peer is speaking HTTP 1.x + TLS.
		base := (http.DefaultTransport).(*http.Transport)
		wrap.transport = &http.Transport{
			Dial:    nil,
			DialTLS: wrap.dialTLS,
	
			// Use default configuration values, taken from the runtime.
			MaxIdleConns:          base.MaxIdleConns,
			IdleConnTimeout:       base.IdleConnTimeout,
			TLSHandshakeTimeout:   base.TLSHandshakeTimeout,
			ExpectContinueTimeout: base.ExpectContinueTimeout,
		}
	}
	wrap.client.Transport = wrap.transport
	// Stash the connection just established for use servicing the
	// actual request (should be near-immediate).
	wrap.initConn = conn

	return nil, errProtocolNegotiated
}

 func (wrap *httpClientWrapper) dialTLSHTTP2(network, addr string, cfg *tls.Config) (net.Conn, error) {
	 return wrap.dialTLS(network, addr)
 }

func getDialTLSAddr(u *url.URL) string {
	host, port, err := net.SplitHostPort(u.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}
	pInt, _ := net.LookupPort("tcp", u.Scheme)

	return net.JoinHostPort(u.Host, strconv.Itoa(pInt))
}

func newHttpClientWrapper(dialFn base.DialFunc, clientHelloID *utls.ClientHelloID) *httpClientWrapper {
	return &httpClientWrapper{
		clientHelloID: clientHelloID,
		dialFn:        dialFn,
	}
}

func parseClientHelloID(s string) (*utls.ClientHelloID, error) {
	s = strings.ToLower(s)
	switch s {
	case "none":
		return nil, nil
	case "":
		return defaultClientHello, nil
	default:
		if ret := clientHelloIDMap[s]; ret != nil {
			return ret, nil
		}
	}
	return nil, fmt.Errorf("invalid ClientHelloID: '%v'", s)
}

func newHTTPClient(dialFn, dialTLSFn base.DialFunc) *http.Client {
	return &http.Client{
		Timeout:   1 * time.Minute,
	}
}