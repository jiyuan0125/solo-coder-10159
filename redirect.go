package req

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type RedirectPolicy func(req *http.Request, via []*http.Request) error

func MaxRedirectPolicy(noOfRedirect int) RedirectPolicy {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= noOfRedirect {
			return fmt.Errorf("stopped after %d redirects", noOfRedirect)
		}
		return nil
	}
}

func DefaultRedirectPolicy() RedirectPolicy {
	return MaxRedirectPolicy(10)
}

func NoRedirectPolicy() RedirectPolicy {
	return func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
}

func SameDomainRedirectPolicy() RedirectPolicy {
	return func(req *http.Request, via []*http.Request) error {
		if getDomain(req.URL.Host) != getDomain(via[0].URL.Host) {
			return errors.New("different domain name is not allowed")
		}
		return nil
	}
}

func SameHostRedirectPolicy() RedirectPolicy {
	return func(req *http.Request, via []*http.Request) error {
		if getHostname(req.URL.Host) != getHostname(via[0].URL.Host) {
			return errors.New("different host name is not allowed")
		}
		return nil
	}
}

func AllowedHostRedirectPolicy(hosts ...string) RedirectPolicy {
	m := make(map[string]struct{})
	for _, h := range hosts {
		m[strings.ToLower(extractHostname(h))] = struct{}{}
	}

	return func(req *http.Request, via []*http.Request) error {
		h := getHostname(req.URL.Host)
		if _, ok := m[h]; !ok {
			return fmt.Errorf("redirect host [%s] is not allowed", h)
		}
		return nil
	}
}

func AllowedDomainRedirectPolicy(hosts ...string) RedirectPolicy {
	domains := make(map[string]struct{})
	for _, h := range hosts {
		domains[strings.ToLower(extractDomain(h))] = struct{}{}
	}

	return func(req *http.Request, via []*http.Request) error {
		domain := getDomain(req.URL.Host)
		if _, ok := domains[domain]; !ok {
			return fmt.Errorf("redirect domain [%s] is not allowed", domain)
		}
		return nil
	}
}

func stripPort(host string) string {
	if strings.HasPrefix(host, "[") {
		closeBracket := strings.Index(host, "]")
		if closeBracket >= 0 {
			return host[:closeBracket+1]
		}
		return host
	}
	colonPos := strings.Index(host, ":")
	if colonPos >= 0 {
		return host[:colonPos]
	}
	return host
}

func stripUserInfo(host string) string {
	atIdx := strings.LastIndex(host, "@")
	if atIdx >= 0 {
		return host[atIdx+1:]
	}
	return host
}

func getHostname(host string) string {
	host = stripUserInfo(host)
	host = stripPort(host)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return strings.ToLower(host)
}

func extractHostname(host string) string {
	return getHostname(host)
}

func getDomain(host string) string {
	hostname := getHostname(host)
	if net.ParseIP(hostname) != nil {
		return hostname
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		return hostname
	}
	return strings.ToLower(domain)
}

func extractDomain(host string) string {
	return getDomain(host)
}

func AlwaysCopyHeaderRedirectPolicy(headers ...string) RedirectPolicy {
	return func(req *http.Request, via []*http.Request) error {
		for _, header := range headers {
			if len(req.Header.Values(header)) > 0 {
				continue
			}
			vals := via[0].Header.Values(header)
			for _, val := range vals {
				req.Header.Add(header, val)
			}
		}
		return nil
	}
}
