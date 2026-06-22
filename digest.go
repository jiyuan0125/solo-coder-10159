package req

import (
	"net/http"
	"sync"

	"github.com/icholy/digest"
	"github.com/imroc/req/v3/internal/header"
)

type cchal struct {
	c *digest.Challenge
	n int
}

type digestAuth struct {
	Username string
	Password string
	cache    map[string]*cchal
	cacheMu  sync.Mutex
}

func (da *digestAuth) digest(req *http.Request, chal *digest.Challenge, count int) (*digest.Credentials, error) {
	opt := digest.Options{
		Method:   req.Method,
		URI:      req.URL.RequestURI(),
		GetBody:  req.GetBody,
		Count:    count,
		Username: da.Username,
		Password: da.Password,
	}
	return digest.Digest(chal, opt)
}

const digestAttemptedHeader = "X-Req-Digest-Attempted"

func (da *digestAuth) handleCommonDigestAuth(c *Client, resp *Response) error {
	r := resp.Request
	if r.Headers.Get(digestAttemptedHeader) != "" {
		return nil
	}
	if resp.Err != nil || resp.StatusCode != http.StatusUnauthorized || resp.Response == nil {
		return nil
	}

	chal, err := digest.FindChallenge(resp.Response.Header)
	if err != nil {
		if err == digest.ErrNoChallenge {
			return nil
		}
		host := r.RawRequest.URL.Hostname()
		da.cacheMu.Lock()
		delete(da.cache, host)
		da.cacheMu.Unlock()
		return err
	}

	host := r.RawRequest.URL.Hostname()
	da.cacheMu.Lock()
	da.cache[host] = &cchal{c: chal}
	da.cacheMu.Unlock()

	cred, err := da.digest(r.RawRequest, chal, 1)
	if err != nil {
		da.cacheMu.Lock()
		delete(da.cache, host)
		da.cacheMu.Unlock()
		return err
	}

	r.SetHeader(header.Authorization, cred.String())
	r.SetHeader(digestAttemptedHeader, "1")

	r.digestAuthNeedRetry = true

	return nil
}

func handleCommonDigestAuthFunc(username, password string) ResponseMiddleware {
	da := &digestAuth{
		Username: username,
		Password: password,
		cache:    make(map[string]*cchal),
	}
	return func(c *Client, resp *Response) error {
		return da.handleCommonDigestAuth(c, resp)
	}
}

func handleDigestAuthFunc(username, password string) ResponseMiddleware {
	return func(client *Client, resp *Response) error {
		r := resp.Request
		if r.Headers.Get(digestAttemptedHeader) != "" {
			return nil
		}
		if resp.Err != nil || resp.StatusCode != http.StatusUnauthorized || resp.Response == nil {
			return nil
		}

		chal, err := digest.FindChallenge(resp.Response.Header)
		if err != nil {
			if err == digest.ErrNoChallenge {
				return nil
			}
			return err
		}

		cred, err := digest.Digest(chal, digest.Options{
			Username: username,
			Password: password,
			Method:   r.RawRequest.Method,
			URI:      r.RawRequest.URL.RequestURI(),
			GetBody:  r.RawRequest.GetBody,
			Count:    1,
		})
		if err != nil {
			return err
		}

		r.SetHeader(header.Authorization, cred.String())
		r.SetHeader(digestAttemptedHeader, "1")

		r.digestAuthNeedRetry = true

		return nil
	}
}
