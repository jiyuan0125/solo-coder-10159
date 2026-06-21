package req

import (
	"bytes"
	"io"
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
	Username   string
	Password   string
	HttpClient *http.Client
	cache      map[string]*cchal
	cacheMu    sync.Mutex
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

func (da *digestAuth) challenge(req *http.Request) (*digest.Challenge, int, bool) {
	da.cacheMu.Lock()
	defer da.cacheMu.Unlock()
	host := req.URL.Hostname()
	cc, ok := da.cache[host]
	if !ok {
		return nil, 0, false
	}
	cc.n++
	return cc.c, cc.n, true
}

func (da *digestAuth) prepare(req *http.Request) error {
	if da.HttpClient.Jar != nil {
		for _, cookie := range da.HttpClient.Jar.Cookies(req.URL) {
			req.AddCookie(cookie)
		}
	}
	chal, count, ok := da.challenge(req)
	if !ok {
		return nil
	}
	cred, err := da.digest(req, chal, count)
	if err != nil {
		da.cacheMu.Lock()
		delete(da.cache, req.URL.Hostname())
		da.cacheMu.Unlock()
		return err
	}
	if cred != nil {
		req.Header.Set("Authorization", cred.String())
	}
	return nil
}

const digestAttemptedHeader = "X-Req-Digest-Attempted"

func (da *digestAuth) HttpRoundTripWrapperFunc(rt http.RoundTripper) HttpRoundTripFunc {
	return func(req *http.Request) (resp *http.Response, err error) {
		if req.Header.Get(digestAttemptedHeader) != "" {
			return rt.RoundTrip(req)
		}

		clone, err := cloner(req)
		if err != nil {
			return nil, err
		}

		first, err := clone()
		if err != nil {
			return nil, err
		}

		if err := da.prepare(first); err != nil {
			return nil, err
		}

		res, err := rt.RoundTrip(first)
		if err != nil || res.StatusCode != http.StatusUnauthorized {
			return res, err
		}

		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()

		host := req.URL.Hostname()
		chal, err := digest.FindChallenge(res.Header)
		if err != nil {
			da.cacheMu.Lock()
			delete(da.cache, host)
			da.cacheMu.Unlock()
			if err == digest.ErrNoChallenge {
				res.Header.Set(digestAttemptedHeader, "1")
				return res, nil
			}
			return nil, err
		}

		da.cacheMu.Lock()
		da.cache[host] = &cchal{c: chal}
		da.cacheMu.Unlock()

		second, err := clone()
		if err != nil {
			return nil, err
		}

		if err := da.prepare(second); err != nil {
			return nil, err
		}

		second.Header.Set(digestAttemptedHeader, "1")

		return rt.RoundTrip(second)
	}
}

func handleDigestAuthFunc(username, password string) ResponseMiddleware {
	return func(client *Client, resp *Response) error {
		if resp.Err != nil || resp.StatusCode != http.StatusUnauthorized {
			return nil
		}
		if resp.Response != nil && resp.Response.Header.Get(digestAttemptedHeader) != "" {
			return nil
		}

		chal, err := digest.FindChallenge(resp.Response.Header)
		if err != nil {
			if err == digest.ErrNoChallenge {
				return nil
			}
			return err
		}

		r := resp.Request
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

		var newResp *Response
		if client.wrappedRoundTrip != nil {
			newResp, err = client.wrappedRoundTrip.RoundTrip(r)
		} else {
			newResp, err = client.roundTrip(r)
		}
		if err != nil {
			return err
		}

		resp.Response = newResp.Response
		resp.Err = newResp.Err
		resp.body = newResp.body
		resp.result = newResp.result
		resp.error = newResp.error

		return nil
	}
}

func cloner(req *http.Request) (func() (*http.Request, error), error) {
	getbody := req.GetBody
	if getbody == nil {
		if req.Body == nil || req.Body == http.NoBody {
			getbody = func() (io.ReadCloser, error) {
				return http.NoBody, nil
			}
		} else {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			if err := req.Body.Close(); err != nil {
				return nil, err
			}
			getbody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(body)), nil
			}
		}
	}
	return func() (*http.Request, error) {
		clone := req.Clone(req.Context())
		body, err := getbody()
		if err != nil {
			return nil, err
		}
		clone.Body = body
		clone.GetBody = getbody
		return clone, nil
	}, nil
}
