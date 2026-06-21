package req

import (
	"github.com/imroc/req/v3/internal/charsets"
	"io"
	"mime"
	"strings"
)

var autoDecodeText = autoDecodeContentTypeFunc("text", "json", "xml", "html")

var knownTextSubtypes = map[string]bool{
	"plain":                true,
	"html":                 true,
	"xml":                  true,
	"css":                  true,
	"csv":                  true,
	"markdown":             true,
	"calendar":             true,
	"vcard":                true,
	"richtext":             true,
	"tab-separated-values": true,
	"uri-list":             true,
	"json":                 true,
}

func autoDecodeContentTypeFunc(contentTypes ...string) func(contentType string) bool {
	hasTextWildcard := false
	for _, ct := range contentTypes {
		if strings.ToLower(strings.TrimSpace(ct)) == "text" {
			hasTextWildcard = true
			break
		}
	}
	return func(contentType string) bool {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			return false
		}
		mediaType = strings.ToLower(mediaType)
		idx := strings.Index(mediaType, "/")
		if idx < 0 {
			return false
		}
		mainType := mediaType[:idx]
		subType := mediaType[idx+1:]
		if hasTextWildcard && mainType == "text" && knownTextSubtypes[subType] {
			return true
		}
		for _, ct := range contentTypes {
			ct = strings.ToLower(strings.TrimSpace(ct))
			switch ct {
			case "text":
				continue
			case "json":
				if strings.Contains(subType, "json") {
					if subType == "jsonl" || subType == "jsonlines" || subType == "x-jsonlines" {
						continue
					}
					return true
				}
			case "xml":
				if strings.Contains(subType, "xml") {
					return true
				}
			case "html":
				if subType == "html" {
					return true
				}
			case "javascript":
				if subType == "javascript" || subType == "ecmascript" ||
					subType == "x-javascript" || subType == "x-ecmascript" {
					return true
				}
			default:
				if subType == ct || mediaType == ct {
					return true
				}
			}
		}
		return false
	}
}

type decodeReaderCloser struct {
	io.ReadCloser
	decodeReader io.Reader
}

func (d *decodeReaderCloser) Read(p []byte) (n int, err error) {
	return d.decodeReader.Read(p)
}

func newAutoDecodeReadCloser(input io.ReadCloser, t *Transport) *autoDecodeReadCloser {
	return &autoDecodeReadCloser{ReadCloser: input, t: t}
}

type autoDecodeReadCloser struct {
	io.ReadCloser
	t            *Transport
	decodeReader io.Reader
	detected     bool
	peek         []byte
}

func (a *autoDecodeReadCloser) peekRead(p []byte) (n int, err error) {
	n, err = a.ReadCloser.Read(p)
	if n == 0 || (err != nil && err != io.EOF) {
		return
	}
	a.detected = true
	enc, name := charsets.FindEncoding(p)
	if enc == nil {
		return
	}
	if a.t.Debugf != nil {
		a.t.Debugf("charset %s found in body's meta, auto-decode to utf-8", name)
	}
	dc := enc.NewDecoder()
	a.decodeReader = dc.Reader(a.ReadCloser)
	var pp []byte
	pp, err = dc.Bytes(p[:n])
	if err != nil {
		return
	}
	if len(pp) > len(p) {
		a.peek = make([]byte, len(pp)-len(p))
		copy(a.peek, pp[len(p):])
		copy(p, pp[:len(p)])
		n = len(p)
		return
	}
	copy(p, pp)
	n = len(p)
	return
}

func (a *autoDecodeReadCloser) peekDrain(p []byte) (n int, err error) {
	if len(a.peek) > len(p) {
		copy(p, a.peek[:len(p)])
		peek := make([]byte, len(a.peek)-len(p))
		copy(peek, a.peek[len(p):])
		a.peek = peek
		n = len(p)
		return
	}
	if len(a.peek) == len(p) {
		copy(p, a.peek)
		n = len(p)
		a.peek = nil
		return
	}
	pp := make([]byte, len(p)-len(a.peek))
	nn, err := a.decodeReader.Read(pp)
	n = len(a.peek) + nn
	copy(p[:len(a.peek)], a.peek)
	copy(p[len(a.peek):], pp[:nn])
	a.peek = nil
	return
}

func (a *autoDecodeReadCloser) Read(p []byte) (n int, err error) {
	if !a.detected {
		return a.peekRead(p)
	}
	if a.peek != nil {
		return a.peekDrain(p)
	}
	if a.decodeReader != nil {
		return a.decodeReader.Read(p)
	}
	return a.ReadCloser.Read(p) // can not determine charset, not decode
}
