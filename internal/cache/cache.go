package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

const (
	ProxyLabelKey    = "com.whalevet.injected"
	ProxyOriginalKey = "com.whalevet.original"
	ProxyImagePrefix = "whalevet-injected/"
)

type InterceptedImage struct {
	OriginalRef string
	ProxyRef    string
	CertHash    string
	InjectedAt  time.Time
}

type ImageCache struct {
	images sync.Map // map[string]*InterceptedImage
}

func New() *ImageCache {
	return &ImageCache{}
}

func (c *ImageCache) Get(originalRef string) (*InterceptedImage, bool) {
	val, ok := c.images.Load(originalRef)
	if !ok {
		return nil, false
	}
	return val.(*InterceptedImage), true
}

func (c *ImageCache) Set(originalRef, proxyRef string, certContents [][]byte) {
	h := sha256.New()
	for _, cert := range certContents {
		h.Write(cert)
	}
	certHash := hex.EncodeToString(h.Sum(nil))
	c.images.Store(originalRef, &InterceptedImage{
		OriginalRef: originalRef,
		ProxyRef:    proxyRef,
		CertHash:    certHash,
		InjectedAt:  time.Now(),
	})
}

func (c *ImageCache) ProxyRefFor(originalRef string) string {
	if img, ok := c.Get(originalRef); ok {
		return img.ProxyRef
	}
	return ""
}

func MakeProxyRef(originalRef string) string {
	return ProxyImagePrefix + originalRef
}
