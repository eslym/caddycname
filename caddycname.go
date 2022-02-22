package caddycname

import (
	"context"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"net"
	"net/http"
	"strings"
	"time"
)

type CaddyCNAME struct {
	Dial     string `json:"dial,omitempty"`
	Protocol string `json:"proto,omitempty"`
	Lookup   string `json:"lookup,omitempty"`

	resolver *net.Resolver
	logger   *zap.Logger
}

func init() {
	caddy.RegisterModule(CaddyCNAME{})
	httpcaddyfile.RegisterHandlerDirective("cname", parseCaddyfileHandler)
}

func (CaddyCNAME) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.cname",
		New: func() caddy.Module {
			return new(CaddyCNAME)
		},
	}
}

func (c *CaddyCNAME) Provision(ctx caddy.Context) error {
	if len(c.Protocol) > 0 {
		if !(c.Protocol == "udp" || c.Protocol == "tcp") {
			return fmt.Errorf("%s is not a valid protocol", c.Protocol)
		}
	} else {
		c.Protocol = "udp"
	}
	ns := "(default server)"
	if len(c.Dial) > 0 {
		c.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, c.Protocol, c.Dial)
			},
		}
		ns = c.Protocol + "/" + c.Dial
	} else {
		c.resolver = net.DefaultResolver
	}
	if len(c.Lookup) == 0 {
		c.Lookup = "{http.request.host}"
	}
	c.logger = ctx.Logger(c)
	c.logger.Debug(
		"Using config",
		zap.String("nameserver", ns),
		zap.String("lookup", c.Lookup),
	)
	return nil
}

func (c CaddyCNAME) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	host := repl.ReplaceAll(c.Lookup, "")
	if net.ParseIP(host) != nil {
		c.logger.Debug("host is an IP, skipping", zap.String("host", host))
		repl.Set("http.request.host.cname", host)
		return next.ServeHTTP(w, r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	cname, err := c.resolver.LookupCNAME(ctx, host)
	if err == nil {
		repl.Set("http.request.host.cname", strings.TrimRight(cname, "."))
	} else {
		repl.Set("http.request.host.cname", host)
		c.logger.Warn(
			"Unable to resolve CNAME for host",
			zap.String("host", host),
			zap.String("error", err.Error()),
		)
	}
	return next.ServeHTTP(w, r)
}

func (c *CaddyCNAME) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			c.Dial = d.Val()
		}
		if d.NextArg() {
			c.Lookup = d.Val()
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "dial":
				if d.NextArg() {
					c.Dial = d.Val()
				} else {
					return d.ArgErr()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "proto":
				if d.NextArg() {
					c.Protocol = d.Val()
				} else {
					return d.ArgErr()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "lookup":
				if d.NextArg() {
					c.Lookup = d.Val()
				} else {
					return d.ArgErr()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("'%s' is not expected.", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var c CaddyCNAME
	err := c.UnmarshalCaddyfile(h.Dispenser)
	return c, err
}

var (
	_ caddy.Provisioner           = (*CaddyCNAME)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyCNAME)(nil)
	_ caddyfile.Unmarshaler       = (*CaddyCNAME)(nil)
)
