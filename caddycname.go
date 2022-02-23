package caddycname

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"net"
	"net/http"
	"strings"
	"time"
)

type CaddyCNAME struct {
	NameServer string `json:"nameserver,omitempty"`
	Protocol   string `json:"proto,omitempty"`
	Lookup     string `json:"lookup,omitempty"`
	Strict     bool   `json:"strict,omitempty"`

	ns     string
	lookup string
	client *dns.Client
	logger *zap.Logger
}

func init() {
	caddy.RegisterModule(CaddyCNAME{})
	httpcaddyfile.RegisterHandlerDirective("resolve_cname", parseCaddyfileHandler)
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
	c.client = new(dns.Client)
	if len(c.Protocol) > 0 {
		c.client.Net = c.Protocol
	}
	c.client.Timeout = 200 * time.Millisecond
	c.client.Net = c.Protocol
	if len(c.NameServer) == 0 {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return err
		}
		if len(config.Servers) == 0 {
			return fmt.Errorf("no server in default resolv.conf")
		}
		c.ns = net.JoinHostPort(config.Servers[0], config.Port)
		c.client.Net = "udp"
	} else {
		c.ns = c.NameServer
	}
	if len(c.Lookup) == 0 {
		c.lookup = "{http.request.host}"
	} else {
		c.lookup = c.Lookup
	}
	c.logger = ctx.Logger(c)
	c.logger.Debug("Using config", zap.Any("config", c))
	return nil
}

func (c CaddyCNAME) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	host := repl.ReplaceAll(c.lookup, "")
	if net.ParseIP(host) != nil {
		if c.Strict {
			return caddyhttp.Error(404, fmt.Errorf("unable to resolve CNAME for %s", host))
		}
		c.logger.Debug("host is an IP, skipping", zap.String("host", host))
		repl.Set("http.request.host.cname", host)
		return next.ServeHTTP(w, r)
	}
	cname, err := c.resolveCNAME(host)
	if err == nil {
		repl.Set("http.request.host.cname", strings.TrimRight(cname, "."))
	} else {
		if c.Strict {
			return caddyhttp.Error(404, err)
		}
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
			c.NameServer = d.Val()
		}
		if d.NextArg() {
			c.Lookup = d.Val()
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "nameserver":
				if d.NextArg() {
					c.NameServer = d.Val()
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
			case "strict":
				c.Strict = true
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

func (c *CaddyCNAME) resolveCNAME(host string) (result string, err error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeCNAME)
	m.RecursionDesired = true
	res, _, err := c.client.Exchange(m, c.ns)
	if err != nil {
		return "", err
	}
	if len(res.Answer) == 0 {
		return "", fmt.Errorf("unable to resovle CNAME for %s", host)
	}
	return res.Answer[0].(*dns.CNAME).Target, nil
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
