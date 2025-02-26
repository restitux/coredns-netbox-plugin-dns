package netboxdns

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/doubleu-labs/coredns-netbox-plugin-dns/internal/netbox"
	"github.com/miekg/dns"
)

const (
	defaultHTTPClientTimeout time.Duration = time.Second * 5
	pluginName               string        = "netboxdns"
)

var logger log.P

func init() {
	logger = log.NewWithPlugin(pluginName)
}

type NetboxDNS struct {
	Next plugin.Handler

	requestClient *netbox.APIRequestClient

	zones []string
	fall  fall.F
}

func NewNetboxDNS() *NetboxDNS {
	return &NetboxDNS{
		requestClient: &netbox.APIRequestClient{
			Client: &http.Client{
				Timeout: defaultHTTPClientTimeout,
			},
		},
		zones: []string{"."},
	}
}

// Name implements the plugin.Handler interface
func (NetboxDNS) Name() string {
	return pluginName
}

// ServeDNS implements the plugin.Handler interface
func (netboxdns *NetboxDNS) ServeDNS(
	reqContext context.Context,
	respWriter dns.ResponseWriter,
	reqMsg *dns.Msg,
) (int, error) {
	state := request.Request{W: respWriter, Req: reqMsg}
	qname := state.QName()
	reqIP, err := netip.ParseAddr(state.IP())
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	family := state.Family()
	qtype := state.QType()
	// qtype := fixQType(state.QType(), family)

	// check if plugin is configured to respond to the requested zone
	respondingZone := plugin.Zones(netboxdns.zones).Matches(qname)
	if respondingZone == "" {
		return netboxdns.nextOrFailure(reqContext, respWriter, reqMsg)
	}

	response, err := netboxdns.lookup(qname, reqIP, qtype, family)
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	if response.LookupResult == lookupNameError {
		if netboxdns.fall.Through(qname) {
			logger.Debugf(
				"forwarding request [%s] %q to next plugin",
				dns.TypeToString[qtype],
				qname,
			)
			return netboxdns.nextOrFailure(reqContext, respWriter, reqMsg)
		} else {
			logger.Debugf(
				"no records for [%s] %q; fallthrough not enabled",
				dns.TypeToString[qtype],
				qname,
			)
		}
	}

	respMsg := &dns.Msg{
		Answer: response.Answer,
		Ns:     response.Ns,
		Extra:  response.Extra,
	}
	respMsg.SetReply(reqMsg)
	respMsg.Authoritative = true

	switch response.LookupResult {
	case lookupSuccess:
	case lookupNameError:
		respMsg.Rcode = dns.RcodeNameError
	case lookupDelegation:
		respMsg.Authoritative = false
	}

	respWriter.WriteMsg(respMsg)
	return dns.RcodeSuccess, nil
}

func (netboxdns *NetboxDNS) nextOrFailure(
	ctx context.Context,
	writer dns.ResponseWriter,
	request *dns.Msg,
) (int, error) {
	return plugin.NextOrFailure(
		pluginName,
		netboxdns.Next,
		ctx,
		writer,
		request,
	)
}

func fixQType(stateQtype uint16, family int) uint16 {
	var qtype uint16
	switch stateQtype {
	case dns.TypeA, dns.TypeAAAA:
		switch family {
		case 1:
			qtype = dns.TypeA
		case 2:
			qtype = dns.TypeAAAA
		}
		return qtype
	default:
		return stateQtype
	}
}
