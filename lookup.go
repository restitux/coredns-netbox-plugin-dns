package netboxdns

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/doubleu-labs/coredns-netbox-plugin-dns/internal/netbox"
	"github.com/miekg/dns"
)

type lookupResult int

const (
	lookupSuccess    lookupResult = iota
	lookupNameError               // NXDomain
	lookupDelegation              // Delegate, non-authoritative
)

type lookupResponse struct {
	Answer       []dns.RR
	Ns           []dns.RR
	Extra        []dns.RR
	LookupResult lookupResult
}

func (netboxdns *NetboxDNS) lookup(
	name string,
	reqIP netip.Addr,
	qtype uint16,
	family int,
) (*lookupResponse, error) {
	logger.Debugf("request for [%v] %v from %v\n", dns.TypeToString[qtype], name, reqIP)

	nameTrimmed := strings.TrimSuffix(name, ".")
	// check if zone exists on Netbox
	zones, default_zone_index, err := netboxdns.matchZone(nameTrimmed, reqIP)
	if err != nil {
		return nil, err
	}
	if zones == nil {
		logger.Debugf("no zone matching %q", name)
		return &lookupResponse{LookupResult: lookupNameError}, nil
	}

	// var responses []*lookupResponse
	var defaultResponse *lookupResponse
	for i, zone := range zones {
		is_zone_default := i == default_zone_index
		// check if qname is for zone origin
		if nameTrimmed == zone.Name {
			originResponse, err := netboxdns.processOrigin(qtype, zone)
			if err != nil {
				log.Debugf("Could not process origin for zone %v: %w", zone, err)
				continue
			}
			if originResponse != nil {
				logger.Debugf(
					"found origin records for [%s] %q in zone %v",
					dns.TypeToString[qtype],
					name,
					zone.Name,
				)
				if is_zone_default {
					return originResponse, nil
				} else {
					defaultResponse = originResponse
				}
				continue
			}
		}

		// lookup exact request
		direct, err := netboxdns.lookupDirect(nameTrimmed, qtype, zone)
		if err != nil {
			log.Debugf("could not lookup exact request for %v in zone %v: %w", nameTrimmed, zone.Name, err)
			continue
		}
		if direct != nil {
			logger.Debugf(
				"found records for [%s] %q in zone %v",
				dns.TypeToString[qtype],
				name,
				zone.View.Name,
			)
			if is_zone_default {
				return direct, nil
			} else {
				defaultResponse = direct
			}
			continue
		}

		// if no exact records exist for the request, check if the qname is a
		// delegate zone
		delegate, err := netboxdns.lookupDelegate(nameTrimmed, zone, qtype)
		if err != nil {
			log.Debugf("could not lookup delegate for %v in zone %v: %w", nameTrimmed, zone.Name, err)
			continue
		}
		if delegate != nil {
			logger.Debugf("found delegate zone records for %q in zone %v", name, zone.Name)
			// return delegate, nil
			if is_zone_default {
				return delegate, nil
			} else {
				defaultResponse = delegate
			}

			continue
		}
	}
	if defaultResponse != nil {
		return defaultResponse, nil
	} else {
		log.Errorf("could not resolve any records for request %v", nameTrimmed)
		return nil, fmt.Errorf("could not resolve any records for request %v ", nameTrimmed)
	}
}

func (netboxdns *NetboxDNS) matchZone(qname string, reqIP netip.Addr) ([]*netbox.Zone, int, error) {
	managedZones, err := netbox.GetZones(netboxdns.requestClient)
	if err != nil {
		return nil, 0, err
	}
	var out []*netbox.Zone
	index_of_default := -1
	for _, managedZone := range managedZones {
		view, err := netbox.GetView(netboxdns.requestClient, managedZone.View.ID)
		if err != nil {
			return nil, 0, err
		}

		viewContainsIP, err := view.ContainsIP(reqIP)
		if err != nil {
			return nil, 0, err
		}
		if !viewContainsIP {
			log.Debugf("view %v's configured prefixes don't match request IP %v", view.Name, reqIP.String())
			continue
		}
		log.Debugf("view %v's configured prefixes match request IP %v", view.Name, reqIP.String())

		if dns.IsSubDomain(managedZone.Name, qname) {
			out = append(out, &managedZone)
			if view.Default {
				if index_of_default != -1 {
					log.Errorf("more than one default view configured for IP %v", reqIP.String())
					return nil, 0, fmt.Errorf("more than one default view configured for IP %v", reqIP.String())
				}
				index_of_default = len(out)
			}
		}
	}
	return out, index_of_default, nil
}

func (netboxdns *NetboxDNS) processOrigin(
	qtype uint16,
	zone *netbox.Zone,
) (*lookupResponse, error) {
	var queryType []string
	switch qtype {
	case dns.TypeSOA:
		queryType = []string{"SOA", "NS"}
	case dns.TypeNS:
		queryType = []string{"NS"}
	default:
		return nil, nil
	}
	records, err := netbox.GetRecordsQuery(
		netboxdns.requestClient,
		&netbox.RecordQuery{
			Name: "@",
			Type: queryType,
			Zone: zone,
		},
	)
	if err != nil {
		return nil, err
	}
	rrs, err := recordsToRR(records)
	if err != nil {
		return nil, err
	}
	answer := filterRRByType(rrs, dns.TypeSOA)
	ns := filterRRByType(rrs, dns.TypeNS)
	extraRecords, err := netboxdns.processExtra(ns, zone, qtype)
	if err != nil {
		return nil, err
	}
	if len(extraRecords) == 0 {
		// if no A/AAAA records exist for the NS in the specified zone, check if
		// the server has records anywhere
		extraRecords, err = netboxdns.processExtra(ns, nil, qtype)
		if err != nil {
			return nil, err
		}
	}
	extra, err := recordsToRR(extraRecords)
	if err != nil {
		return nil, err
	}
	if qtype == dns.TypeNS {
		answer = ns
		ns = nil
	}
	return &lookupResponse{
		Answer: answer,
		Ns:     ns,
		Extra:  extra,
	}, nil
}

func (netboxdns *NetboxDNS) processExtra(
	answer []dns.RR,
	zone *netbox.Zone,
	qtype uint16,
) ([]netbox.Record, error) {
	var out []netbox.Record
	for _, rr := range answer {
		name := ""
		switch t := rr.(type) {
		case *dns.SRV:
			name = t.Target
		case *dns.MX:
			name = t.Mx
		case *dns.NS:
			name = t.Ns
		case *dns.CNAME:
			name = t.Target
		}
		if len(name) == 0 {
			continue
		}
		//var reqType []string
		//switch qtype {
		//case 1:
		//	reqType = []string{"A"}
		//case 2:
		//	reqType = []string{"AAAA"}
		//}
		records, err := netbox.GetRecordsQuery(
			netboxdns.requestClient,
			&netbox.RecordQuery{
				FQDN: strings.TrimSuffix(name, "."),
				Type: []string{dns.TypeToString[qtype]},
				Zone: zone,
			},
		)
		if err != nil {
			return out, err
		}
		out = append(out, records...)
	}
	return out, nil
}

func (netboxdns *NetboxDNS) lookupDirect(
	qname string,
	qtype uint16,
	zone *netbox.Zone,
) (*lookupResponse, error) {
	queryTypes := []string{dns.TypeToString[qtype]}
	if qtype == dns.TypeA || qtype == dns.TypeAAAA {
		queryTypes = append(queryTypes, "CNAME")
	}

	records, err := netbox.GetRecordsQuery(
		netboxdns.requestClient,
		&netbox.RecordQuery{
			FQDN: qname,
			Type: queryTypes,
			Zone: zone,
		},
	)
	if err != nil {
		return nil, err
	}
	// log.Debugf("%v", records)

	// allRecords := append([]netbox.Record{}, records...)
	var allRecords []netbox.Record

	var newRecords []netbox.Record
	for i := 0; ; i++ {
		foundCNAME := false
		// If record data end with ., pass as is
		// If record data doesn't end with ., append the zone name
		for i, record := range records {
			// log.Debugf("%v", record)
			if record.Type == "CNAME" {
				foundCNAME = true
				if record.Value[len(record.Value)-1:] != "." {
					records[i].Value = strings.Join([]string{record.Value, ".", zone.Name, "."}, "")
				}
				// log.Debugf("%v", records[i].Value)
				newRecordsForCNAME, err := netbox.GetRecordsQuery(
					netboxdns.requestClient,
					&netbox.RecordQuery{
						FQDN: records[i].Value,
						Type: queryTypes,
						Zone: zone,
					},
				)
				if err != nil {
					return nil, err
				}
				// log.Debugf("%v", newRecordsForCNAME)

				if len(newRecordsForCNAME) > 0 {
					newRecords = append(newRecords, newRecordsForCNAME...)
				}
			}
		}
		// log.Debugf("%v", newRecords)

		allRecords = append(allRecords, records...)
		records = newRecords
		newRecords = []netbox.Record{}

		if !foundCNAME {
			break
		}

		if i > 20 {
			return nil, fmt.Errorf("CNAME recursion depth exceeded")
		}
	}
	//for _, record := range allRecords {
	//	log.Debugf("%v -> %v", record.FQDN, record.Value)
	//}
	answer, err := recordsToRR(allRecords)
	if err != nil {
		return nil, err
	}

	log.Debug(answer)
	if len(answer) > 0 {
		return &lookupResponse{
			Answer: answer,
			Extra:  []dns.RR{},
		}, nil
	} else {
		return nil, nil
	}
}

func (netboxdns *NetboxDNS) lookupDelegate(
	qname string,
	zone *netbox.Zone,
	qtype uint16,
) (*lookupResponse, error) {
	records, err := netbox.GetRecordsQuery(
		netboxdns.requestClient,
		&netbox.RecordQuery{
			FQDN: qname,
			Type: []string{"NS"},
			Zone: zone,
		},
	)
	if err != nil {
		return nil, err
	}
	if len(records) > 0 {
		ns, err := recordsToRR(records)
		if err != nil {
			return nil, err
		}
		extraRecords, err := netboxdns.processExtra(ns, nil, qtype)
		if err != nil {
			return nil, err
		}
		extra, err := recordsToRR(extraRecords)
		if err != nil {
			return nil, err
		}
		return &lookupResponse{
			Ns:           ns,
			Extra:        extra,
			LookupResult: lookupDelegation,
		}, nil
	}
	return nil, nil
}
