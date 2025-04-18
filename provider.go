package libdns

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/console-dns/client"
	"github.com/libdns/libdns"
)

// ConsoleDnsProvider facilitates DNS record manipulation with <TODO: PROVIDER NAME>.
type ConsoleDnsProvider struct {
	*client.ConsoleDnsClient `json:"client"`
}

// GetRecords lists all the records in the zone.
func (p *ConsoleDnsProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zone = strings.TrimSuffix(zone, ".")
	log.Println("查询 " + zone)
	z, _, err := p.ListZone(zone)
	if err != nil {
		return nil, err
	}
	result := make([]libdns.Record, 0)
	for s, record := range z.Records {
		for _, a := range record.A {
			result = append(result, ToLDnsA(s, a))
		}
		for _, aaaa := range record.AAAA {
			result = append(result, ToLDnsAAAA(s, aaaa))
		}
		for _, txt := range record.TXT {
			result = append(result, ToLDnsTXT(s, txt))
		}
	}

	return result, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *ConsoleDnsProvider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = strings.TrimSuffix(zone, ".")
	result := make([]libdns.Record, 0)
	for _, record := range records {
		switch record.Type {
		case "A":
			_, current, err := FromLDnsA(&record)
			if err != nil {
				return result, err
			}
			_, err = p.CreateRecord(zone, record.Name, record.Type, current)
			if err != nil {
				return result, err
			}
			result = append(result, ToLDnsA(record.Name, current))
		case "AAAA":
			_, aaaa, err := FromLDnsAAAA(&record)
			if err != nil {
				return nil, err
			}
			_, err = p.CreateRecord(zone, record.Name, record.Type, aaaa)
			if err != nil {
				return result, err
			}
			result = append(result, ToLDnsAAAA(record.Name, aaaa))
		case "TXT":
			_, txt, err := FromLDnsTXT(&record)
			if err != nil {
				return nil, err
			}
			_, err = p.CreateRecord(zone, record.Name, record.Type, txt)
			if err != nil {
				return result, err
			}
			result = append(result, ToLDnsTXT(record.Name, txt))
		default:
			return nil, fmt.Errorf("unknown type: %s", record.Type)
		}
	}
	return result, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *ConsoleDnsProvider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = strings.TrimSuffix(zone, ".")
	result := make([]libdns.Record, 0)
	for _, record := range records {
		switch record.Type {
		case "A":
			old, n, err := FromLDnsA(&record)
			if err != nil {
				return result, err
			}
			if old != nil {
				_, err := p.UpdateRecord(zone, record.Name, record.Type, old, n)
				if err != nil {
					return result, err
				}
			} else {
				_, err := p.CreateRecord(zone, record.Name, record.Type, n)
				if err != nil {
					return result, err
				}
			}
			result = append(result, ToLDnsA(record.Name, n))
		case "AAAA":
			old, n, err := FromLDnsAAAA(&record)
			if err != nil {
				return result, err
			}
			if old != nil {
				_, err := p.UpdateRecord(zone, record.Name, record.Type, old, n)
				if err != nil {
					return result, err
				}
			} else {
				_, err := p.CreateRecord(zone, record.Name, record.Type, n)
				if err != nil {
					return result, err
				}
			}
			result = append(result, ToLDnsAAAA(record.Name, n))
		case "TXT":
			old, n, err := FromLDnsTXT(&record)
			if err != nil {
				return result, err
			}
			if old != nil {
				_, err := p.UpdateRecord(zone, record.Name, record.Type, old, n)
				if err != nil {
					return result, err
				}
			} else {
				_, err := p.CreateRecord(zone, record.Name, record.Type, n)
				if err != nil {
					return result, err
				}
			}
			result = append(result, ToLDnsTXT(record.Name, n))
		default:
			return result, fmt.Errorf("unknown type: %s", record.Type)
		}
	}
	return result, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *ConsoleDnsProvider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = strings.TrimSuffix(zone, ".")
	result := make([]libdns.Record, 0)
	for _, record := range records {
		switch record.Type {
		case "A":
			_, current, err := FromLDnsA(&record)
			if err != nil {
				return result, err
			}
			_, err = p.DeleteRecord(zone, record.Name, record.Type, current)
			if err != nil {
				return result, err
			}
			result = append(result, record)
		case "AAAA":
			_, aaaa, err := FromLDnsAAAA(&record)
			if err != nil {
				return nil, err
			}
			_, err = p.DeleteRecord(zone, record.Name, record.Type, aaaa)
			if err != nil {
				return result, err
			}
			result = append(result, record)
		case "TXT":
			_, txt, err := FromLDnsTXT(&record)
			if err != nil {
				return nil, err
			}
			_, err = p.DeleteRecord(zone, record.Name, record.Type, txt)
			if err != nil {
				return result, err
			}
			result = append(result, record)
		default:
			return nil, fmt.Errorf("unknown type: %s", record.Type)
		}
	}
	return result, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*ConsoleDnsProvider)(nil)
	_ libdns.RecordAppender = (*ConsoleDnsProvider)(nil)
	_ libdns.RecordSetter   = (*ConsoleDnsProvider)(nil)
	_ libdns.RecordDeleter  = (*ConsoleDnsProvider)(nil)
)
