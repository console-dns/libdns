package libdns

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/console-dns/spec/models"
	"github.com/libdns/libdns"
)

func ToLDnsA(name string, a *models.RecordA) libdns.Record {
	marshal, _ := json.Marshal(a)
	return libdns.Record{
		ID:    string(marshal),
		Type:  "A",
		Name:  name,
		Value: a.Ip.String(),
		TTL:   time.Duration(a.Ttl) * time.Second,
	}
}

func ToLDnsAAAA(name string, a *models.RecordAAAA) libdns.Record {
	marshal, _ := json.Marshal(a)
	return libdns.Record{
		ID:    string(marshal),
		Type:  "AAAA",
		Name:  name,
		Value: a.Ip.String(),
		TTL:   time.Duration(a.Ttl) * time.Second,
	}
}
func ToLDnsTXT(name string, a *models.RecordTXT) libdns.Record {
	marshal, _ := json.Marshal(a)
	return libdns.Record{
		ID:    string(marshal),
		Type:  "TXT",
		Name:  name,
		Value: a.Text,
		TTL:   time.Duration(a.Ttl) * time.Second,
	}
}

func FromLDnsA(r *libdns.Record) (old, new *models.RecordA, err error) {
	old = &models.RecordA{}
	if r.ID != "" {
		err = json.Unmarshal([]byte(r.ID), old)
		if err != nil {
			return nil, nil, err
		}
	} else {
		old = nil
	}
	a, err := models.NewRecordA(r.Value, strconv.Itoa(int(r.TTL.Seconds())))
	return old, a, err
}
func FromLDnsAAAA(r *libdns.Record) (old, new *models.RecordAAAA, err error) {
	old = &models.RecordAAAA{}
	if r.ID != "" {
		err = json.Unmarshal([]byte(r.ID), old)
		if err != nil {
			return nil, nil, err
		}
	} else {
		old = nil
	}
	new, err = models.NewRecordAAAA(r.Value, strconv.Itoa(int(r.TTL.Seconds())))
	return old, new, err
}
func FromLDnsTXT(r *libdns.Record) (old, new *models.RecordTXT, err error) {
	old = &models.RecordTXT{}
	if r.ID != "" {
		err = json.Unmarshal([]byte(r.ID), old)
		if err != nil {
			return nil, nil, err
		}
	} else {
		old = nil
	}
	new, err = models.NewRecordTXT(r.Value, strconv.Itoa(int(r.TTL.Seconds())))
	return old, new, err
}
