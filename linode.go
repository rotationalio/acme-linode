package acme

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/linode/linodego"
	"golang.org/x/oauth2"
	"k8s.io/klog/v2"
)

const DefaultTimeout = 90 * time.Second

var (
	Weight    int    = 1
	Port      int    = 0
	Priority  int    = 0
	UserAgent string = fmt.Sprintf("go.rtnl.ai/acme-linode/%s github.com/linode/linodego/%s", Version(true), linodego.Version)
)

// Wraps the linode API client with DNS specific methods used by the solver.
type Linode struct {
	client linodego.Client
}

// Creates a new Linode API client using the provided API key.
func NewLinode(apiKey string) *Linode {
	lin := &Linode{
		client: linodego.NewClient(&http.Client{
			Transport: &oauth2.Transport{
				Source: oauth2.StaticTokenSource(&oauth2.Token{
					AccessToken: apiKey,
				}),
			},
		}),
	}

	lin.client.SetUserAgent(UserAgent)
	return lin
}

// Returns the Linode Zone object that matches the provided domain name.
func (l *Linode) FindZone(domain string) (zone *linodego.Domain, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	var zones []linodego.Domain
	if zones, err = l.client.ListDomains(ctx, linodego.NewListOptions(0, "")); err != nil {
		return nil, err
	}

	// Find the zone that matches the domain
	for _, zone := range zones {
		if zone.Domain == domain {
			return &zone, nil
		}
	}

	return nil, fmt.Errorf("no zone found for domain %q", domain)
}

// Returns the Linode DNS Record object that matches the provided parameters.
func (l *Linode) FindRecord(zoneID int, entry string) (record *linodego.DomainRecord, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	var records []linodego.DomainRecord
	if records, err = l.client.ListDomainRecords(ctx, zoneID, linodego.NewListOptions(0, "")); err != nil {
		return nil, err
	}

	// Find the record that matches the entry
	for _, record := range records {
		if record.Name == entry && record.Type == "TXT" {
			return &record, nil
		}
	}

	return nil, ErrNoRecord
}

// Creates a new TXT DNS Record in the specified Linode Zone.
func (l *Linode) CreateRecord(zoneID int, entry, value string) error {
	klog.Infof("creating TXT record %s in zone ID %d", entry, zoneID)
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	_, err := l.client.CreateDomainRecord(ctx, zoneID, linodego.DomainRecordCreateOptions{
		Type:     linodego.RecordTypeTXT,
		Name:     entry,
		Target:   value,
		Priority: &Priority,
		Weight:   &Weight,
		Port:     &Port,
		TTLSec:   180,
	})

	if err != nil {
		klog.Errorf("failed to create TXT record %q in linode zone ID %d: %v", entry, zoneID, err)
	}
	return err
}

// Updates an existing TXT DNS Record in the specified Linode Zone.
func (l *Linode) UpdateRecord(zoneID, recordID int, entry, value string) error {
	klog.Infof("updating TXT record %s (ID %d) in zone ID %d", entry, recordID, zoneID)
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	_, err := l.client.UpdateDomainRecord(ctx, zoneID, recordID, linodego.DomainRecordUpdateOptions{
		Type:     linodego.RecordTypeTXT,
		Name:     entry,
		Target:   value,
		Priority: &Priority,
		Weight:   &Weight,
		Port:     &Port,
		TTLSec:   180,
	})

	if err != nil {
		klog.Errorf("failed to update TXT record %q (ID %d) in linode zone ID %d: %v", entry, recordID, zoneID, err)
	}
	return err
}

// Deletes the specified TXT DNS Record from the Linode Zone.
func (l *Linode) DeleteRecord(zoneID, recordID int) error {
	klog.Infof("deleting TXT record ID %d in zone ID %d", recordID, zoneID)
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	err := l.client.DeleteDomainRecord(ctx, zoneID, recordID)
	if err != nil {
		klog.Errorf("failed to delete TXT record ID %d in linode zone ID %d: %v", recordID, zoneID, err)
	}
	return err
}
