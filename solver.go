package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/linode/linodego"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	k8sapiv1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
)

const (
	DefaultTokenSecretName = "linode-credentials"
	DefaultTokenSecretKey  = "token"
)

//===========================================================================
// Solver Interface
//===========================================================================

// LinodeDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// Implements `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
type LinodeDNSProviderSolver struct {
	k8s          *kubernetes.Clientset
	ctx          context.Context
	namespace    string
	secretKeyRef *cmmeta.SecretKeySelector
}

// Ensure LinodeDNSProviderSolver meets the webhook.Solver interface
var _ webhook.Solver = (*LinodeDNSProviderSolver)(nil)

// LinodeDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
//
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
//
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
//
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
//
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type LinodeDNSProviderConfig struct {
	// Expect apiKeySecretRef with name: <secret name> and key: <token field in secret>
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource (e.g. in the certman kubectl configuration).
//
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
//
// For example, `cloudflare` may be used as the name of a solver.
func (s *LinodeDNSProviderSolver) Name() string {
	return "linode"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (s *LinodeDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) (err error) {
	klog.Infof("presented with challenge for fqdn=%s zone=%s", ch.ResolvedFQDN, ch.ResolvedZone)

	var linode *Linode
	if linode, err = s.LinodeClient(ch); err != nil {
		klog.Errorf("failed to create linode client: %v", err)
		return err
	}

	// Compute the entry and the domain from the request
	entry, domain := DomainEntry(ch.ResolvedFQDN, ch.ResolvedZone)

	// Fetch the zone from the Linode account
	var zone *linodego.Domain
	if zone, err = linode.FindZone(domain); err != nil {
		klog.Errorf("failed to find zone %q in linode account: %v", domain, err)
		return err
	}

	// Fetch the txt record for the specified entry
	var record *linodego.DomainRecord
	if record, err = linode.FindRecord(zone.ID, entry); err != nil {
		if errors.Is(err, ErrNoRecord) {
			// Record does not exist, create it
			return linode.CreateRecord(zone.ID, entry, ch.Key)
		}

		klog.Errorf("failed to find record %q in linode zone %q: %v", entry, domain, err)
		return err
	}

	// If the record already exists, update it
	return linode.UpdateRecord(zone.ID, record.ID, record.Name, ch.Key)
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (s *LinodeDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) (err error) {
	klog.Infof("cleaning up challenge for fqdn=%s zone=%s", ch.ResolvedFQDN, ch.ResolvedZone)

	var linode *Linode
	if linode, err = s.LinodeClient(ch); err != nil {
		klog.Errorf("failed to create linode client: %v", err)
		return err
	}

	// Compute the entry and the domain from the request
	entry, domain := DomainEntry(ch.ResolvedFQDN, ch.ResolvedZone)

	// Fetch the zone from the Linode account
	var zone *linodego.Domain
	if zone, err = linode.FindZone(domain); err != nil {
		klog.Warningf("failed to find zone %q in linode account: %v", domain, err)
		return err
	}

	// Fetch the txt record for the specified entry
	var record *linodego.DomainRecord
	if record, err = linode.FindRecord(zone.ID, entry); err != nil {
		if errors.Is(err, ErrNoRecord) {
			// Record does not exist, nothing to clean up and no error
			return nil
		}

		klog.Warningf("failed to find record %q in linode zone %q: %v", entry, domain, err)
		return err
	}

	// Delete the record for thee specified entry
	return linode.DeleteRecord(zone.ID, record.ID)
}

// Initialize will be called when the webhook first starts.
//
// This method can be used to instantiate the webhook, i.e. initializing
// connections or warming up caches.
//
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
//
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (s *LinodeDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) (err error) {
	klog.Info("Initializing Linode DNS provider solver webhook")
	if s.k8s, err = kubernetes.NewForConfig(kubeClientConfig); err != nil {
		return fmt.Errorf("failed to create kube client: %v", err)
	}

	s.ctx = context.Background()
	return nil
}

// LoadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func LoadConfig(data *extapi.JSON) (cfg LinodeDNSProviderConfig, err error) {
	// handle the 'base case' where no configuration has been provided
	if data == nil {
		return cfg, nil
	}

	if err = json.Unmarshal(data.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

// DomainEntry is a small helper function that decodes the entry and domain into a
// string format that is recognized by the Linode DNS provider.
func DomainEntry(fqdn, zone string) (entry string, domain string) {
	// Strip the zone from the fqdn to get the record name (subdomain)
	entry = strings.TrimSuffix(fqdn, zone)
	entry = strings.TrimSuffix(entry, ".") // Trim trailing dot if present

	// The Linode API expects the domain to not have a trailing dot
	domain = strings.TrimSuffix(zone, ".")

	return entry, domain
}

//===========================================================================
// Kubernetes and Linode Interactions
//===========================================================================

func (s *LinodeDNSProviderSolver) PodNamespace() string {
	// The namespace the webhook is running in is available via the
	// POD_NAMESPACE environment variable or read from the pod configuration.
	if s.namespace == "" {
		// First lookup namespace from the environment variable.
		if s.namespace = os.Getenv("POD_NAMESPACE"); s.namespace == "" {
			// Fallback to reading the namespace from the pod configuration.
			data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
			if err != nil {
				klog.Errorf("failed to read pod namespace: %v", err)
			} else {
				s.namespace = string(data)
			}
		}

		// Trim any whitespace from the namespace.
		s.namespace = strings.TrimSpace(s.namespace)
	}

	// Second check to make sure we have a valid namespace.
	if s.namespace == "" {
		klog.Error("invalid webhook pod namespace provided")
		return "default"
	}

	return s.namespace
}

func (s *LinodeDNSProviderSolver) SecretKeyRef() cmmeta.SecretKeySelector {
	if s.secretKeyRef == nil {
		// Create the default key selector
		s.secretKeyRef = &cmmeta.SecretKeySelector{
			LocalObjectReference: cmmeta.LocalObjectReference{
				Name: DefaultTokenSecretName,
			},
			Key: DefaultTokenSecretKey,
		}

		// Lookup secret key reference from the environment
		if name := strings.TrimSpace(os.Getenv("LINODE_TOKEN_SECRET_NAME")); name != "" {
			s.secretKeyRef.LocalObjectReference.Name = name
		}

		if key := strings.TrimSpace(os.Getenv("LINODE_TOKEN_SECRET_KEY")); key != "" {
			s.secretKeyRef.Key = key
		}
	}
	return *s.secretKeyRef
}

func (s *LinodeDNSProviderSolver) LinodeClient(ch *v1alpha1.ChallengeRequest) (_ *Linode, err error) {
	// Load the solver configuration for this ChallengeRequest
	var cfg LinodeDNSProviderConfig
	if cfg, err = LoadConfig(ch.Config); err != nil {
		return nil, err
	}

	// Extract the Linode API key from the referenced Secret resource
	var apiKey string
	if apiKey, err = s.GetAPIKey(cfg.APIKeySecretRef, ch.ResourceNamespace); err != nil {
		return nil, err
	}

	// Create and return the client
	return NewLinode(apiKey), nil
}

// GetAPIKey retrieves the Linode API key from the referenced Secret resource.
func (s *LinodeDNSProviderSolver) GetAPIKey(secretRef cmmeta.SecretKeySelector, namespace string) (token string, err error) {
	// Get token from secret in the same namespace as the certificate if possible.
	if token, err = s.getSecret(secretRef, namespace); err == nil {
		return token, nil
	}

	// Fallback to getting the secret from the webhook's namespace.
	klog.Warningf("failed to find certificate namespace linode API token secret: %v", err)
	klog.Info("falling back to webhook namespace for linode API token secret")
	if token, err = s.getSecret(s.SecretKeyRef(), s.PodNamespace()); err == nil {
		return token, nil
	}

	return "", err
}

func (s *LinodeDNSProviderSolver) getSecret(secretRef cmmeta.SecretKeySelector, namespace string) (_ string, err error) {
	if secretRef.LocalObjectReference.Name == "" || secretRef.Key == "" {
		return "", ErrInvalidSecretReference
	}

	// Get the secret
	var secret *k8sapiv1.Secret
	if secret, err = s.k8s.CoreV1().Secrets(namespace).Get(s.ctx, secretRef.LocalObjectReference.Name, k8smetav1.GetOptions{}); err != nil {
		return "", fmt.Errorf("failed to get secret %q in namespace %q: %v", secretRef.LocalObjectReference.Name, namespace, err)
	}

	// Extract token from secret
	if token, ok := secret.Data[secretRef.Key]; ok {
		return string(token), nil
	}
	return "", fmt.Errorf("key %q not found in secret %s/%s", secretRef.Key, namespace, secretRef.LocalObjectReference.Name)
}
