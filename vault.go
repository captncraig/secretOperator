package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	v1alpha1 "github.com/captncraig/secretOperator/pkg/apis/secrets/v1alpha1"
	"github.com/golang/glog"
	"github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *Controller) syncVault(key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the RandomSecret resource with this namespace/name
	vsec, err := c.vaultSecLister.VaultSecrets(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("vault secret '%s' in work queue no longer exists", key))
			return nil
		}
		return err
	}

	// Find matching Secret
	needUpdate := false
	secretExists := false
	sec, err := c.kubeclientset.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			glog.Infof("Secret %s/%s not found. Generating", namespace, name)
			needUpdate = true
		} else {
			return err
		}
	} else {
		secretExists = true
		// verify ownership
		if !metav1.IsControlledBy(sec, vsec) {
			return fmt.Errorf("Secret %s/%s exists, but is not linked to VaultSecret", namespace, name)
		}
	}

	auth := vsec.Spec.Auth
	vClient, err := c.getVaultClient(vsec.Namespace, auth.ServiceAccount, auth.Role)
	if err != nil {
		return err
	}
	source, err := vClient.Logical().Read(vsec.Spec.Path)
	if err != nil {
		return err
	}

	if sec != nil && len(source.Data) == len(sec.Data) {
		for k, v := range sec.Data {
			existing := string(v)
			wanted, ok := source.Data[k].(string)
			if !ok || existing != wanted {
				needUpdate = true
				break
			}
		}
	} else {
		needUpdate = true
	}

	if needUpdate {
		// create and save secret
		glog.Infof("secret %s/%s is out of date. Updating from vault", namespace, name)
		stringData := map[string]string{}
		for k, v := range source.Data {
			stringData[k] = fmt.Sprint(v)
		}
		newSec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(vsec, schema.GroupVersionKind{
						Group:   v1alpha1.SchemeGroupVersion.Group,
						Version: v1alpha1.SchemeGroupVersion.Version,
						Kind:    "VaultSecret",
					}),
				},
			},
			StringData: stringData,
		}
		sclient := c.kubeclientset.CoreV1().Secrets(namespace)
		if !secretExists {
			_, err = sclient.Create(newSec)
		} else {
			_, err = sclient.Update(newSec)
		}
		return err
	}

	return nil
}

var vaultBackend = os.Getenv("VAULT_AUTH_BACKEND")

func (c *Controller) getVaultClient(namespace string, svcAccount string, role string) (*api.Client, error) {
	cacheKey := fmt.Sprintf("%s/%s-%s", namespace, svcAccount, role)
	var client *api.Client

	// check cache
	clientCacheLock.RLock()
	item := clientCache[cacheKey]
	if item != nil && time.Now().Before(item.until) {
		client = item.client
	}
	clientCacheLock.RUnlock()

	if client != nil {
		return client, nil
	}

	// read svc account token
	svc, err := c.kubeclientset.CoreV1().ServiceAccounts(namespace).Get(svcAccount, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	jwt := ""
	for _, sec := range svc.Secrets {
		if strings.Contains(sec.Name, "-token-") {
			tsec, err := c.kubeclientset.CoreV1().Secrets(namespace).Get(sec.Name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			jwt = string(tsec.Data["token"])
		}
	}
	if jwt == "" {
		return nil, fmt.Errorf("couldn't identify jwt token for service account %s", svcAccount)
	}

	// base client config
	conf := api.DefaultConfig()
	if err := conf.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("Error creating vault config from environment: %s", err)
	}
	client, err = api.NewClient(conf)
	if err != nil {
		return nil, fmt.Errorf("Error creating vault client: %s", err)
	}

	// log in with service account token
	path := fmt.Sprintf("auth/%s/login", vaultBackend)
	resp, err := client.Logical().Write(path, map[string]interface{}{
		"role": role,
		"jwt":  jwt,
	})
	if err != nil {
		return nil, err
	}
	glog.Infof("Successfully authenticated with vault as %s. Policies: %s. ttl: %d", svcAccount, resp.Auth.Policies, resp.Auth.LeaseDuration)
	client.SetToken(resp.Auth.ClientToken)
	cacheFor := time.Duration(resp.Auth.LeaseDuration-120) * time.Second // two minutes less than the lease duration
	cacheUntil := time.Now().Add(cacheFor)
	clientCacheLock.Lock()
	clientCache[cacheKey] = &clientCacheItem{
		client: client,
		until:  cacheUntil,
	}
	clientCacheLock.Unlock()
	return client, nil
}

var clientCache = map[string]*clientCacheItem{}
var clientCacheLock sync.RWMutex

type clientCacheItem struct {
	client *api.Client
	until  time.Time
}
