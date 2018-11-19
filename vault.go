package main

import (
	"fmt"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/api/errors"
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

	// TODO: fully validate keys and such

	// Find matching Secret
	sec, err := c.secretLister.Secrets(namespace).Get(name)
	if err != nil && errors.IsNotFound(err) {
		glog.Infof("Secret %s/%s not found. Generating", namespace, name)
		// sec, err = c.generateRandomSecret(rsec)
		// if err != nil {
		// 	return err
		// }
		// _, err = c.kubeclientset.CoreV1().Secrets(namespace).Create(sec)
		// return err
		return nil
	}

	// verify ownership
	if !metav1.IsControlledBy(sec, vsec) {
		return fmt.Errorf("Secret %s/%s exists, but is not linked to VaultSecret", namespace, name)
	}

	return nil
}
