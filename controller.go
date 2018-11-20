/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	clientset "github.com/captncraig/secretOperator/pkg/client/clientset/versioned"
	secretsscheme "github.com/captncraig/secretOperator/pkg/client/clientset/versioned/scheme"
	informers "github.com/captncraig/secretOperator/pkg/client/informers/externalversions/secrets/v1alpha1"
	listers "github.com/captncraig/secretOperator/pkg/client/listers/secrets/v1alpha1"
)

const controllerAgentName = "secrets-controller"

type Controller struct {
	kubeclientset kubernetes.Interface
	crdClientset  clientset.Interface

	randSecLister  listers.RandomSecretLister
	randSecsSynced cache.InformerSynced

	vaultSecLister  listers.VaultSecretLister
	vaultSecsSynced cache.InformerSynced

	workqueue workqueue.RateLimitingInterface

	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder
}

// NewController returns a new sample controller
func NewController(
	kubeclientset kubernetes.Interface,
	crdClientset clientset.Interface,
	randSecretInformer informers.RandomSecretInformer,
	vaultSecretInformer informers.VaultSecretInformer,
) *Controller {

	// Create event broadcaster
	// Add sample-controller types to the default Kubernetes Scheme so Events can be
	// logged for sample-controller types.
	utilruntime.Must(secretsscheme.AddToScheme(scheme.Scheme))
	glog.V(4).Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeclientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	controller := &Controller{
		kubeclientset:   kubeclientset,
		crdClientset:    crdClientset,
		randSecLister:   randSecretInformer.Lister(),
		randSecsSynced:  randSecretInformer.Informer().HasSynced,
		vaultSecLister:  vaultSecretInformer.Lister(),
		vaultSecsSynced: vaultSecretInformer.Informer().HasSynced,

		workqueue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "SecretsQueue"),
		recorder:  recorder,
	}

	glog.Info("Setting up event handlers")
	randSecretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueRand,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueRand(new)
		},
	})

	vaultSecretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueVault,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueVault(new)
		},
	})
	return controller
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *Controller) Run(threadiness int, stopCh <-chan struct{}) error {
	defer runtime.HandleCrash()
	defer c.workqueue.ShutDown()

	// Start the informer factories to begin populating the informer caches
	glog.Info("Starting Secrets controller")

	// Wait for the caches to be synced before starting workers
	glog.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.randSecsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}
	if ok := cache.WaitForCacheSync(stopCh, c.vaultSecsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	glog.Info("Starting workers")
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	glog.Info("Started workers")
	<-stopCh
	glog.Info("Shutting down workers")

	return nil
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	obj, shutdown := c.workqueue.Get()

	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.workqueue.Done(obj)
		defer c.workqueue.Forget(obj)
		var key string
		var ok bool
		if key, ok = obj.(string); !ok {
			c.workqueue.Forget(obj)
			runtime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		parts := strings.SplitN(key, "|", 2)
		typ, key := parts[0], parts[1]
		switch typ {
		case "random":
			if err := c.syncRandom(key); err != nil {
				return fmt.Errorf("error syncing random secret '%s': %s", key, err.Error())
			}
		case "vault":
			if err := c.syncVault(key); err != nil {
				return fmt.Errorf("error syncing vault secret '%s': %s", key, err.Error())
			}
		default:
			return fmt.Errorf("Invalid queue item type %s", typ)
		}
		glog.Infof("Successfully synced %s secret '%s'", typ, key)
		return nil
	}(obj)

	if err != nil {
		runtime.HandleError(err)
		return true
	}

	return true
}

func (c *Controller) enqueueRand(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		runtime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited("random|" + key)
}

func (c *Controller) enqueueVault(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		runtime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited("vault|" + key)
}
