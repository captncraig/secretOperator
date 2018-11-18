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
	"time"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
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

	secretLister  corelisters.SecretLister
	secretsSynced cache.InformerSynced

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
	secretInformer coreinformers.SecretInformer,
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
		kubeclientset:  kubeclientset,
		crdClientset:   crdClientset,
		randSecLister:  randSecretInformer.Lister(),
		randSecsSynced: randSecretInformer.Informer().HasSynced,

		secretLister:  secretInformer.Lister(),
		secretsSynced: secretInformer.Informer().HasSynced,
		workqueue:     workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "RandomSecrets"),
		recorder:      recorder,
	}

	glog.Info("Setting up event handlers")
	// Set up an event handler for when Foo resources change
	randSecretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueRand,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueRand(new)
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
	if ok := cache.WaitForCacheSync(stopCh, c.secretsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	glog.Info("Starting workers")
	// Launch two workers to process Foo resources
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
		if err := c.syncRandom(key); err != nil {
			return fmt.Errorf("error syncing random secret'%s': %s.", key, err.Error())
		}
		glog.Infof("Successfully synced '%s'", key)
		return nil
	}(obj)

	if err != nil {
		runtime.HandleError(err)
		return true
	}

	return true
}

// enqueueFoo takes a Foo resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than Foo.
func (c *Controller) enqueueRand(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		runtime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited(key)
}

// handleObject will take any resource implementing metav1.Object and attempt
// to find the Foo resource that 'owns' it. It does this by looking at the
// objects metadata.ownerReferences field for an appropriate OwnerReference.
// It then enqueues that Foo resource to be processed. If the object does not
// have an appropriate OwnerReference, it will simply be skipped.
func (c *Controller) handleObject(obj interface{}) {
	var object metav1.Object
	var ok bool
	if object, ok = obj.(metav1.Object); ok {
		fmt.Println(object.GetName())
	}
	// if object, ok = obj.(metav1.Object); !ok {
	// 	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	// 	if !ok {
	// 		runtime.HandleError(fmt.Errorf("error decoding object, invalid type"))
	// 		return
	// 	}
	// 	object, ok = tombstone.Obj.(metav1.Object)
	// 	if !ok {
	// 		runtime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
	// 		return
	// 	}
	// 	glog.V(4).Infof("Recovered deleted object '%s' from tombstone", object.GetName())
	// }
	// glog.V(4).Infof("Processing object: %s", object.GetName())
	// if ownerRef := metav1.GetControllerOf(object); ownerRef != nil {
	// 	// If this object is not owned by a Foo, we should not do anything more
	// 	// with it.
	// 	if ownerRef.Kind != "Foo" {
	// 		return
	// 	}

	// 	foo, err := c.foosLister.Foos(object.GetNamespace()).Get(ownerRef.Name)
	// 	if err != nil {
	// 		glog.V(4).Infof("ignoring orphaned object '%s' of foo '%s'", object.GetSelfLink(), ownerRef.Name)
	// 		return
	// 	}

	// 	c.enqueueFoo(foo)
	// 	return
	// }
}
