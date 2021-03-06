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
	"flag"
	"os"
	"time"

	"github.com/golang/glog"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	// Uncomment the following line to load the gcp plugin (only required to authenticate against GKE clusters).
	// _ "k8s.io/client-go/plugin/pkg/client/auth/gcp"

	clientset "github.com/captncraig/secretOperator/pkg/client/clientset/versioned"
	informers "github.com/captncraig/secretOperator/pkg/client/informers/externalversions"
	"github.com/captncraig/secretOperator/pkg/signals"
)

func main() {
	flag.Parse()
	glog.Info("Starting up")

	// set up signals so we handle the first shutdown signal gracefully
	stopCh := signals.SetupSignalHandler()

	cfg, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		glog.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		glog.Fatalf("Error building kubernetes clientset: %s", err.Error())
	}

	secretClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		glog.Fatalf("Error building secret clientset: %s", err.Error())
	}

	secretInformerFactory := informers.NewSharedInformerFactory(secretClient, time.Second*60)

	controller := NewController(kubeClient, secretClient,
		secretInformerFactory.Secrets().V1alpha1().RandomSecrets(),
		secretInformerFactory.Secrets().V1alpha1().VaultSecrets(),
	)

	secretInformerFactory.Start(stopCh)

	if err = controller.Run(2, stopCh); err != nil {
		glog.Fatalf("Error running controller: %s", err.Error())
	}
}
