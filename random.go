package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	mrand "math/rand"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	v1alpha1 "github.com/captncraig/secretOperator/pkg/apis/secrets/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *Controller) syncRandom(key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the RandomSecret resource with this namespace/name
	rsec, err := c.randSecLister.RandomSecrets(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("random secret '%s' in work queue no longer exists", key))
			return nil
		}
		return err
	}

	// TODO: fully validate keys and such

	// Find matching Secret
	sec, err := c.kubeclientset.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		glog.Infof("Secret %s/%s not found. Generating", namespace, name)
		sec, err = c.generateRandomSecret(rsec)
		if err != nil {
			return err
		}
		_, err = c.kubeclientset.CoreV1().Secrets(namespace).Create(sec)
		return err
	}

	// verify ownership
	if !metav1.IsControlledBy(sec, rsec) {
		return fmt.Errorf("Secret %s/%s exists, but is not linked to RandomSecret", namespace, name)
	}

	needsUpdate := false
	if sec.StringData == nil {
		sec.StringData = map[string]string{}
	}
	keysToDelete := map[string]bool{}
	for k := range sec.Data {
		keysToDelete[k] = true
	}
	for _, key := range rsec.Spec.Keys {
		delete(keysToDelete, key.Name)
		expHash := key.Hash()
		found := sec.Annotations["secrets.k8s.captncraig.io/gen_hash_"+key.Name]
		if len(sec.Data[key.Name]) == 0 {
			glog.Infof("Secret %s/%s missing key %s. Generating", namespace, name, key.Name)
		} else if found != expHash {
			glog.Infof("Secret %s/%s spec changed for key %s. Regenerating", namespace, name, key.Name)
		} else {
			continue
		}
		setRandAnno(sec, &key)
		sec.StringData[key.Name] = getRandomData(key)
		needsUpdate = true
	}
	for k := range keysToDelete {
		glog.Infof("Secret %s/%s has extra key %s. Deleting", namespace, name, k)
		delete(sec.Data, k)
		delete(sec.Annotations, randAnnoBase+k)
		needsUpdate = true
	}
	if needsUpdate {
		_, err := c.kubeclientset.CoreV1().Secrets(namespace).Update(sec)
		if err != nil {
			return err
		}
	}
	return nil
}

const randAnnoBase = "secrets.k8s.captncraig.io/gen_hash_"

func setRandAnno(sec *corev1.Secret, key *v1alpha1.RandomSecretKey) {
	if sec.Annotations == nil {
		sec.Annotations = map[string]string{}
	}
	sec.Annotations[randAnnoBase+key.Name] = key.Hash()
}

func (c *Controller) generateRandomSecret(rsec *v1alpha1.RandomSecret) (*corev1.Secret, error) {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: rsec.Namespace,
			Name:      rsec.Name,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(rsec, schema.GroupVersionKind{
					Group:   v1alpha1.SchemeGroupVersion.Group,
					Version: v1alpha1.SchemeGroupVersion.Version,
					Kind:    "RandomSecret",
				}),
			},
		},
		StringData: map[string]string{},
	}
	for _, key := range rsec.Spec.Keys {
		setRandAnno(sec, &key)
		sec.StringData[key.Name] = getRandomData(key)
	}
	return sec, nil
}

func getRandomData(key v1alpha1.RandomSecretKey) string {
	switch key.Mode {
	case "binary":
		return genBinary(key)
	case "text":
		return genText(key)
	default:
		panic(fmt.Errorf("unknown random secret mode %s", key.Mode))
	}
}

func genBinary(key v1alpha1.RandomSecretKey) string {
	l := key.Length
	if l == 0 {
		l = 32
	}
	dat := make([]byte, l)
	rand.Read(dat)
	switch key.Encoding {
	case "", "base64":
		return base64.StdEncoding.EncodeToString(dat)
	case "hex":
		return hex.EncodeToString(dat)
	default:
		panic(fmt.Errorf("unknown random secret binary encoding %s", key.Encoding))
	}
}

func genText(key v1alpha1.RandomSecretKey) string {
	alpha := key.Alphabet
	if alpha == "" {
		alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}
	l := key.Length
	if l == 0 {
		l = 32
	}
	dat := make([]byte, l)
	for i := range dat {
		dat[i] = alpha[randomGen.Intn(len(alpha))]
	}
	return string(dat)
}

// build a math/rand generator with a crypto/rand backend.
// lets us use Intn type utilities with stronger backing entropy
var randomGen = mrand.New(cryptoSource{})

type cryptoSource struct{}

func (s cryptoSource) Seed(seed int64) {}

func (s cryptoSource) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}

func (s cryptoSource) Uint64() (v uint64) {
	binary.Read(rand.Reader, binary.BigEndian, &v)
	return v
}
