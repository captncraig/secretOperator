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

package v1alpha1

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RandomSecret is a specification for a RandomSecret resource
type RandomSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec RandomSecretSpec `json:"spec"`
}

// FooSpec is the spec for a Foo resource
type RandomSecretSpec struct {
	Keys []RandomSecretKey `json:"keys"`
}

type RandomSecretKey struct {
	Name     string `json:"name"`
	Mode     string `json:"mode"` // "text" or "binary"
	Length   int32  `json:"length"`
	RegenKey string `json:"regenKey"`

	Alphabet string `json:"alphabet"` // text only
	Encoding string `json:"encoding"` // binary only. "hex" or "base64"
}

// important that all fields are represented here. Order matters.
func (key *RandomSecretKey) Hash() string {
	s := sha1.New()
	fmt.Fprint(s, key.Mode)
	fmt.Fprint(s, key.RegenKey)
	fmt.Fprint(s, key.Length)

	if key.Mode == "binary" {
		fmt.Fprint(s, key.Encoding)
	} else if key.Mode == "text" {
		fmt.Fprint(s, key.Alphabet)
	}

	d := s.Sum(nil)
	return hex.EncodeToString(d)
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RandomSecretList is a list of RandomSecret resources
type RandomSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []RandomSecret `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VaultSecret is a secret copied from vault
type VaultSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec VaultSecretSpec `json:"spec"`
}

type VaultSecretSpec struct {
	Path string          `json:"path"`
	Mode string          `json:"mode"` //v1 or v2 for kv stores
	Auth VaultSecretAuth `json:"auth"`
}

type VaultSecretAuth struct {
	Role           string `json:"role"`
	ServiceAccount string `json:"serviceAccount"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VaultSecretList is a list of VaultSecret resources
type VaultSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []VaultSecret `json:"items"`
}
