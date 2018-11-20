## secretOperator

This is a suite of utilities for making secret management easier in a kubernetes cluster. It is an "operator" that
you can run in your cluster, and a set of custom resource definitions to declaratively manage secrets of various types.

### VaultSecret

Many organizations use [vault](https://www.hashicorp.com/products/vault/) as their source of truth for secrets, but also need to access
those secrets from within a kubernetes cluster. Sadly, there are no native integrations between vault and kubernetes.

The `VaultSecret` CRD allows you to declare a secret that you need to be present in the cluster, as well as how to get it from vault:

```
apiVersion: secrets.k8s.captncraig.io/v1alpha1
kind: VaultSecret
metadata:
  namespace: myapp
  name: database-credentials
spec:
  path: "secret/myapp/db-prod"
  mode: v1
  auth:
    role: myapp
    serviceAccount: myapp
```

This Operator would see the above `VaultSecret`, fetch the data from vault, and create a matching `Secret` object in your cluster that your pods and applications can use.

### RandomSecret

### Installing and Running