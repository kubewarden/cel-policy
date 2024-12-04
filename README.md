[![Kubewarden Policy Repository](https://github.com/kubewarden/community/blob/main/badges/kubewarden-policies.svg)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#policy-scope)
[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)

## CEL Policy

This policy is a meta-policy that allows to run [CEL](https://github.com/google/cel-go) expressions
against Kubernetes resources.
A meta-policy is a policy that can be configured via settings, and does not require to be recompiled to change its behavior, acting as a DSL.

The settings of the policy are compliant with the [ValidatingAdmissionPolicy Kubernetes resource](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/),
please refer to [writing a policy](#writing-a-policy) for more information on what fields are supported.
Under the hood, the policy uses [CEL](https://github.com/google/cel-go) and [Kubernetes CEL libraries](https://pkg.go.dev/k8s.io/apiserver/pkg/cel/library),
this allows to use the same CEL syntax and functions that are available in Kubernetes.

### Writing a policy

Both `validations` and `variables` fields are supported.
The policy provides the following variables:

- `request`: the admission request
- `object`: the Kubernetes resource being validated
- `oldObject`: the Kubernetes resource before the update, nil if the request is not an update
- `namespaceObject`: the namespace of the resource being validated

The policy will be evaluated as `allowed` if all the CEL expressions are evaluated as `true`.
It is required that the validations expression is a boolean, otherwise the policy will not pass the settings validation phase.

A `message` or a `messageExpression` can be specified to provide a custom message when the policy is evaluated as `false`.
The `messageExpression` will be evaluated as a CEL expression, and the result will be used as the message.
It is required that the message expression is a string, otherwise the policy will not pass the settings validation phase.

For more information about variables and validation expressions, please refer to the [ValidatingAdmissionPolicy Kubernetes resource](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/).

### Example

Given the following `ValidatingAdmissionPolicy`:

```yaml
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingAdmissionPolicy
metadata:
  name: "demo-policy.example.com"
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
  variables:
    - name: replicas
      expression: "object.spec.replicas"
  validations:
    - expression: "variables.replicas <= 5"
      message: "The number of replicas must be less than or equal to 5"
```

the Kubewarden CEL policy can be written as follows:

```yaml
apiVersion: policies.kubewarden.io/v1
kind: AdmissionPolicy
metadata:
  annotations:
    io.kubewarden.policy.category: Resource validation
    io.kubewarden.policy.severity: low
  name: "demo-policy.example.com"
spec:
  module: registry://ghcr.io/kubewarden/policies/cel-policy:latest
  settings:
    variables:
      - name: "replicas"
        expression: "object.spec.replicas"
    validations:
      - expression: "variables.replicas <= 5"
        message: "The number of replicas must be less than or equal to 5"
  rules:
    - apiGroups: ["apps"]
      apiVersions: ["v1"]
      operations: ["CREATE", "UPDATE"]
      resources: ["deployments"]
  mutating: false
  backgroundAudit: false
```

## Host capabilities

Kubewarden's [host capabilities](https://docs.kubewarden.io/reference/spec/host-capabilities/intro-host-capabilities) can be accessed by CEL extension libraries available in the policy environment.

The following host capabilities are available:

| Capability                                                                                          | Description                                   | Documentation                                                                                         |
| --------------------------------------------------------------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| [kubernetes](https://docs.kubewarden.io/reference/spec/host-capabilities/kubernetes)                | Access to Kubernetes resources in the cluster | [**Kubernetes**](https://pkg.go.dev/github.com/kubewarden/cel-policy/internal/cel/library#Kubernetes) |
| [sigstore](https://docs.kubewarden.io/reference/spec/host-capabilities/signature-verifier-policies) | Sigstore (secure supply chain) support        | [**Sigstore**](https://pkg.go.dev/github.com/kubewarden/cel-policy/internal/cel/library#Sigstore)     |
| [oci](https://docs.kubewarden.io/reference/spec/host-capabilities/container-registry)               | Interact with container registries            | [**OCI**](https://pkg.go.dev/github.com/kubewarden/cel-policy/internal/cel/library#OCI)               |
| [crypto](https://docs.kubewarden.io/reference/spec/host-capabilities/crypto)                        | Host-side cryptographic functions             | [**Crypto**](https://pkg.go.dev/github.com/kubewarden/cel-policy/internal/cel/library#Crypto)         |
| [net](https://docs.kubewarden.io/reference/spec/host-capabilities/net)                              | Network operations                            | [**Net**](https://pkg.go.dev/github.com/kubewarden/cel-policy/internal/cel/library#Net)               |

## Known limitations

At the moment the policy does not support the following Kubernetes extensions:

- [authz](https://pkg.go.dev/k8s.io/apiserver/pkg/cel/library#Authz)
