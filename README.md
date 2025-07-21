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
- `params`: the parameters found when `paramKind` and `paramRef` is defined.

The policy will be evaluated as `allowed` if all the CEL expressions are evaluated as `true`.
It is required that the validations expression is a boolean, otherwise the policy will not pass the settings validation phase.

A `message` or a `messageExpression` can be specified to provide a custom message when the policy is evaluated as `false`.
The `messageExpression` will be evaluated as a CEL expression, and the result will be used as the message.
It is required that the message expression is a string, otherwise the policy will not pass the settings validation phase.

For more information about variables and validation expressions, please refer to the [ValidatingAdmissionPolicy Kubernetes resource](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/).

#### Parameters

It's possible to configure the policy to read parameters from other resources
available in the cluster, similar to how the native Kubernetes
[ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/#parameter-resources)
works. This allows the values used for validation to be split from the policy's
logic.

The cel-policy uses two fields for this purpose: `paramKind` and `paramRef`.
They function identically to their Kubernetes counterparts.

- `paramKind`: Defines the kind of resource to be used as a parameter (e.g.,
  `ConfigMap`).
- `paramRef`: Specifies how to find the parameter resource(s). It can find
  resources by name or by a labelSelector, but you cannot use both at the same
  time.

In standard Kubernetes policies, `paramKind` is defined in the
ValidatingAdmissionPolicy resource, while `paramRef` is defined in the
ValidatingAdmissionPolicyBinding. However, the cel-policy simplifies this by
defining both fields directly within the policy settings, as there is no such
separation.

The `paramRef` field also contains a setting called `parameterNotFoundAction`,
which controls the policy's behavior when a specified parameter resource cannot
be found. If `parameterNotFoundAction` is set to `Deny`, the outcome then
depends on the `failurePolicy` setting. To mirror the native Kubernetes
behavior, the Kubewarden cel-policy also includes the `failurePolicy` field in
its settings. The `failurePolicy` settins is optional. And, its default values
is `Fail`.

When `paramRef` matches multiple parameter resources, the incoming request is
validated against each one. The policy will only return an acceptance response
if the resource is valid against all found parameters.

### Example

Given the following `ValidatingAdmissionPolicy`:

```yaml
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingAdmissionPolicy
metadata:
  name: "demo-policy.example.com"
spec:
  failurePolicy: Fail
  paramKind:
    apiVersion: v1
    kind: ConfigMap
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

Let's consider the following example `ValidatingAdmissionPolicyBinding` with
`paramRef`:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: "demo-policy-binding.example.com"
spec:
  policyName: "demo-policy.example.com"
  validationActions: [Deny]
  paramRef:
    name: "my-params"
    namespace: "default"
    parameterNotFoundAction: Deny
  matchResources:
    namespaceSelector:
      matchLabels:
        environment: test
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
    failurePolicy: Fail # this settings is optional. When not defined, the default value is `Fail`
    paramKind:
      apiVersion: v1
      kind: ConfigMap
    paramRef:
      name: "my-params"
      namespace: "default"
      parameterNotFoundAction: Deny
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

## Extensions

CEL policy has some extensions that add extra functionality to the language that are not defined in the language definition. The CEL policy has the following extensions enabled:

| Extension       | Description                                  | Documentation                                                                 |
| --------------- | -------------------------------------------- | ----------------------------------------------------------------------------- |
| Base64 Encoders | Allows users to encode/decode base64 strings | [Encoder extension](https://pkg.go.dev/github.com/google/cel-go/ext#Encoders) |

## Known limitations

At the moment the policy does not support the following Kubernetes extensions:

- [authz](https://pkg.go.dev/k8s.io/apiserver/pkg/cel/library#Authz)
