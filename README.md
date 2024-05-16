## CEL Policy

This is a meta-policy that allows running [CEL](https://github.com/google/cel-go) expressions
against Kubernetes resources.
A meta-policy is a policy that can be configured via settings, and does not require recompilation to change its behavior, acting as a DSL.

The settings of the policy are compliant with the [ValidatingAdmissionPolicy Kubernetes resource](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/),
please refer to [writing a policy](#writing-a-policy) for more information on what fields are supported.

The policy is implemented using [CEL](https://github.com/google/cel-go) and [Kubernetes CEL libraries](https://pkg.go.dev/k8s.io/apiserver/pkg/cel/library), together with our own Kubewarden CEL library extensions for context-aware calls.
This allows reusing the same CEL syntax and functions that are available in Kubernetes.

### Writing a policy

Both `validations` and `variables` fields from Kubernetes' ValidatingAdmissionPolicies are supported.
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

#### Example

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
  module: registry://ghcr.io/kubewarden/policies/cel-policy:0.1.0
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

### Kubewarden CEL library extensions

#### `kw.net.lookupHost`

This CEL function looks up the addresses for a given hostname via DNS. It
returns the addresses as a list of strings.

    net.lookupHost(<string>) -> <list<string>>

Example:

    kw.net.lookupHost('google.com') // returns '142.250.185.238'

#### `kw.oci.verifyPubKeysImage`

This CEL function verifies Sigstore signatures of an image using public keys.

    OCI.verifyPubKeysImage(<string>, <list<string>>, map(<string>)<string>) -> <bool, string>

Returns a `map(<string>)` with 2 fields:

- `"trusted": <bool>` informs if the image passed verification or not
- `"digest": <string>` digest of the verified image

Example:

    kw.oci.verifyPubKeysImage('ghcr.io/example/image', [variables.pubkey], {} ).trusted == true
    where variables.pubkey is defined as '-----BEGIN PUBLIC KEY----- <key contents> ==-----END PUBLIC KEY-----'

## Known limitations

At the moment the policy does not support the following Kubernetes extensions:

- [authz](https://pkg.go.dev/k8s.io/apiserver/pkg/cel/library#Authz)
