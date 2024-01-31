## CEL Policy

This policy is a meta-policy that allows to run [CEL](https://github.com/google/cel-go) expressions
against Kubernetes resources.
A meta-policy is a policy that can be configured via settings, and does not require to be recompiled to change its behavior, acting as a DSL.

The settings of the policy are compliant with the [ValidatingAdmissionPolicy Kubernetes resource](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/),
please refer to [writing a policy](#writing-a-policy) for more information on what fields are supported.

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

## Known limitations

At the moment the policy does not support the following Kubernetes extensions:

- [quantity](https://pkg.go.dev/k8s.io/apiserver/pkg/cel/library#Quantity)
- [authz](https://pkg.go.dev/k8s.io/apiserver/pkg/cel/library#Authz)
