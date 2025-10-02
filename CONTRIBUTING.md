# Contributing

This policy follows the same [Kubewarden contributing
guidelines](https://github.com/kubewarden/community/blob/main/CONTRIBUTING.md#rust-code-conventions).
Please review them before contributing.

## End-to-End Testing

The end-to-end (e2e) tests for this policy have a special requirement. They
need access to Kubernetes resources to be used as parameters, which
necessitates adding a `contextAwareResources` section to the policy's metadata
file.

However, this configuration is for testing only and must not be present in the
default `metadata.yml` file used for releases.

To solve this, the `metadata.yml` file used during e2e tests is generated
dynamically right before the test suite runs. This process is handled
automatically by the `e2e-tests` target in the `Makefile`.
