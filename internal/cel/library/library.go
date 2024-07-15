// Package library implements CEL extension functions that expose Kubewarden
// context-aware capabilities as CEL functions for the policy to use.
package library

import "github.com/kubewarden/policy-sdk-go/pkg/capabilities"

// handle to interact with the policy host.
var host = capabilities.NewHost()
