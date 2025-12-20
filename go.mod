module github.com/kubewarden/cel-policy

go 1.25.0

toolchain go1.25.5

require (
	github.com/google/cel-go v0.26.1
	github.com/hashicorp/go-multierror v1.1.1
	github.com/kubewarden/k8s-objects v1.29.0-kw1
	github.com/kubewarden/policy-sdk-go v0.12.0
	github.com/opencontainers/image-spec v1.1.1
	github.com/stretchr/testify v1.11.1
	k8s.io/api v0.35.0
	k8s.io/apiserver v1.34.2
)

require (
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/net v0.47.0 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20250910181357-589584f1c912 // indirect
	k8s.io/utils v0.0.0-20251002143259-bc988d571ff4 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.0 // indirect
)

replace github.com/go-openapi/strfmt => github.com/kubewarden/strfmt v0.1.3

replace (
	k8s.io/apiserver v0.29.1 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.31.1 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.31.2 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.31.3 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.32.0 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.32.1 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.32.2 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.32.3 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.33.0 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.33.1 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.33.2 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.33.3 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.33.4 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.34.0 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.34.1 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.34.2 => ./third_party/k8s.io/apiserver/
)

replace (
	k8s.io/apimachinery v0.29.1 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.31.1 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.31.2 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.31.3 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.32.0 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.32.1 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.32.2 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.32.3 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.33.0 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.33.1 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.33.2 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.33.3 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.33.4 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.34.0 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.34.1 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.34.2 => ./third_party/k8s.io/apimachinery/
)

require (
	cel.dev/expr v0.24.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-openapi/strfmt v0.23.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/wapc/wapc-guest-tinygo v0.3.3 // indirect
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250303144028-a0af3efb3deb // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250528174236-200df99c418a // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apimachinery v0.35.0
	k8s.io/kubernetes v1.35.0
)
