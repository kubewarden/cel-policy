module github.com/kubewarden/cel-policy

go 1.22.0

toolchain go1.23.5

require (
	github.com/google/cel-go v0.22.1
	github.com/hashicorp/go-multierror v1.1.1
	github.com/kubewarden/k8s-objects v1.29.0-kw1
	github.com/kubewarden/policy-sdk-go v0.11.0
	github.com/opencontainers/image-spec v1.1.0
	github.com/stretchr/testify v1.10.0
	k8s.io/apiserver v1.32.0
)

replace github.com/go-openapi/strfmt => github.com/kubewarden/strfmt v0.1.3

replace (
	k8s.io/apiserver v0.29.1 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.31.1 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.31.2 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.31.3 => ./third_party/k8s.io/apiserver/
	k8s.io/apiserver v1.32.0 => ./third_party/k8s.io/apiserver/
)

replace (
	k8s.io/apimachinery v0.29.1 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.31.1 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.31.2 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.31.3 => ./third_party/k8s.io/apimachinery/
	k8s.io/apimachinery v1.32.0 => ./third_party/k8s.io/apimachinery/
)

require (
	cel.dev/expr v0.18.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-openapi/strfmt v0.23.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/wapc/wapc-guest-tinygo v0.3.3 // indirect
	golang.org/x/exp v0.0.0-20230515195305-f3d0a9c9a5cc // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apimachinery v0.30.2 // indirect
)
