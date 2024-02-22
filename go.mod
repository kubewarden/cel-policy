module github.com/kubewarden/cel-policy

go 1.21.5

require (
	github.com/google/cel-go v0.17.7
	github.com/hashicorp/go-multierror v1.1.1
	github.com/kubewarden/k8s-objects v1.29.0-kw1
	github.com/kubewarden/policy-sdk-go v0.8.0
	github.com/stretchr/testify v1.8.4
	k8s.io/apiserver v0.29.1
)

replace github.com/go-openapi/strfmt => github.com/kubewarden/strfmt v0.1.3

replace k8s.io/apiserver v0.29.1 => ./third_party/k8s.io/apiserver/

replace k8s.io/apimachinery v0.29.1 => ./third_party/k8s.io/apimachinery/

require (
	github.com/antlr/antlr4/runtime/Go/antlr/v4 v4.0.0-20230305170008-8188dc5388df // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-openapi/strfmt v0.21.3 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/wapc/wapc-guest-tinygo v0.3.3 // indirect
	golang.org/x/exp v0.0.0-20230515195305-f3d0a9c9a5cc // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230803162519-f966b187b2e5 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230822172742-b8732ec3820d // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apimachinery v0.29.1 // indirect
)
