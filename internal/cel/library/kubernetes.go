//nolint:varnamelen
package library

import (
	"encoding/json"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/kubernetes"
)

// Kubernetes provides a CEL function library extension for performing context-aware calls.
//
// apiVersion
//
// Returns a scoped client builder that can be used to build a client object for a specific API version.
// (v1 for core group, groupName/groupVersions for other).
//
//	kw.k8s.apiVersion(<string>) <APIVersionClient>
//
// Examples:
//
//	kw.k8s.apiversion('v1') // returns an APIVersionClient for the core group
//	kw.k8s.path('apps/v1') /// returns an APIVersionClient for the 'apps' group
//
// kind
//
// Returns a Client object configured to list or get resources of the provided kind.
//
//	<APIVersionClient>.kind(<string>) <Client>
//
// Examples:
//
//	kw.k8s.apiVersion('v1').kind('Pod') // returns a Client for the 'Pod' resources in the core group
//	kw.k8s.apiVersion('apps/v1').kind('Deployment') // returns a Client for the 'Deployment' resources in the 'apps' group
//
// namespace
//
// Returns a Client object configured to list or get resources in the provided namespace.
//
//	<Client>.namespace(<string>) <Client>
//
// Examples:
//
//	kw.k8s.apiVersion('v1').kind('Pod').namespace('default') // returns a Client for the 'Pod' resources in the core group in the 'default' namespace
//
// labelSelector
//
// Returns a Client object configured to list resources with the provided label selector.
// NOTE: this is ignored for get operations. The label selector should be a valid Kubernetes label selector.
//
//	<Client>.labelSelector(<string>) <Client>
//
// Examples:
//
//	kw.k8s.apiVersion('v1').kind('Pod').labelSelector('app=nginx') // returns a Client for the 'Pod' resources in the core group with the label selector 'app=nginx'
//
// fieldSelector
//
// Returns a Client object configured to list resources with the provided field selector.
// NOTE: this is ignored for get operations. The field selector should be a valid Kubernetes field selector.
//
//	<Client>.fieldSelector(<string>) <Client>
//
// Examples:
//
//	kw.k8s.apiVersion('v1').kind('Pod').fieldSelector('status.phase=Running') // returns a Client for the 'Pod' resources in the core group with the field selector 'status.phase=Running'
//
// list
//
// Returns a list of Kubernetes resources matching the client configuration.
//
//	<Client>.list() <objectList>
//
// Examples:
//
//	kw.k8s.apiVersion('v1').kind('Pod').namespace('default').list() // returns a list of 'Pod' resources in the 'default' namespace
//	kw.k8s.apiVersion('v1').kind('Pod').list() // returns a list of 'Pod' resources in all namespaces
//	kw.k8s.apiVersion('v1').kind('Pod').labelSelector('app=nginx').list() // returns a list of 'Pod' resources in all namespaces with the label selector 'app=nginx'
//	kw.k8s.apiVersion('v1').kind('Pod').fieldSelector('status.phase=Running').namespace('default').list() // returns a list of running 'Pod' resources in the default namespace with the field selector 'status.phase=Running'
//
// get
//
// Returns a Kubernetes resource matching the provided name.
// If a resource is namespaced, the namespace should be set using the namespace method.
//
//	<Client>.get(<string>) <object>
//
// Examples:
//
//	kw.k8s.apiVersion('v1').kind('Pod').namespace('default').get('nginx') // returns the 'Pod' resource with the name 'nginx' in the 'default' namespace
//	kw.k8s.apiVersion('v1').kind('Pod').get('nginx') // error, 'Pod' resources are namespaced and the namespace must be set
//	kw.k8s.apiVersion('v1').kind('Namespace').get('default') // returns the 'Namespace' resource with the name 'default'

func Kubernetes() cel.EnvOption {
	return cel.Lib(&kubernetesLib{})
}

type kubernetesLib struct{}

func (*kubernetesLib) LibraryName() string {
	return "kw.k8s"
}

func (*kubernetesLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("kw.k8s.apiVersion",
			cel.Overload("kw_k8s_api_version",
				[]*cel.Type{cel.StringType},
				apiVersionClientType,
				cel.UnaryBinding(apiVersion),
			),
		),
		cel.Function("kind",
			cel.MemberOverload("kw_k8s_kind",
				[]*cel.Type{apiVersionClientType, cel.StringType},
				clientType,
				cel.BinaryBinding(kind),
			),
		),
		cel.Function("namespace",
			cel.MemberOverload("kw_k8s_namespace",
				[]*cel.Type{clientType, cel.StringType},
				clientType,
				cel.BinaryBinding(namespace),
			),
		),
		cel.Function("labelSelector",
			cel.MemberOverload("kw_k8s_label_selector",
				[]*cel.Type{clientType, cel.StringType},
				clientType,
				cel.BinaryBinding(labelSelector),
			),
		),
		cel.Function("fieldSelector",
			cel.MemberOverload("kw_k8s_field_selector",
				[]*cel.Type{clientType, cel.StringType},
				clientType,
				cel.BinaryBinding(fieldSelector),
			),
		),
		cel.Function("list",
			cel.MemberOverload("kw_k8s_list",
				[]*cel.Type{clientType},
				cel.DynType,
				cel.UnaryBinding(list),
			),
		),
		cel.Function("get",
			cel.MemberOverload("kw_k8s_get",
				[]*cel.Type{clientType, cel.StringType},
				cel.DynType,
				cel.BinaryBinding(get),
			),
		),
	}
}

func (*kubernetesLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func apiVersion(arg ref.Val) ref.Val {
	apiVersion, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return apiVersionClient{receiverOnlyObjectVal: receiverOnlyVal(apiVersionClientType), apiVersion: apiVersion}
}

func kind(arg1, arg2 ref.Val) ref.Val {
	apiVersionClient, ok := arg1.(apiVersionClient)
	if !ok {
		panic(apiVersionClient)
	}

	kind, ok := arg2.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	return client{receiverOnlyObjectVal: receiverOnlyVal(clientType), apiVersion: apiVersionClient.apiVersion, kind: kind}
}

func namespace(arg1, arg2 ref.Val) ref.Val {
	client, ok := arg1.(client)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg1)
	}

	namespace, ok := arg2.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	client.namespace = &namespace

	return client
}

func labelSelector(arg1, arg2 ref.Val) ref.Val {
	client, ok := arg1.(client)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg1)
	}

	labelSelector, ok := arg2.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	client.labelSelector = &labelSelector

	return client
}

func fieldSelector(arg1, arg2 ref.Val) ref.Val {
	client, ok := arg1.(client)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg1)
	}

	fieldSelector, ok := arg2.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	client.fieldSelector = &fieldSelector

	return client
}

func list(arg ref.Val) ref.Val {
	client, ok := arg.(client)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return client.list()
}

func get(arg1 ref.Val, arg2 ref.Val) ref.Val {
	client, ok := arg1.(client)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg1)
	}

	name, ok := arg2.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	return client.get(name)
}

var apiVersionClientType = cel.ObjectType("kw.k8s.APIVersionClient")

// apiVersionClient is an intermediate object that holds the API version.
// It is used to build the client object.
type apiVersionClient struct {
	receiverOnlyObjectVal
	apiVersion string
}

var clientType = cel.ObjectType("kw.k8s.Client")

// client is the object that holds the Kubernetes client configuration
// and exposes the list and get functions.
type client struct {
	receiverOnlyObjectVal
	apiVersion    string
	kind          string
	namespace     *string
	labelSelector *string
	fieldSelector *string
}

// list returns a list of Kubernetes resources.
func (c *client) list() ref.Val {
	var responseBytes []byte
	var err error
	if c.namespace != nil {
		request := kubernetes.ListResourcesByNamespaceRequest{
			APIVersion:    c.apiVersion,
			Kind:          c.kind,
			Namespace:     *c.namespace,
			LabelSelector: c.labelSelector,
			FieldSelector: c.fieldSelector,
		}

		responseBytes, err = kubernetes.ListResourcesByNamespace(&host, request)
	} else {
		request := kubernetes.ListAllResourcesRequest{
			APIVersion:    c.apiVersion,
			Kind:          c.kind,
			LabelSelector: c.labelSelector,
			FieldSelector: c.fieldSelector,
		}

		responseBytes, err = kubernetes.ListResources(&host, request)
	}

	if err != nil {
		return types.NewErr("cannot list all Kubernetes resources: %s", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return types.NewErr("cannot unmarshal Kubernetes list resources response: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, response)
}

// get returns a Kubernetes resource.
func (c *client) get(name string) ref.Val {
	request := kubernetes.GetResourceRequest{
		APIVersion: c.apiVersion,
		Kind:       c.kind,
		Name:       name,
		Namespace:  c.namespace,
	}

	responseBytes, err := kubernetes.GetResource(&host, request)
	if err != nil {
		return types.NewErr("cannot get Kubernetes resource: %s", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return types.NewErr("cannot unmarshal Kubernetes get resource response: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, response)
}
