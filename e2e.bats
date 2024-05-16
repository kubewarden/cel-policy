#!/usr/bin/env bats

@test "vanilla cel test: accept" {
  run kwctl run annotated-policy.wasm \
    --allow-context-aware \
    --replay-host-capabilities-interactions test_data/session.yaml \
    --request-path test_data/deployment_lte_max_replicas.json \
    --settings-path test_data/settings.json

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "vanilla cel test: reject" {
  run kwctl run annotated-policy.wasm \
    --allow-context-aware \
    --replay-host-capabilities-interactions test_data/session.yaml \
    --request-path test_data/deployment_gt_max_replicas.json \
    --settings-path test_data/settings.json

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*Deployment: nginx, namespace: default - replicas must be no greater than 50.*') -ne 0 ]
  [ $(expr "$output" : '.*code.*401') -ne 0 ]
}

# NET tests

@test "kw.net.lookupHost: accept" {
  run kwctl run  --request-path test_data/net/pod_creation.json --settings-path test_data/net/settings-lookuphost.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "kw.net.lookupHost: reject" {
  run kwctl run  --request-path test_data/net/pod_creation.json --settings-path test_data/net/settings-lookuphost-reject.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false,"status":{"message":"Wanted 127.0.0.2, got 127.0.0.1 instead","code":401}.*') -ne 0 ]
}

# Kubernetes tests
  
@test "kw.k8s.getResource: Accept" {
  run kwctl run \
    --request-path test_data/kubernetes/pod.json \
    --replay-host-capabilities-interactions test_data/kubernetes/session.yml \
    --settings-path test_data/kubernetes/settings-getresource.yaml \
    --allow-context-aware \
    annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "kw.k8s.listAllResources: Accept" {
  run kwctl run \
    --request-path test_data/kubernetes/pod.json \
    --replay-host-capabilities-interactions test_data/kubernetes/session-listallresources.yml \
    --settings-path test_data/kubernetes/settings-listallresources.yaml \
    --allow-context-aware \
    annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "kw.k8s.listResourcesByNamespace: Accept" {
  run kwctl run \
    --request-path test_data/kubernetes/pod.json \
    --replay-host-capabilities-interactions test_data/kubernetes/session-listresources.yaml \
    --settings-path test_data/kubernetes/settings-listresources.yaml \
    --allow-context-aware \
    annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

# OCI tests
 
@test "kw.oci.verifyPubKeysImage: accept a valid signature" {
  run kwctl run  --request-path test_data/oci/pod_creation_signed.json --settings-path test_data/oci/settings-verify.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "kw.oci.verifyPubKeysImage: Reject a valid signature because of missing annotation" {
  run kwctl run  --request-path test_data/oci/pod_creation_signed.json --settings-path test_data/oci/settings-rejection-with-annot.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*Image verification failed: missing signatures.*The following constraints were not satisfied.*annotation: nonexistent.*') -ne 0 ]
}

@test "kw.oci.verifyPubKeysImage: Reject because of missing signature" {
  run kwctl run  --request-path test_data/oci/pod_creation_unsigned.json --settings-path test_data/oci/settings-reject.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*"message":.*no signatures found for image.*') -ne 0 ]
}
