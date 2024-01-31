#!/usr/bin/env bats

@test "accept" {
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

@test "reject" {
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

