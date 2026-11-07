#!/usr/bin/env bash

run_id="${1:?usage: <run_id> <name>}"
name="${2:?usage: <run_id> <name>}"

./build/linux/arm64/debug/bundle/ic_node_ui \
	--config ~/.ic-pw-demo/${run_id}/config/${name}.json
