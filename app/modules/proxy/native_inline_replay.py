"""Opt-in normalization of explicit native Responses-Lite HTTP input.

No recovery of stored or opaque context is performed here. The projection is
sent before the first dispatch, so a later quota retry sends the same content.
"""

from copy import deepcopy

from app.modules.proxy.replay_safety import responses_payload_is_account_neutral_fresh_replay


def project_native_inline_payload(payload: dict) -> dict | None:
    if payload.get("tools") not in (None, []):
        return None
    if any(payload.get(key) not in (None, "") for key in ("previous_response_id", "conversation", "prompt")):
        return None
    items = payload.get("input")
    if not isinstance(items, list) or not items:
        return None
    if not isinstance(items[0], dict) or items[0].get("type") != "additional_tools":
        return None
    candidate = deepcopy(payload)
    for item in candidate["input"]:
        if not isinstance(item, dict):
            return None
        if "type" in item and not isinstance(item["type"], str):
            return None
        # A populated inline item is mandatory; references/opaque state remain
        # in the candidate and are rejected by the whole-payload classifier.
        if "id" in item and (not isinstance(item["id"], str) or not item["id"].strip()):
            return None
        item.pop("id", None)

    validation = deepcopy(candidate)
    tools_disabled = items[0].get("tools") == []
    declarations = {}
    for item in validation["input"]:
        if item.get("type") != "additional_tools":
            continue
        if item is not validation["input"][0]:
            return None
        tools = item.get("tools")
        if not isinstance(tools, list):
            return None
        flat = []
        namespaces = set()
        for namespace in tools:
            if (
                not isinstance(namespace, dict)
                or namespace.get("type") != "namespace"
                or not set(namespace) <= {"type", "name", "description", "tools"}
            ):
                return None
            name = namespace.get("name")
            leaves = namespace.get("tools")
            if (
                not isinstance(name, str)
                or not name.strip()
                or name in namespaces
                or not isinstance(leaves, list)
                or ("description" in namespace and not isinstance(namespace["description"], str))
            ):
                return None
            namespaces.add(name)
            for leaf in leaves:
                if (
                    not isinstance(leaf, dict)
                    or not isinstance(leaf.get("type"), str)
                    or leaf["type"] not in {"function", "custom"}
                ):
                    return None
                leaf_name = leaf.get("name")
                if not isinstance(leaf_name, str) or not leaf_name.strip() or leaf_name in declarations:
                    return None
                declarations[leaf_name] = (name, leaf["type"])
                flat.append(leaf)
        item["tools"] = flat
    for item in validation["input"]:
        kind = item.get("type")
        if kind in {"function_call", "custom_tool_call"}:
            call_name = item.get("name")
            if not isinstance(call_name, str):
                return None
            declared = declarations.get(call_name)
            expected = "function" if kind == "function_call" else "custom"
            if tools_disabled:
                # Native local compaction disables tools but keeps completed
                # history. Admit only the exact native call shape we proved;
                # do not restore declarations or alter historical wire input.
                if (item.get("namespace"), call_name, expected) != ("functions", "exec", "custom"):
                    return None
                declared = ("functions", "custom")
            if declared is None or declared[1] != expected:
                return None
            if "namespace" in item:
                if item["namespace"] != declared[0]:
                    return None
                item.pop("namespace")

    reasoning = validation.get("reasoning")
    if isinstance(reasoning, dict) and "context" in reasoning:
        if reasoning["context"] != "all_turns":
            return None
        reasoning.pop("context")
    metadata = validation.get("client_metadata")
    if isinstance(metadata, dict):
        for key in ("root_turn_id", "thread_id", "turn_id", "session_id"):
            if key in metadata:
                if not isinstance(metadata[key], str) or not metadata[key].strip():
                    return None
                metadata.pop(key)
    if not responses_payload_is_account_neutral_fresh_replay(validation):
        return None
    return candidate


def normalize_native_inline_request(request):
    # Check the model BEFORE wire sanitizers can omit unsupported opaque items.
    if not request._codex_lb_native_inline_input_preserved:
        return None
    projected = project_native_inline_payload(request.model_dump_for_forwarding())
    return request.model_copy(update={"input": projected["input"]}) if projected is not None else None
