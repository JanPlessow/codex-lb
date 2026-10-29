from copy import deepcopy

import pytest

from app.modules.proxy.native_inline_replay import project_native_inline_payload


def inline():
    return {
        "model": "gpt-6-astra",
        "instructions": "",
        "reasoning": {"effort": "medium", "context": "all_turns"},
        "client_metadata": {"root_turn_id": "turn-local"},
        "input": [
            {
                "type": "additional_tools",
                "id": "at_local",
                "role": "developer",
                "tools": [
                    {
                        "type": "namespace",
                        "name": "functions",
                        "tools": [{"type": "custom", "name": "exec", "format": {"type": "text"}}],
                    }
                ],
            },
            {
                "type": "message",
                "id": "msg_local",
                "role": "developer",
                "content": [{"type": "input_text", "text": "Preserve this exact instruction."}],
            },
            {
                "type": "custom_tool_call",
                "id": "ctc_local",
                "name": "exec",
                "namespace": "functions",
                "call_id": "call-local",
                "input": "write_once()",
                "status": "completed",
            },
            {"type": "custom_tool_call_output", "id": "ctco_local", "call_id": "call-local", "output": "done"},
        ],
    }


def test_projection_preserves_every_value_except_top_level_item_ids():
    source = inline()
    before = deepcopy(source)
    result = project_native_inline_payload(source)
    expected = deepcopy(source)
    for item in expected["input"]:
        item.pop("id")
    assert result == expected
    assert source == before
    assert project_native_inline_payload(result) == result


def test_disabled_tools_preserve_complete_native_history_without_restoring_tools():
    source = inline()
    source["input"][0]["tools"] = []
    result = project_native_inline_payload(source)
    expected = deepcopy(source)
    for item in expected["input"]:
        item.pop("id")
    assert result == expected
    assert result["input"][0]["tools"] == []


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p["input"].pop(),
        lambda p: p["input"].append(deepcopy(p["input"][-1])),
        lambda p: p["input"][2].pop("namespace"),
        lambda p: p["input"][2].update(namespace="unproved"),
        lambda p: p["input"][2].update(name="unproved"),
        lambda p: p["input"][2].update(type="function_call"),
        lambda p: p["input"].append({"type": "compaction", "encrypted_content": "opaque"}),
    ],
)
def test_disabled_tools_still_refuse_pending_unknown_and_opaque_history(change):
    source = inline()
    source["input"][0]["tools"] = []
    change(source)
    assert project_native_inline_payload(source) is None


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p.update(previous_response_id="resp-owner"),
        lambda p: p.update(conversation="conv-owner"),
        lambda p: p.update(prompt={"id": "prompt-owner"}),
        lambda p: p.update(future_state="opaque"),
        lambda p: p.update(tools=[{"type": "custom", "name": "exec"}]),
        lambda p: p["input"].append({"type": "reasoning", "id": "rs-owner", "encrypted_content": "opaque"}),
        lambda p: p["input"].append({"type": "compaction", "encrypted_content": "opaque"}),
        lambda p: p["input"].append({"type": "item_reference", "id": "msg-owner"}),
        lambda p: p["input"].append({"type": "input_file", "file_id": "file-owner"}),
        lambda p: p["input"].pop(),
        lambda p: p["input"].append(deepcopy(p["input"][-1])),
        lambda p: p["input"][2].update(namespace="unknown"),
        lambda p: p["input"][2].update(name="unknown"),
        lambda p: p["input"][2].update(namespace={"file_id": "owner"}),
        lambda p: p["input"][1].update(future_state="owner"),
        lambda p: p["input"][1].update(id={"file_id": "owner"}),
        lambda p: p["input"][1].update(content=[]),
        lambda p: p["reasoning"].update(context="unknown"),
        lambda p: p["client_metadata"].update(root_turn_id={"file_id": "owner"}),
        lambda p: p["input"][0]["tools"][0]["tools"].append({"type": "file_search"}),
        lambda p: p["input"][0]["tools"].append(deepcopy(p["input"][0]["tools"][0])),
        lambda p: p["input"][0]["tools"].append(
            {
                "type": "namespace",
                "name": "other",
                "tools": [{"type": "custom", "name": "exec", "format": {"type": "text"}}],
            }
        ),
    ],
)
def test_rejects_incomplete_opaque_ambiguous_and_unknown_state(change):
    payload = inline()
    change(payload)
    assert project_native_inline_payload(payload) is None


def test_stream_entry_rejects_opaque_state_before_lossy_wire_sanitization():
    from app.core.openai.requests import ResponsesRequest
    from app.modules.proxy.native_inline_replay import normalize_native_inline_request

    payload = inline()
    payload["input"] = payload["input"][:1] + [
        {
            "type": "message",
            "role": "assistant",
            "content": [
                {
                    "type": "output_text",
                    "text": "Local compact fallback preserved the latest encrypted reasoning state.",
                }
            ],
        },
        {"type": "compaction", "encrypted_content": "opaque-account-state"},
        {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "continue"}]},
    ]
    request = ResponsesRequest.model_validate(payload)
    # Reproduce the upstream sanitizer's omission, then guard before that step.
    assert len(request.to_replay_safety_payload()["input"]) == 2
    assert normalize_native_inline_request(request) is None


def test_stream_entry_rejects_input_loss_during_model_validation():
    from app.core.openai.requests import ResponsesRequest
    from app.modules.proxy.native_inline_replay import normalize_native_inline_request

    payload = inline()
    payload["input"][1]["reasoning_content"] = "opaque interleaved state"
    request = ResponsesRequest.model_validate(payload)
    assert "reasoning_content" not in request.input[1]
    assert not request._codex_lb_native_inline_input_preserved
    assert normalize_native_inline_request(request) is None
