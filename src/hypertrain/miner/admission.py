"""Client-side signatures only; the service decides funding and eligibility."""

from __future__ import annotations

from pydantic import JsonValue

from hypertrain.protocol.envelope_v2 import join_signing_message, seal
from hypertrain.protocol.keys import Keypair
from hypertrain.protocol.messages_v2 import HardwareHint, JoinRequest, RotateRequest, WorkProof


def sign_join(
    hotkey: Keypair,
    coldkey: Keypair,
    *,
    run_id: str,
    request_id: str,
    expires_beacon: int,
    policy_hash: str,
    hardware_hint: HardwareHint,
) -> JoinRequest:
    request = JoinRequest(
        run_id=run_id,
        request_id=request_id,
        hotkey=hotkey.ss58,
        coldkey=coldkey.ss58,
        expires_beacon=expires_beacon,
        policy_hash=policy_hash,
        hardware_hint=hardware_hint,
        hot_sig="0" * 128,
        cold_sig="0" * 128,
    )
    message = join_signing_message(request)
    return JoinRequest.model_validate(
        {
            **request.body(),
            "hot_sig": hotkey.sign(message).hex(),
            "cold_sig": coldkey.sign(message).hex(),
        }
    )


def sign_proof(
    hotkey: Keypair, run_id: str, proof: WorkProof, expires_beacon: int
) -> dict[str, JsonValue]:
    return seal(hotkey, "WorkProof", run_id, proof, expires_beacon)


def sign_rotation(
    coldkey: Keypair, run_id: str, request: RotateRequest, expires_beacon: int
) -> dict[str, JsonValue]:
    return seal(coldkey, "RotateRequest", run_id, request, expires_beacon)
