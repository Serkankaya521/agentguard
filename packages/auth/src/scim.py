"""Strict SCIM User normalization; caller supplies authenticated tenant."""
from dataclasses import dataclass


@dataclass(frozen=True)
class SCIMUser:
    external_id: str
    user_name: str
    display_name: str
    active: bool


def parse_user(payload: dict) -> SCIMUser:
    if not isinstance(payload,dict):
        raise ValueError("SCIM resource must be an object")
    allowed = {"schemas","externalId","userName","displayName","active","name","emails"}
    if set(payload)-allowed:
        raise ValueError("unsupported SCIM field")
    external_id, user_name = payload.get("externalId"), payload.get("userName")
    if not isinstance(external_id,str) or not external_id or not isinstance(user_name,str) or not user_name:
        raise ValueError("externalId and userName are required")
    display = payload.get("displayName") or user_name
    return SCIMUser(external_id[:255],user_name[:255],str(display)[:120],bool(payload.get("active",True)))
