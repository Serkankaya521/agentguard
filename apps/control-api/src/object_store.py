"""S3-compatible evidence object storage with tenant-safe paths."""
from dataclasses import dataclass
import re


def validate_object_key(tenant_id: str, key: str) -> str:
    if len(key) > 1024 or not key.startswith(tenant_id + "/"):
        raise ValueError("cross-tenant object key")
    if any(part in ("", ".", "..") for part in key.split("/")):
        raise ValueError("unsafe object key")
    return key


@dataclass(frozen=True)
class ObjectMetadata:
    size_bytes: int
    sha256: str
    media_type: str


class S3ObjectStore:
    def __init__(self, *, endpoint_url: str, bucket: str, region: str = "us-east-1"):
        import boto3
        self.bucket = bucket
        self.client = boto3.client("s3", endpoint_url=endpoint_url, region_name=region)

    def create_upload(self, tenant_id: str, key: str, *, sha256: str,
                      media_type: str, expires_s: int = 300) -> str:
        validate_object_key(tenant_id,key)
        if not 30 <= expires_s <= 900 or not re.fullmatch(r"[0-9a-f]{64}",sha256):
            raise ValueError("invalid upload constraint")
        return self.client.generate_presigned_url("put_object", Params={
            "Bucket":self.bucket,"Key":key,"ContentType":media_type,
            "Metadata":{"sha256":sha256,"tenant":tenant_id}}, ExpiresIn=expires_s)

    def head(self, tenant_id: str, key: str) -> ObjectMetadata:
        validate_object_key(tenant_id,key)
        data = self.client.head_object(Bucket=self.bucket,Key=key)
        if data.get("Metadata",{}).get("tenant") != tenant_id:
            raise ValueError("object tenant metadata mismatch")
        return ObjectMetadata(data["ContentLength"],data.get("Metadata",{}).get("sha256",""),
                              data.get("ContentType","application/octet-stream"))

    def put(self, tenant_id: str, key: str, content: bytes, *, sha256: str,
            media_type: str) -> ObjectMetadata:
        validate_object_key(tenant_id,key)
        if len(content) > 1_073_741_824 or not re.fullmatch(r"[0-9a-f]{64}",sha256):
            raise ValueError("invalid object")
        self.client.put_object(Bucket=self.bucket,Key=key,Body=content,ContentType=media_type,
                               Metadata={"sha256":sha256,"tenant":tenant_id})
        return self.head(tenant_id,key)

    def delete(self, tenant_id: str, key: str) -> None:
        validate_object_key(tenant_id,key)
        self.client.delete_object(Bucket=self.bucket,Key=key)


class MemoryObjectStore:
    """Deterministic test adapter; production uses S3ObjectStore."""
    def __init__(self):
        self.objects = {}

    def seed(self, tenant_id, key, metadata: ObjectMetadata):
        validate_object_key(str(tenant_id),key)
        self.objects[key] = (str(tenant_id),metadata,b"")

    def create_upload(self, tenant_id, key, *, sha256, media_type, expires_s=300):
        validate_object_key(str(tenant_id),key)
        return "memory://upload/" + key

    def head(self, tenant_id, key):
        validate_object_key(str(tenant_id),key)
        owner, metadata, _ = self.objects[key]
        if owner != str(tenant_id):
            raise ValueError("object tenant metadata mismatch")
        return metadata

    def put(self, tenant_id, key, content: bytes, *, sha256: str, media_type: str):
        validate_object_key(str(tenant_id),key)
        metadata = ObjectMetadata(len(content),sha256,media_type)
        self.objects[key] = (str(tenant_id),metadata,bytes(content))
        return metadata

    def get(self, tenant_id, key):
        validate_object_key(str(tenant_id),key)
        owner, _, content = self.objects[key]
        if owner != str(tenant_id):
            raise ValueError("object tenant metadata mismatch")
        return content

    def delete(self, tenant_id, key):
        validate_object_key(str(tenant_id),key)
        owner,_,_=self.objects[key]
        if owner != str(tenant_id):
            raise ValueError("object tenant metadata mismatch")
        del self.objects[key]
