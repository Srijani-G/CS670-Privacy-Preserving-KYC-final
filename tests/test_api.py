"""API request-schema and endpoint boundary tests for the private registry."""

from fastapi import HTTPException
from pydantic import ValidationError

from backend.app import RegistryRequest, private_registry_read


def test_registry_api_accepts_2048_records():
    records = [index % 4 for index in range(2048)]
    request = RegistryRequest(records=records, index=2047)

    result = private_registry_read(request)

    assert result["registry_size"] == 2048
    assert result["status_code"] == records[2047]
    assert result["status_label"] == "Under review"


def test_registry_api_rejects_more_than_2048_records():
    records = [index % 4 for index in range(2049)]

    try:
        RegistryRequest(records=records, index=2048)
    except ValidationError:
        pass
    else:
        raise AssertionError("Registry API schema must reject 2,049 records")


def test_registry_api_rejects_empty_registry():
    try:
        RegistryRequest(records=[], index=0)
    except ValidationError:
        pass
    else:
        raise AssertionError("Registry API schema must reject an empty registry")


def test_registry_api_rejects_index_outside_registry():
    request = RegistryRequest(records=[0], index=1)

    try:
        private_registry_read(request)
    except HTTPException as exc:
        assert exc.status_code == 422
    else:
        raise AssertionError("Registry API must reject an out-of-range index")
