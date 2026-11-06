"""API request-schema boundary tests for the private registry endpoint."""

from pydantic import ValidationError

from backend.app import RegistryRequest


def test_registry_api_accepts_2048_records():
    records = [index % 4 for index in range(2048)]
    request = RegistryRequest(records=records, index=2047)

    assert len(request.records) == 2048
    assert request.index == 2047


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
