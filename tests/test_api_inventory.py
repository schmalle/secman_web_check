import json

import pytest

from secman_web_check.api_inventory import observed_operation, openapi_inventory


def test_declared_operations_keep_placeholders_methods_types_and_auth_but_no_values(tmp_path):
    path = tmp_path / "api.json"
    path.write_text(
        json.dumps(
            {
                "openapi": "3.1.0",
                "security": [{"bearer": []}],
                "components": {
                    "parameters": {
                        "item": {
                            "name": "id",
                            "in": "path",
                            "schema": {"type": "string"},
                            "example": "SYNTHETIC",
                        }
                    }
                },
                "paths": {
                    "/items/{id}": {
                        "parameters": [{"$ref": "#/components/parameters/item"}],
                        "get": {
                            "parameters": [
                                {
                                    "name": "token",
                                    "in": "query",
                                    "schema": {"type": "string", "default": "SYNTHETIC"},
                                }
                            ],
                            "responses": {
                                "200": {
                                    "content": {"application/json": {"schema": {"type": "object"}}}
                                }
                            },
                        },
                        "delete": {
                            "requestBody": {
                                "content": {"application/json": {"example": "SYNTHETIC"}}
                            },
                            "responses": {},
                        },
                    }
                },
            }
        )
    )
    inventory = openapi_inventory(path)
    assert {operation.method for operation in inventory} == {"GET", "DELETE"}
    assert all(not operation.executed and operation.authenticated for operation in inventory)
    assert inventory[0].path == "/items/{id}"
    assert "path:id:string" in inventory[0].parameters
    assert inventory[0].response_content_types == ("application/json",)
    assert "SYNTHETIC" not in repr(inventory)


@pytest.mark.parametrize(
    "reference", ["https://attacker.example/schema", "#/missing", "#/paths/~1cycle"]
)
def test_external_missing_or_cyclic_refs_fail_without_network(tmp_path, reference):
    path = tmp_path / "api.json"
    path.write_text(json.dumps({"paths": {"/cycle": {"$ref": reference}}}))
    with pytest.raises((TypeError, ValueError)):
        openapi_inventory(path)


def test_observed_read_parameters_drop_values_and_blocked_write_is_not_executed():
    read = observed_operation(
        "https://example.com/api?token=SYNTHETIC&limit=5", "GET", "application/json; charset=utf-8"
    )
    assert read.parameters == ("query:limit:unknown", "query:token:unknown")
    assert read.executed
    assert "SYNTHETIC" not in repr(read)
    assert not observed_operation("https://example.com/api", "POST").executed
