"""A small JSON Schema checker for the keywords this package's schemas use.

The schemas in schemas/ are ordinary JSON Schema (draft 2020-12), so any
standard validator accepts them. An unknown keyword raises SchemaError, so a
schema can never appear to enforce a rule this checker ignores.

Messages name the location and the rule. They do not repeat the offending
value, in case a credential was typed into the wrong field.
"""
import re

_ANNOTATIONS = {"$schema", "$id", "title", "description", "default", "$defs"}
_KEYWORDS = {
    "type", "required", "properties", "additionalProperties", "enum",
    "pattern", "items", "minItems", "minLength", "minimum", "$ref",
}


class SchemaError(ValueError):
    pass


def validate(instance, schema):
    """Return a list of (path, message) problems; empty when valid."""
    problems = []
    _check(instance, schema, schema, "$", problems)
    return problems


def _type_ok(value, name):
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "null":
        return value is None
    raise SchemaError("unsupported type: {}".format(name))


def _resolve(ref, root):
    if not ref.startswith("#/"):
        raise SchemaError("only local $ref values are supported")
    node = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def _check(value, schema, root, path, problems):
    unknown = set(schema) - _KEYWORDS - _ANNOTATIONS
    if unknown:
        raise SchemaError("unsupported schema keywords: {}".format(sorted(unknown)))
    if "$ref" in schema:
        _check(value, _resolve(schema["$ref"], root), root, path, problems)
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(value, name) for name in names):
            problems.append((path, "must be of type {}".format(" or ".join(names))))
            return
    if "enum" in schema and value not in schema["enum"]:
        problems.append((path, "must be one of: {}".format(", ".join(map(str, schema["enum"])))))
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            problems.append((path, "must not be empty"))
        if "pattern" in schema and not re.search(schema["pattern"], value):
            problems.append((path, "must match pattern {}".format(schema["pattern"])))
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            problems.append((path, "must be at least {}".format(schema["minimum"])))
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            problems.append((path, "must have at least {} item(s)".format(schema["minItems"])))
        if "items" in schema:
            for index, item in enumerate(value):
                _check(item, schema["items"], root, "{}[{}]".format(path, index), problems)
    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                problems.append((path, "missing required field '{}'".format(name)))
        properties = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for key, item in value.items():
            child = "{}.{}".format(path, key)
            if key in properties:
                _check(item, properties[key], root, child, problems)
            elif extra is False:
                problems.append((path, "unknown field '{}'".format(key)))
            elif isinstance(extra, dict):
                _check(item, extra, root, child, problems)
