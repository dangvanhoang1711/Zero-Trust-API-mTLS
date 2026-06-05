import os
from functools import wraps

import yaml
from flask import Blueprint, jsonify, request, g

from services.jwt_validator import JWKSValidator

abac_bp = Blueprint("abac", __name__, url_prefix="/api/abac")
validator = JWKSValidator()

_POLICY_PATH = os.environ.get(
    "ABAC_POLICY_PATH",
    "/app/config/authz-policy.yaml",
)

_POLICY_CACHE = None


def _load_policy():
    global _POLICY_CACHE
    if _POLICY_CACHE is not None:
        return _POLICY_CACHE
    if not os.path.exists(_POLICY_PATH):
        return {"version": "1", "default_action": "allow", "rules": []}
    with open(_POLICY_PATH) as f:
        _POLICY_CACHE = yaml.safe_load(f)
    return _POLICY_CACHE


def require_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        if not token:
            return jsonify({"error": "Missing authorization token"}), 401
        try:
            g.token_payload = validator.verify_token(token)
            g.token_raw = token
        except Exception as e:
            return jsonify({"error": "Invalid token", "detail": str(e)}), 401
        return f(*args, **kwargs)
    return decorated


@abac_bp.route("/policies", methods=["GET"])
@require_jwt
def policies():
    policy = _load_policy()
    claims = g.token_payload
    roles = claims.get("realm_access", {}).get("roles", [])
    rules = policy.get("rules", [])

    enriched = []
    for rule in rules:
        match = rule.get("match", {})
        conditions = rule.get("conditions", {})
        action = rule.get("action", "allow")

        matched = _match_rule(rule, claims, roles)
        enriched.append({
            "name": rule.get("name", ""),
            "match": match,
            "conditions": conditions,
            "action": action,
            "userMatch": matched,
        })

    return jsonify({
        "version": policy.get("version", "1"),
        "default_action": policy.get("default_action", "allow"),
        "rules": enriched,
        "user": {
            "sub": claims.get("sub"),
            "iss": claims.get("iss"),
            "aud": claims.get("aud"),
            "roles": roles,
            "preferred_username": claims.get("preferred_username"),
            "email": claims.get("email"),
        },
    })


@abac_bp.route("/evaluate", methods=["GET"])
@require_jwt
def evaluate():
    target_path = request.args.get("path", "")
    target_method = request.args.get("method", "GET").upper()

    if not target_path:
        return jsonify({"error": "Missing 'path' query parameter"}), 400

    policy = _load_policy()
    claims = g.token_payload
    roles = claims.get("realm_access", {}).get("roles", [])

    rules = policy.get("rules", [])
    default_action = policy.get("default_action", "allow")

    matching_rules = []
    for rule in rules:
        if not _path_matches(rule, target_path):
            continue
        if not _method_matches(rule, target_method):
            continue
        condition_satisfied = _check_conditions(rule, claims, roles)
        matching_rules.append({
            "name": rule.get("name", ""),
            "action": rule.get("action", "allow"),
            "conditionSatisfied": condition_satisfied,
            "conditions": rule.get("conditions", {}),
            "match": rule.get("match", {}),
        })

    if not matching_rules:
        return jsonify({
            "path": target_path,
            "method": target_method,
            "allowed": default_action == "allow",
            "reason": f"no matching rule, default action is '{default_action}'",
            "matchingRules": [],
            "defaultAction": default_action,
        })

    # simulate ext-authz evaluation: first match with satisfied conditions wins
    final = None
    for rule in matching_rules:
        if rule["conditionSatisfied"]:
            final = rule
            break

    if final is None:
        # all matched but no condition satisfied → default action
        return jsonify({
            "path": target_path,
            "method": target_method,
            "allowed": default_action == "allow",
            "reason": f"matched {len(matching_rules)} rules but no condition satisfied, default is '{default_action}'",
            "matchingRules": matching_rules,
            "defaultAction": default_action,
        })

    if final["action"] == "deny":
        return jsonify({
            "path": target_path,
            "method": target_method,
            "allowed": False,
            "reason": f"denied by rule '{final['name']}'",
            "matchingRules": matching_rules,
            "finalRule": final["name"],
            "defaultAction": default_action,
        })

    return jsonify({
        "path": target_path,
        "method": target_method,
        "allowed": True,
        "reason": f"allowed by rule '{final['name']}'",
        "matchingRules": matching_rules,
        "finalRule": final["name"],
        "defaultAction": default_action,
    })


def _path_matches(rule, path):
    match = rule.get("match", {})
    exact = match.get("path", "")
    prefix = match.get("path_prefix", "")
    if exact and exact == path:
        return True
    if prefix and path.startswith(prefix):
        return True
    return False


def _method_matches(rule, method):
    methods = rule.get("match", {}).get("methods")
    if not methods:
        return True
    return method.upper() in [m.upper() for m in methods]


def _match_rule(rule, claims, roles):
    conditions = rule.get("conditions", {})
    if not conditions:
        return True

    constraint = conditions.get("constraint")
    if constraint:
        return _evaluate_constraint(constraint, claims, roles)

    # legacy condition checks
    token_subjects = conditions.get("token_subjects", [])
    if token_subjects and claims.get("sub") not in token_subjects:
        return False

    cert_subjects = conditions.get("cert_subjects", [])
    if cert_subjects:
        return False

    required_claims = conditions.get("claims", {})
    for key, allowed in required_claims.items():
        actual = _resolve_claim(claims, key)
        if not actual or not any(a in allowed for a in actual):
            return False

    required_scopes = conditions.get("required_scopes", [])
    if required_scopes:
        token_scopes = claims.get("scope", "").split()
        if not any(s in token_scopes for s in required_scopes):
            return False

    return True


def _check_conditions(rule, claims, roles):
    return _match_rule(rule, claims, roles)


def _evaluate_constraint(constraint, claims, roles):
    if not isinstance(constraint, dict):
        return True

    # Handle all (AND)
    if "all" in constraint:
        items = constraint["all"]
        if not isinstance(items, list) or len(items) == 0:
            return True
        for item in items:
            if not _evaluate_constraint(item, claims, roles):
                return False
        return True

    # Handle any (OR)
    if "any" in constraint:
        items = constraint["any"]
        if not isinstance(items, list) or len(items) == 0:
            return True
        for item in items:
            if _evaluate_constraint(item, claims, roles):
                return True
        return False

    # Handle not
    if "not" in constraint:
        inner = constraint["not"]
        return not _evaluate_constraint(inner, claims, roles)

    # Leaf condition
    fact = constraint.get("fact", "")
    operator = constraint.get("operator", "")
    value = constraint.get("value")

    actual = _resolve_fact(fact, claims, roles)
    if actual is None:
        return operator == "not_exists"

    if operator == "exists":
        return True
    if operator == "not_exists":
        return False
    if operator == "contains":
        return any(str(value).lower() in str(a).lower() for a in actual)
    if operator == "in":
        allowed = value if isinstance(value, list) else [value]
        return any(str(a) in [str(v) for v in allowed] for a in actual)
    if operator == "eq":
        return any(str(a) == str(value) for a in actual)
    if operator == "neq":
        return not any(str(a) == str(value) for a in actual)
    if operator == "matches":
        import re
        try:
            pattern = re.compile(str(value))
            return any(pattern.search(str(a)) for a in actual)
        except re.error:
            return False
    return True


def _resolve_fact(fact, claims, roles):
    if not fact or "." not in fact:
        return None

    source, path = fact.split(".", 1)
    if source == "token":
        return _resolve_claim(claims, path)
    if source == "request" and path == "time.hour":
        import datetime
        return [str(datetime.datetime.now().hour)]
    if source == "request" and path in ("time.day_of_week", "time.dayofweek", "time.dow"):
        import datetime
        return [str(datetime.datetime.now().weekday())]
    if source == "request" and path == "method":
        return [request.method]
    if source == "request" and path == "path":
        return [request.path]
    return None


def _resolve_claim(claims, path):
    parts = path.split(".")
    current = claims
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    if current is None:
        return None
    if isinstance(current, list):
        return [str(x) for x in current]
    if isinstance(current, str):
        return [current]
    return [str(current)]
