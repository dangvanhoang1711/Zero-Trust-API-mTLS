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


def abac_enforce(rule_name):
    """Decorator that enforces a named ABAC rule against the current token.

    Evaluates the rule's conditions using the same engine as /api/abac/evaluate.
    Returns 403 with HTML error message if the rule exists but conditions are not met.
    Falls through (allows) if the rule is not found, preserving default_action semantics.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            policy = _load_policy()
            claims = getattr(g, "token_payload", )
            roles = claims.get("realm_access", {}).get("roles", [])
            default_action = policy.get("default_action", "allow")

            # find the named rule
            rule = next((r for r in policy.get("rules", []) if r.get("name") == rule_name), None)

            if rule is None:
                # rule not found — honour default action
                if default_action != "allow":
                    return f"""
                    <!DOCTYPE html>
                    <html><head><meta charset="utf-8"><title>Access Denied</title></head>
                    <body style="font-family: sans-serif; padding: 2rem; background: #fee; color: #900;">
                        <h1>❌ Access Denied - Rule Not Found</h1>
                        <p>ABAC rule <strong>{rule_name}</strong> not found and default action is <code>{default_action}</code>.</p>
                    </body></html>
                    """, 403
                return f(*args, **kwargs)

            satisfied, condition_details = _match_rule(rule, claims, roles)

            if not satisfied:
                failing = [d for d in condition_details if not d.get("result", True)]
                failing_html = "<ul>" + "".join(
                    f"<li><code>{d['fact']}</code> {d['operator']} <code>{d.get('expected')}</code> "
                    f"(actual: <code>{d.get('actual')}</code>) → <strong>FAIL</strong></li>"
                    for d in failing
                ) + "</ul>"
                
                return f"""
                <!DOCTYPE html>
                <html><head><meta charset="utf-8"><title>Access Denied</title></head>
                <body style="font-family: sans-serif; padding: 2rem; background: #fee; color: #900;">
                    <h1>❌ Access Denied - ABAC Policy Mismatch</h1>
                    <p>Rule: <strong>{rule_name}</strong></p>
                    <p>Your request does not satisfy the following conditions:</p>
                    {failing_html}
                </body></html>
                """, 403

            return f(*args, **kwargs)
        return decorated
    return decorator


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

        matched, condition_details = _match_rule(rule, claims, roles)
        enriched.append({
            "name": rule.get("name", ""),
            "match": match,
            "conditions": conditions,
            "action": action,
            "userMatch": matched,
            "conditionDetails": condition_details,
        })

    relevant_roles = [r for r in roles if r in ("admin", "user")] + ["guest"] if not any(r in roles for r in ("admin", "user")) else [r for r in roles if r in ("admin", "user")]
    is_admin = "admin" in roles
    privilege = "HIGH" if is_admin else "LOW"

    return jsonify({
        "version": policy.get("version", "1"),
        "default_action": policy.get("default_action", "allow"),
        "rules": enriched,
        "user": {
            "sub": claims.get("sub"),
            "iss": claims.get("iss"),
            "aud": claims.get("aud"),
            "roles": roles,
            "relevantRoles": relevant_roles,
            "privilege": privilege,
            "preferred_username": claims.get("preferred_username"),
            "email": claims.get("email"),
            "emailVerified": claims.get("email_verified"),
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
        return True, []

    details = []

    # required_scopes — always checked regardless of constraint
    required_scopes = conditions.get("required_scopes", [])
    if required_scopes:
        token_scopes = claims.get("scope", "").split()
        scope_ok = all(s in token_scopes for s in required_scopes)
        details.append({
            "fact": "token.scope",
            "operator": "contains",
            "expected": required_scopes,
            "actual": token_scopes,
            "result": scope_ok,
        })
        if not scope_ok:
            return False, details

    constraint = conditions.get("constraint")
    if constraint:
        result, constraint_details = _evaluate_constraint_detailed(constraint, claims, roles)
        details.extend(constraint_details)
        return result, details

    # legacy condition checks (no constraint block)
    token_subjects = conditions.get("token_subjects", [])
    if token_subjects:
        sub_ok = claims.get("sub") in token_subjects
        details.append({"fact": "token.sub", "operator": "in", "expected": token_subjects, "actual": claims.get("sub"), "result": sub_ok})
        if not sub_ok:
            return False, details

    cert_subjects = conditions.get("cert_subjects", [])
    if cert_subjects:
        details.append({"fact": "cert.subject", "operator": "exists", "expected": "any", "actual": None, "result": False})
        return False, details

    required_claims = conditions.get("claims", {})
    for key, allowed in required_claims.items():
        actual = _resolve_claim(claims, key)
        ok = bool(actual) and any(a in allowed for a in actual)
        details.append({"fact": f"token.{key}", "operator": "in", "expected": allowed, "actual": actual, "result": ok})
        if not ok:
            return False, details

    return True, details


def _check_conditions(rule, claims, roles):
    result, _ = _match_rule(rule, claims, roles)
    return result


def _negate_operator(op):
    return {
        "in": "not in",
        "contains": "not contains",
        "exists": "not exists",
        "not_exists": "exists",
        "matches": "not matches",
        "between": "not between",
        "eq": "neq",
        "neq": "eq",
    }.get(op, f"not {op}")


def _evaluate_constraint_detailed(constraint, claims, roles, path=""):
    if not isinstance(constraint, dict):
        return True, []

    if "all" in constraint:
        items = constraint["all"]
        if not isinstance(items, list) or len(items) == 0:
            return True, []
        all_details = []
        for i, item in enumerate(items):
            ok, sub_details = _evaluate_constraint_detailed(item, claims, roles, f"{path}.all[{i}]")
            all_details.extend(sub_details)
            if not ok:
                return False, all_details
        return True, all_details

    if "any" in constraint:
        items = constraint["any"]
        if not isinstance(items, list) or len(items) == 0:
            return True, []
        any_details = []
        for i, item in enumerate(items):
            ok, sub_details = _evaluate_constraint_detailed(item, claims, roles, f"{path}.any[{i}]")
            any_details.extend(sub_details)
            if ok:
                return True, any_details
        return False, any_details

    if "not" in constraint:
        inner = constraint["not"]
        if "fact" in inner:
            fact = inner.get("fact", "")
            operator = inner.get("operator", "")
            value = inner.get("value")
            actual = _resolve_fact(fact, claims, roles)
            negated = _negate_operator(operator)
            if actual is None:
                result = operator == "not_exists"
                return not result, [{"fact": fact, "operator": negated, "expected": value, "actual": None, "result": not result}]
            ok, _ = _evaluate_constraint_detailed(inner, claims, roles, f"{path}.not")
            return not ok, [{"fact": fact, "operator": negated, "expected": value, "actual": actual, "result": not ok}]
        ok, sub_details = _evaluate_constraint_detailed(inner, claims, roles, f"{path}.not")
        return not ok, sub_details

    fact = constraint.get("fact", "")
    operator = constraint.get("operator", "")
    value = constraint.get("value")

    actual = _resolve_fact(fact, claims, roles)
    if actual is None:
        result = operator == "not_exists"
        return result, [{"fact": fact, "operator": operator, "expected": value, "actual": None, "result": result}]

    if operator == "exists":
        return True, [{"fact": fact, "operator": "exists", "expected": None, "actual": actual, "result": True}]
    if operator == "not_exists":
        return False, [{"fact": fact, "operator": "not_exists", "expected": None, "actual": actual, "result": False}]
    if operator == "contains":
        result = any(str(value).lower() in str(a).lower() for a in actual)
        return result, [{"fact": fact, "operator": "contains", "expected": value, "actual": actual, "result": result}]
    if operator == "in":
        allowed = value if isinstance(value, list) else [value]
        result = any(str(a) in [str(v) for v in allowed] for a in actual)
        return result, [{"fact": fact, "operator": "in", "expected": allowed, "actual": actual, "result": result}]
    if operator == "between":
        if isinstance(value, list) and len(value) == 2:
            result = any(float(value[0]) <= float(a) <= float(value[1]) for a in actual)
        else:
            result = False
        return result, [{"fact": fact, "operator": "between", "expected": value, "actual": actual, "result": result}]
    if operator == "eq":
        result = any(str(a) == str(value) for a in actual)
        return result, [{"fact": fact, "operator": "eq", "expected": value, "actual": actual, "result": result}]
    if operator == "neq":
        result = not any(str(a) == str(value) for a in actual)
        return result, [{"fact": fact, "operator": "neq", "expected": value, "actual": actual, "result": result}]
    if operator == "matches":
        import re
        try:
            pattern = re.compile(str(value))
            result = any(pattern.search(str(a)) for a in actual)
        except re.error:
            result = False
        return result, [{"fact": fact, "operator": "matches", "expected": value, "actual": actual, "result": result}]
    return True, []


def _resolve_fact(fact, claims, roles):
    if not fact or "." not in fact:
        return None

    import datetime
    from zoneinfo import ZoneInfo
    _TZ = ZoneInfo("Asia/Ho_Chi_Minh")

    source, path = fact.split(".", 1)
    if source == "token":
        return _resolve_claim(claims, path)
    if source == "request" and path == "time.hour":
        now = datetime.datetime.now(_TZ)
        return [str(now.hour)]
    if source == "request" and path in ("time.day_of_week", "time.dayofweek", "time.dow"):
        now = datetime.datetime.now(_TZ)
        dw = now.weekday()          # Mon=0 … Sun=6
        return [str((dw + 1) % 7)] # Sun=0, Mon=1 … Sat=6  (Go convention)
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
