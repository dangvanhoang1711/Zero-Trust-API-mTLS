package auth

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Operator constants for ABAC conditions.
const (
	opAnd        = "and"
	opOr         = "or"
	opNot        = "not"
	opEq         = "eq"
	opNeq        = "neq"
	opContains   = "contains"
	opIn         = "in"
	opMatches    = "matches"
	opGt         = "gt"
	opGte        = "gte"
	opLt         = "lt"
	opLte        = "lte"
	opBetween    = "between"
	opExists     = "exists"
	opNotExists  = "not_exists"
)

// Condition is a recursive tree structure for ABAC evaluation.
// Leaf conditions must have Fact, Operator, and Value set.
// Logical conditions (All, Any, Not) contain sub-conditions.
type Condition struct {
	All      []Condition `yaml:"all"`
	Any      []Condition `yaml:"any"`
	Not      *Condition  `yaml:"not"`
	Fact     string      `yaml:"fact"`
	Operator string      `yaml:"operator"`
	Value    any         `yaml:"value"`
}

const (
	defaultPolicyAction      = "allow"
	defaultRateLimitWindow   = 60 * time.Second
	defaultRateLimitIdentity = "sub"
)

type PolicyRequest struct {
	Method   string
	Path     string
	Claims   *TokenClaims
	Identity *ClientIdentity
}

type PolicyDecision struct {
	Allowed        bool
	HTTPStatus     int
	Reason         string
	RequiredScopes []string
	RateLimit      *RateLimitDecision
}

type PolicyConfig struct {
	Version       string      `yaml:"version"`
	DefaultAction string      `yaml:"default_action"`
	Global        *PolicyRule `yaml:"global"`
	Rules         []PolicyRule `yaml:"rules"`
}

type PolicyRule struct {
	Name       string           `yaml:"name"`
	Match      PolicyMatch      `yaml:"match"`
	Conditions PolicyConditions `yaml:"conditions"`
	RateLimit  *PolicyRateLimit `yaml:"rate_limit"`
	Action     string           `yaml:"action"`
}

type PolicyMatch struct {
	Path       string   `yaml:"path"`
	PathPrefix string   `yaml:"path_prefix"`
	Methods    []string `yaml:"methods"`
}

type PolicyConditions struct {
	RequiredScopes []string           `yaml:"required_scopes"`
	TokenSubjects  []string           `yaml:"token_subjects"`
	CertSubjects   []string           `yaml:"cert_subjects"`
	Claims         map[string][]string `yaml:"claims"`
	Constraint     *Condition         `yaml:"constraint"`
}

type PolicyRateLimit struct {
	Enabled     bool   `yaml:"enabled"`
	MaxRequests int    `yaml:"max_requests"`
	Window      string `yaml:"window"`
	IdentityBy  string `yaml:"identity_by"`
}

type RateLimitDecision struct {
	Enabled     bool
	MaxRequests int
	Window      time.Duration
	IdentityBy  string
}

func LoadPolicyFromFile(path string) (*PolicyConfig, error) {
	if strings.TrimSpace(path) == "" {
		return NewAllowPolicy(), nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg PolicyConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}

	cfg.normalize()
	return &cfg, nil
}

func NewAllowPolicy() *PolicyConfig {
	return &PolicyConfig{
		DefaultAction: defaultPolicyAction,
	}
}

func (cfg *PolicyConfig) normalize() {
	if cfg == nil {
		return
	}

	if strings.TrimSpace(cfg.DefaultAction) == "" {
		cfg.DefaultAction = defaultPolicyAction
	}
	cfg.DefaultAction = strings.ToLower(strings.TrimSpace(cfg.DefaultAction))

	cfg.Global = normalizePolicyRule(cfg.Global)
	for i := range cfg.Rules {
		cfg.Rules[i] = normalizePolicyRuleValue(cfg.Rules[i])
	}
}

func normalizePolicyRule(rule *PolicyRule) *PolicyRule {
	if rule == nil {
		return nil
	}

	normalized := normalizePolicyRuleValue(*rule)
	return &normalized
}

func normalizePolicyRuleValue(rule PolicyRule) PolicyRule {
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Match.Path = strings.TrimSpace(rule.Match.Path)
	rule.Match.PathPrefix = strings.TrimSpace(rule.Match.PathPrefix)
	rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))

	if len(rule.Conditions.RequiredScopes) > 0 {
		rule.Conditions.RequiredScopes = normalizeList(rule.Conditions.RequiredScopes)
	}

	if len(rule.Conditions.TokenSubjects) > 0 {
		rule.Conditions.TokenSubjects = normalizeList(rule.Conditions.TokenSubjects)
	}

	if len(rule.Conditions.CertSubjects) > 0 {
		rule.Conditions.CertSubjects = normalizeList(rule.Conditions.CertSubjects)
	}

	for idx, method := range rule.Match.Methods {
		rule.Match.Methods[idx] = strings.ToUpper(strings.TrimSpace(method))
	}

	if len(rule.Match.Methods) > 0 {
		rule.Match.Methods = normalizeList(rule.Match.Methods)
	}

	if len(rule.Conditions.Claims) > 0 {
		normalized := make(map[string][]string, len(rule.Conditions.Claims))
		for key, values := range rule.Conditions.Claims {
			normalizedKey := strings.ToLower(strings.TrimSpace(key))
			if normalizedKey == "" {
				continue
			}
			normalized[normalizedKey] = normalizeList(values)
		}
		rule.Conditions.Claims = normalized
	}

	if rule.RateLimit != nil {
		rule.RateLimit.IdentityBy = strings.ToLower(strings.TrimSpace(rule.RateLimit.IdentityBy))
	}

	return rule
}

func (cfg *PolicyConfig) Evaluate(req PolicyRequest) PolicyDecision {
	req.Method = strings.ToUpper(strings.TrimSpace(req.Method))
	req.Path = normalizePolicyPath(req.Path)
	inputClaims := req.Claims
	inputIdentity := req.Identity

	if cfg == nil {
		return PolicyDecision{
			Allowed:    true,
			HTTPStatus: http.StatusOK,
		}
	}

	decision := PolicyDecision{
		Allowed:    true,
		HTTPStatus: http.StatusOK,
	}
	defaultAction := cfg.DefaultAction
	if defaultAction == "" {
		defaultAction = defaultPolicyAction
	}

	matchingRules := cfg.allMatchingRules(req.Path, req.Method)
	requiredScopes := make([]string, 0, 8)

	if !applyPolicyRule(defaultAction, cfg.Global, inputClaims, inputIdentity, &decision, &requiredScopes, false) {
		return decision
	}

	// Try each matching rule in order. If a rule matches path/method but fails
	// conditions, continue to the next rule (allows fallthrough like break-glass).
	ruleApplied := false
	for _, rule := range matchingRules {
		ruleAction := defaultAction
		if strings.TrimSpace(rule.Action) != "" {
			ruleAction = rule.Action
		}
		localDecision := decision
		localScopes := make([]string, len(requiredScopes))
		copy(localScopes, requiredScopes)

		if ok := applyPolicyRule(ruleAction, &rule, inputClaims, inputIdentity, &localDecision, &localScopes, true); ok {
			ruleApplied = true
			decision = localDecision
			requiredScopes = localScopes
			break
		} else if !localDecision.Allowed {
			ruleApplied = true
			decision = localDecision
			requiredScopes = localScopes
			break
		}
	}

	if !ruleApplied {
		// No rule fully matched; apply global + default action only
		decision.RequiredScopes = dedupeList(requiredScopes)
		return decision
	}

	decision.RequiredScopes = dedupeList(requiredScopes)
	return decision
}

func (cfg *PolicyConfig) matchingRule(path, method string) *PolicyRule {
	for idx := range cfg.Rules {
		rule := &cfg.Rules[idx]
		if policyRuleMatches(*rule, path, method) {
			return rule
		}
	}
	return nil
}

func (cfg *PolicyConfig) allMatchingRules(path, method string) []PolicyRule {
	var out []PolicyRule
	for _, rule := range cfg.Rules {
		if policyRuleMatches(rule, path, method) {
			out = append(out, rule)
		}
	}
	return out
}

func applyPolicyRule(action string, rule *PolicyRule, claims *TokenClaims, identity *ClientIdentity, decision *PolicyDecision, requiredScopes *[]string, skipOnConditionFail bool) bool {
	if rule == nil {
		if action == "deny" {
			*decision = PolicyDecision{
				Allowed:    false,
				HTTPStatus: http.StatusForbidden,
				Reason:     "policy denied (default action)",
			}
			return false
		}
		return true
	}

	if ok, reason := policyRuleSatisfied(*rule, claims, identity); !ok {
		if skipOnConditionFail {
			return false
		}
		*decision = PolicyDecision{
			Allowed:    false,
			HTTPStatus: http.StatusForbidden,
			Reason:     reason,
		}
		return false
	}

	*requiredScopes = append(*requiredScopes, rule.Conditions.RequiredScopes...)
	if rule.RateLimit != nil {
		decision.RateLimit = buildRateLimitDecision(rule.RateLimit)
	}

	if action == "deny" {
		*decision = PolicyDecision{
			Allowed:    false,
			HTTPStatus: http.StatusForbidden,
			Reason:     fmt.Sprintf("policy denied by rule %q", rule.Name),
			RateLimit:  decision.RateLimit,
		}
		return false
	}

	return true
}

func policyRuleMatches(rule PolicyRule, path, method string) bool {
	if rule.Match.Path != "" && normalizePolicyPath(rule.Match.Path) != path {
		return false
	}
	if rule.Match.PathPrefix != "" && !strings.HasPrefix(path, normalizePolicyPath(rule.Match.PathPrefix)) {
		return false
	}
	if len(rule.Match.Methods) > 0 {
		matchMethod := false
		for _, configuredMethod := range rule.Match.Methods {
			if strings.EqualFold(strings.TrimSpace(configuredMethod), strings.TrimSpace(method)) {
				matchMethod = true
				break
			}
		}
		if !matchMethod {
			return false
		}
	}
	return true
}

func policyRuleSatisfied(rule PolicyRule, claims *TokenClaims, identity *ClientIdentity) (bool, string) {
	if claims == nil {
		return false, "missing token claims for policy evaluation"
	}

	if len(rule.Conditions.TokenSubjects) > 0 && !stringInList(strings.TrimSpace(claims.Subject), rule.Conditions.TokenSubjects) {
		return false, "token subject does not satisfy policy"
	}

	if identity == nil {
		identity = &ClientIdentity{}
	}
	if len(rule.Conditions.CertSubjects) > 0 && !stringInList(strings.TrimSpace(identity.Subject), rule.Conditions.CertSubjects) {
		return false, "certificate subject does not satisfy policy"
	}

	for key, allowed := range rule.Conditions.Claims {
		if len(allowed) == 0 {
			continue
		}
		if !tokenClaimContainsAllowed(claims, key, allowed) {
			return false, fmt.Sprintf("token claim mismatch: %s", key)
		}
	}

	if rule.Conditions.Constraint != nil {
		if ok, reason := evaluateCondition(*rule.Conditions.Constraint, claims, identity, PolicyRequest{}); !ok {
			return false, reason
		}
	}

	return true, ""
}

func tokenClaimContainsAllowed(claims *TokenClaims, claim string, allowed []string) bool {
	if claims == nil {
		return false
	}

	actual := tokenClaimValues(claims, claim)
	if len(actual) == 0 {
		return false
	}
	for _, value := range actual {
		if stringInList(value, allowed) {
			return true
		}
	}
	return false
}

func tokenClaimValues(claims *TokenClaims, claim string) []string {
	switch key := strings.ToLower(strings.TrimSpace(claim)); key {
	case "sub":
		return normalizeList([]string{claims.Subject})
	case "iss":
		return normalizeList([]string{claims.Issuer})
	case "aud":
		return normalizeList(claims.Audience)
	case "jti":
		return normalizeList([]string{claims.JWTID})
	default:
		return extractClaimValues(claims.RawClaims, strings.Split(key, "."))
	}
}

func extractClaimValues(raw map[string]any, path []string) []string {
	if len(raw) == 0 {
		return nil
	}

	current := map[string]any(raw)
	for i, key := range path {
		next, ok := current[strings.TrimSpace(key)]
		if !ok {
			return nil
		}

		if i == len(path)-1 {
			return anyToStringSlice(next)
		}

		nextMap, ok := next.(map[string]any)
		if !ok {
			return nil
		}
		current = nextMap
	}

	return nil
}

func anyToStringSlice(value any) []string {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		return normalizeList([]string{strings.TrimSpace(v)})
	case []string:
		return normalizeList(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, normalizeToString(item))
		}
		return normalizeList(out)
	case map[string]any:
		out := make([]string, 0, len(v))
		for key := range v {
			out = append(out, key)
		}
		return normalizeList(out)
	default:
		return normalizeList([]string{normalizeToString(v)})
	}
}

func normalizeToString(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		s := strings.TrimSpace(strings.TrimSuffix(fmt.Sprintf("%v", v), ".0"))
		return s
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
}

func buildRateLimitDecision(raw *PolicyRateLimit) *RateLimitDecision {
	if raw == nil || !raw.Enabled {
		return nil
	}

	maxRequests := raw.MaxRequests
	if maxRequests <= 0 {
		return nil
	}

	window := defaultRateLimitWindow
	if raw.Window != "" {
		if parsed, err := time.ParseDuration(strings.TrimSpace(raw.Window)); err == nil && parsed > 0 {
			window = parsed
		}
	}

	identityBy := strings.TrimSpace(raw.IdentityBy)
	if identityBy == "" {
		identityBy = defaultRateLimitIdentity
	}

	return &RateLimitDecision{
		Enabled:     true,
		MaxRequests: maxRequests,
		Window:      window,
		IdentityBy:  identityBy,
	}
}

func normalizeList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func stringInList(value string, list []string) bool {
	i := sort.SearchStrings(list, value)
	return i < len(list) && list[i] == value
}

func dedupeList(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	sort.Strings(values)
	out := values[:0]
	var last string
	for _, value := range values {
		if value == "" {
			continue
		}
		if value != last {
			out = append(out, value)
			last = value
		}
	}
	return out
}

func normalizePolicyPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

// ---------------------------------------------------------------------------
// ABAC Condition Engine
// ---------------------------------------------------------------------------

// evaluateCondition recursively evaluates a condition tree.
// Returns (true, "") if satisfied, (false, reason) if not.
func evaluateCondition(c Condition, claims *TokenClaims, identity *ClientIdentity, req PolicyRequest) (bool, string) {
	op := strings.ToLower(strings.TrimSpace(c.Operator))

	if op == opAnd || (c.All != nil && op == "") {
		return evaluateAll(c.All, claims, identity, req)
	}
	if op == opOr || (c.Any != nil && op == "") {
		return evaluateAny(c.Any, claims, identity, req)
	}
	if op == opNot || c.Not != nil {
		return evaluateNot(c, claims, identity, req)
	}

	// Leaf condition
	if strings.TrimSpace(c.Fact) == "" {
		return false, "condition missing 'fact'"
	}
	if op == "" {
		return false, "condition missing 'operator'"
	}

	actual, err := resolveFact(c.Fact, claims, identity, req)
	if err != "" {
		return false, err
	}

	ok, reason := compareValues(actual, op, c.Value)
	if !ok {
		return false, reason
	}
	return true, ""
}

func evaluateAll(conditions []Condition, claims *TokenClaims, identity *ClientIdentity, req PolicyRequest) (bool, string) {
	if len(conditions) == 0 {
		return true, ""
	}
	for _, c := range conditions {
		if ok, reason := evaluateCondition(c, claims, identity, req); !ok {
			return false, reason
		}
	}
	return true, ""
}

func evaluateAny(conditions []Condition, claims *TokenClaims, identity *ClientIdentity, req PolicyRequest) (bool, string) {
	if len(conditions) == 0 {
		return true, ""
	}
	for _, c := range conditions {
		if ok, _ := evaluateCondition(c, claims, identity, req); ok {
			return true, ""
		}
	}
	return false, "no condition matched (any)"
}

func evaluateNot(c Condition, claims *TokenClaims, identity *ClientIdentity, req PolicyRequest) (bool, string) {
	inner := c.Not
	if inner == nil {
		return false, "'not' condition missing inner condition"
	}
	if ok, _ := evaluateCondition(*inner, claims, identity, req); ok {
		return false, "negated condition was true"
	}
	return true, ""
}

// resolveFact resolves an attribute fact string to its actual value(s).
// Format: "source.attribute.path"
// Sources: token (JWT claims), cert (mTLS identity), request (method/path/time)
func resolveFact(fact string, claims *TokenClaims, identity *ClientIdentity, req PolicyRequest) ([]string, string) {
	fact = strings.TrimSpace(fact)
	if fact == "" {
		return nil, "empty fact"
	}

	parts := strings.SplitN(fact, ".", 2)
	if len(parts) < 2 {
		return nil, fmt.Sprintf("invalid fact %q: expected source.attribute", fact)
	}

	source := strings.ToLower(strings.TrimSpace(parts[0]))
	attrPath := strings.TrimSpace(parts[1])

	switch source {
	case "token":
		return resolveTokenFact(attrPath, claims)
	case "cert":
		return resolveCertFact(attrPath, identity)
	case "request":
		return resolveRequestFact(attrPath, req)
	default:
		return nil, fmt.Sprintf("unknown fact source %q", source)
	}
}

func resolveTokenFact(path string, claims *TokenClaims) ([]string, string) {
	if claims == nil {
		return nil, "token claims not available"
	}

	switch key := strings.ToLower(strings.TrimSpace(path)); key {
	case "sub", "subject":
		return []string{claims.Subject}, ""
	case "iss", "issuer":
		return []string{claims.Issuer}, ""
	case "aud", "audience":
		return claims.Audience, ""
	case "jti":
		return []string{claims.JWTID}, ""
	case "scope", "scopes":
		return claims.Scopes, ""
	default:
		segments := strings.Split(key, ".")
		vals := extractClaimValues(claims.RawClaims, segments)
		if len(vals) == 0 {
			return nil, fmt.Sprintf("token claim %q not found", path)
		}
		return vals, ""
	}
}

func resolveCertFact(path string, identity *ClientIdentity) ([]string, string) {
	if identity == nil {
		return nil, "client certificate identity not available"
	}

	switch strings.ToLower(strings.TrimSpace(path)) {
	case "sub", "subject":
		return []string{identity.Subject}, ""
	case "thumbprint":
		return []string{identity.Thumbprint}, ""
	case "serial", "serial_number":
		return []string{identity.SerialNumber}, ""
	case "san":
		return identity.SAN, ""
	default:
		return nil, fmt.Sprintf("unknown cert attribute %q", path)
	}
}

func resolveRequestFact(path string, req PolicyRequest) ([]string, string) {
	switch strings.ToLower(strings.TrimSpace(path)) {
	case "method":
		return []string{strings.ToUpper(strings.TrimSpace(req.Method))}, ""
	case "path":
		return []string{normalizePolicyPath(req.Path)}, ""
	case "time.hour":
		return []string{strconv.Itoa(time.Now().Hour())}, ""
	case "time.minute":
		return []string{strconv.Itoa(time.Now().Minute())}, ""
	case "time.day_of_week", "time.dayofweek", "time.dow":
		return []string{strconv.Itoa(int(time.Now().Weekday()))}, ""
	default:
		return nil, fmt.Sprintf("unknown request attribute %q", path)
	}
}

// compareValues compares actual values against expected value using the given operator.
func compareValues(actual []string, operator string, expected any) (bool, string) {
	if len(actual) == 0 {
		return false, "no actual values to compare"
	}

	op := strings.ToLower(strings.TrimSpace(operator))

	switch op {
	case opExists:
		return true, ""

	case opNotExists:
		return false, "attribute exists but should not"

	case opEq:
		exp := normalizeToString(expected)
		for _, a := range actual {
			if strings.EqualFold(a, exp) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("expected %q, got %v", exp, actual)

	case opNeq:
		exp := normalizeToString(expected)
		for _, a := range actual {
			if strings.EqualFold(a, exp) {
				return false, fmt.Sprintf("value equals %q", exp)
			}
		}
		return true, ""

	case opIn:
		allowed := anyToStringSlice(expected)
		if len(allowed) == 0 {
			return false, "empty allowed values for 'in'"
		}
		for _, a := range actual {
			for _, b := range allowed {
				if strings.EqualFold(a, b) {
					return true, ""
				}
			}
		}
		return false, fmt.Sprintf("%v not in %v", actual, allowed)

	case opContains:
		exp := normalizeToString(expected)
		for _, a := range actual {
			if strings.Contains(strings.ToLower(a), strings.ToLower(exp)) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("%q not found in %v", exp, actual)

	case opMatches:
		exp := normalizeToString(expected)
		re, err := regexp.Compile(exp)
		if err != nil {
			return false, fmt.Sprintf("invalid regex %q: %v", exp, err)
		}
		for _, a := range actual {
			if re.MatchString(a) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("no match for pattern %q in %v", exp, actual)

	case opGt, opGte, opLt, opLte, opBetween:
		return compareNumeric(actual, op, expected)

	default:
		return false, fmt.Sprintf("unknown operator %q", op)
	}
}

func compareNumeric(actual []string, operator string, expected any) (bool, string) {
	expValues := anyToFloatSlice(expected)
	if len(expValues) == 0 {
		return false, "empty expected numeric values"
	}

	for _, a := range actual {
		actualFloat, err := strconv.ParseFloat(strings.TrimSpace(a), 64)
		if err != nil {
			continue
		}

		switch operator {
		case opGt:
			if actualFloat > expValues[0] {
				return true, ""
			}
		case opGte:
			if actualFloat >= expValues[0] {
				return true, ""
			}
		case opLt:
			if actualFloat < expValues[0] {
				return true, ""
			}
		case opLte:
			if actualFloat <= expValues[0] {
				return true, ""
			}
		case opBetween:
			if len(expValues) >= 2 && actualFloat >= expValues[0] && actualFloat <= expValues[1] {
				return true, ""
			}
		}
	}

	return false, fmt.Sprintf("numeric condition %s %v not met by %v", operator, expValues, actual)
}

func anyToFloatSlice(value any) []float64 {
	switch v := value.(type) {
	case float64:
		return []float64{v}
	case int:
		return []float64{float64(v)}
	case int64:
		return []float64{float64(v)}
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return nil
		}
		return []float64{f}
	case []any:
		out := make([]float64, 0, len(v))
		for _, item := range v {
			if f, err := toFloat64(item); err == nil {
				out = append(out, f)
			}
		}
		return out
	case []int:
		out := make([]float64, 0, len(v))
		for _, item := range v {
			out = append(out, float64(item))
		}
		return out
	default:
		return nil
	}
}

func toFloat64(v any) (float64, error) {
	switch val := v.(type) {
	case float64:
		return val, nil
	case int:
		return float64(val), nil
	case int64:
		return float64(val), nil
	case string:
		return strconv.ParseFloat(strings.TrimSpace(val), 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}
