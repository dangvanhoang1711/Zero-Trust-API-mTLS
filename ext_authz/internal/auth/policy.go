package auth

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

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

	matchedRule := cfg.matchingRule(req.Path, req.Method)
	requiredScopes := make([]string, 0, 8)

	if !applyPolicyRule(defaultAction, cfg.Global, inputClaims, inputIdentity, &decision, &requiredScopes) {
		return decision
	}

	if matchedRule != nil {
		ruleAction := defaultAction
		if strings.TrimSpace(matchedRule.Action) != "" {
			ruleAction = matchedRule.Action
		}
		if !applyPolicyRule(ruleAction, matchedRule, inputClaims, inputIdentity, &decision, &requiredScopes) {
			return decision
		}
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

func applyPolicyRule(action string, rule *PolicyRule, claims *TokenClaims, identity *ClientIdentity, decision *PolicyDecision, requiredScopes *[]string) bool {
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
