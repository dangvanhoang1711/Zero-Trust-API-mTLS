package cache

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type redisReplayBackend struct {
	addr       string
	username   string
	password   string
	dbIndex    int
	keyPrefix  string
	timeout    time.Duration
}

func newRedisReplayBackend(rawURL, keyPrefix string) (replayCacheBackend, error) {
	cfg, err := parseRedisConfig(rawURL, keyPrefix)
	if err != nil {
		return nil, err
	}

	return &redisReplayBackend{
		addr:      cfg.addr,
		username:  cfg.username,
		password:  cfg.password,
		dbIndex:   cfg.dbIndex,
		keyPrefix: cfg.keyPrefix,
		timeout:   cfg.timeout,
	}, nil
}

type redisReplayConfig struct {
	addr      string
	username  string
	password  string
	dbIndex   int
	keyPrefix string
	timeout   time.Duration
}

func parseRedisConfig(rawURL, keyPrefix string) (*redisReplayConfig, error) {
	normalized := strings.TrimSpace(rawURL)
	if normalized == "" {
		return nil, fmt.Errorf("missing redis URL")
	}

	if !strings.Contains(normalized, "://") {
		normalized = "redis://" + normalized
	}

	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid redis URL: %w", err)
	}

	if parsed.Scheme != "redis" {
		return nil, fmt.Errorf("unsupported redis scheme: %s", parsed.Scheme)
	}

	addr := strings.TrimSpace(parsed.Host)
	if addr == "" {
		return nil, fmt.Errorf("missing redis host in URL: %s", rawURL)
	}
	if !strings.Contains(addr, ":") {
		addr = addr + ":6379"
	}

	dbIndex := 0
	if parsed.Path != "" && parsed.Path != "/" {
		dbPath := strings.TrimPrefix(parsed.Path, "/")
		if strings.TrimSpace(dbPath) != "" {
			parsedIndex, parseErr := strconv.Atoi(dbPath)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid redis DB index %q: %w", dbPath, parseErr)
			}
			if parsedIndex < 0 {
				return nil, fmt.Errorf("invalid redis DB index %q", dbPath)
			}
			dbIndex = parsedIndex
		}
	}

	username := ""
	password := ""
	if parsed.User != nil {
		username = strings.TrimSpace(parsed.User.Username())
		password, _ = parsed.User.Password()
	}

	prefix := strings.TrimSpace(keyPrefix)
	if prefix == "" {
		prefix = defaultRedisKeyPrefix
	}

	timeout := 2 * time.Second
	if parsedQueryTimeout := strings.TrimSpace(parsed.Query().Get("timeout")); parsedQueryTimeout != "" {
		if parsedTimeout, parseErr := time.ParseDuration(parsedQueryTimeout); parseErr == nil && parsedTimeout > 0 {
			timeout = parsedTimeout
		}
	}

	return &redisReplayConfig{
		addr:      addr,
		username:  username,
		password:  password,
		dbIndex:   dbIndex,
		keyPrefix: prefix,
		timeout:   timeout,
	}, nil
}

func (b *redisReplayBackend) markIfNew(ctx context.Context, jti string, ttl time.Duration, maxEntries int) (bool, error) {
	if ttl <= 0 {
		ttl = defaultReplayTTL
	}

	if maxEntries <= 0 {
		maxEntries = defaultReplayMaxEntries
	}

	jtiKey := b.jtiKey(jti)
	indexKey := b.indexKey()
	commandTTL := strconv.FormatInt(ttl.Milliseconds(), 10)
	setResp, err := b.run(ctx, "SET", jtiKey, "1", "NX", "PX", commandTTL)
	if err != nil {
		return false, err
	}

	if setResp.isNil {
		return false, nil
	}
	if setResp.typ != '+' || !strings.EqualFold(setResp.value, "OK") {
		return false, fmt.Errorf("redis set response unexpected: %q", setResp.value)
	}

	_, _ = b.run(ctx, "ZADD", indexKey, strconv.FormatInt(time.Now().UnixNano(), 10), jti)
	if maxEntries <= 0 {
		return true, nil
	}

	countResp, err := b.run(ctx, "ZCARD", indexKey)
	if err != nil {
		return true, nil
	}
	if countResp.typ != ':' {
		return true, nil
	}

	excess := int(countResp.valueInt) - maxEntries
	if excess <= 0 {
		return true, nil
	}

	rangeEnd := strconv.Itoa(excess - 1)
	victimsResp, err := b.run(ctx, "ZRANGE", indexKey, "0", rangeEnd)
	if err != nil || victimsResp.typ != '*' {
		return true, nil
	}

	for _, victim := range victimsResp.values {
		if strings.TrimSpace(victim) == "" {
			continue
		}
		_, _ = b.run(ctx, "DEL", b.jtiKey(victim))
		_, _ = b.run(ctx, "ZREM", indexKey, victim)
	}

	return true, nil
}

func (b *redisReplayBackend) indexKey() string {
	return b.keyPrefix + ":index"
}

func (b *redisReplayBackend) jtiKey(jti string) string {
	return b.keyPrefix + ":jti:" + jti
}

type redisReply struct {
	typ     byte
	value   string
	valueInt int64
	values  []string
	isNil   bool
}

func (b *redisReplayBackend) run(ctx context.Context, args ...string) (redisReply, error) {
	if len(args) == 0 {
		return redisReply{}, fmt.Errorf("redis command is empty")
	}

	deadline := time.Now().Add(b.timeout)
	if ctx != nil {
		if d, ok := ctx.Deadline(); ok {
			deadline = d
		}
	}

	conn, err := net.DialTimeout("tcp", b.addr, b.timeout)
	if err != nil {
		return redisReply{}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(deadline)

	rw := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	if b.password != "" {
		authArgs := []string{"AUTH"}
		if strings.TrimSpace(b.username) != "" && strings.TrimSpace(b.username) != "default" {
			authArgs = append(authArgs, strings.TrimSpace(b.username), b.password)
		} else {
			authArgs = append(authArgs, b.password)
		}

		if authResp, err := b.execCommand(w, rw, authArgs...); err != nil {
			return redisReply{}, err
		} else if authResp.typ == '-' {
			return redisReply{}, fmt.Errorf("redis auth error: %s", authResp.value)
		}
	}

	if b.dbIndex > 0 {
		if resp, err := b.execCommand(w, rw, "SELECT", strconv.Itoa(b.dbIndex)); err != nil {
			return redisReply{}, err
		} else if resp.typ != '+' || !strings.EqualFold(resp.value, "OK") {
			return redisReply{}, fmt.Errorf("redis select error: %s", resp.value)
		}
	}

	return b.execCommand(w, rw, args...)
}

func (b *redisReplayBackend) execCommand(w *bufio.Writer, rw *bufio.Reader, args ...string) (redisReply, error) {
	if len(args) == 0 {
		return redisReply{}, fmt.Errorf("redis command is empty")
	}

	if err := writeArrayCommand(w, args); err != nil {
		return redisReply{}, err
	}

	if err := w.Flush(); err != nil {
		return redisReply{}, err
	}

	return readReply(rw)
}

func writeArrayCommand(w *bufio.Writer, args []string) error {
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(args)); err != nil {
		return err
	}

	for _, arg := range args {
		normalized := strings.TrimSpace(arg)
		if _, err := fmt.Fprintf(w, "$%d\r\n%s\r\n", len(normalized), normalized); err != nil {
			return err
		}
	}

	return nil
}

func readReply(r *bufio.Reader) (redisReply, error) {
	first, err := r.ReadByte()
	if err != nil {
		return redisReply{}, err
	}

	line, err := r.ReadString('\n')
	if err != nil {
		return redisReply{}, err
	}
	payload := strings.TrimSuffix(strings.TrimSuffix(line, "\r\n"), "\n")

	switch first {
	case '+':
		return redisReply{typ: '+', value: payload}, nil
	case '-':
		return redisReply{typ: '-', value: payload}, fmt.Errorf("redis error: %s", payload)
	case ':':
		num, err := strconv.ParseInt(payload, 10, 64)
		if err != nil {
			return redisReply{}, fmt.Errorf("invalid redis integer: %s", payload)
		}
		return redisReply{typ: ':', valueInt: num}, nil
	case '$':
		size, err := strconv.Atoi(payload)
		if err != nil {
			return redisReply{}, fmt.Errorf("invalid redis bulk size: %s", payload)
		}
		if size < 0 {
			return redisReply{typ: '$', isNil: true}, nil
		}
		buffer := make([]byte, size)
		if _, err := io.ReadFull(r, buffer); err != nil {
			return redisReply{}, err
		}
		if _, err := r.ReadString('\n'); err != nil {
			return redisReply{}, err
		}
		return redisReply{typ: '$', value: string(buffer)}, nil
	case '*':
		count, err := strconv.Atoi(payload)
		if err != nil {
			return redisReply{}, fmt.Errorf("invalid redis array size: %s", payload)
		}
		if count < 0 {
			return redisReply{typ: '*', isNil: true}, nil
		}
		items := make([]string, 0, count)
	for i := 0; i < count; i++ {
		item, err := readReply(r)
		if err != nil {
			return redisReply{}, err
		}
			if item.typ == '$' {
				if item.isNil {
					items = append(items, "")
					continue
				}
				items = append(items, item.value)
				continue
			}
			if item.typ == '+' || item.typ == ':' {
				items = append(items, item.value)
				continue
			}
			if item.typ == '-' {
				return redisReply{}, fmt.Errorf("redis array item error: %s", item.value)
			}
			items = append(items, "")
		}
		return redisReply{typ: '*', values: items}, nil
	default:
		return redisReply{}, fmt.Errorf("unsupported redis response type: %q", first)
	}
}
