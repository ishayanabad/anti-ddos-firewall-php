<?php
/**
 * Anti‑DDoS & Web Security Firewall
 * Lightweight, dependency‑free firewall for PHP 8.2+
 * — Mitigates Layer‑7 HTTP floods, bad‑bot traffic and common web‑intrusion patterns
 *
 * @author  https://github.com/ishayanabad
 * @license MIT
 */

declare(strict_types=1);

namespace AntiDDoS;

use DateTimeImmutable;
use Exception;

final class Firewall
{
    /* ---------------------------------------------------------------------
     |  Public API
     |--------------------------------------------------------------------- */

    /**
     * Initialise the firewall. Call once, as early as possible.
     *
     * @param array $overrides optional run‑time configuration overrides
     */
    public static function init(array $overrides = []): void
    {
        self::$cfg = array_replace_recursive(self::$cfg, $overrides);
        (new self)->handleRequest();
    }

    /* ---------------------------------------------------------------------
     |  Configuration – toggles are true/false; every module can be disabled
     |--------------------------------------------------------------------- */

    private static array $cfg = [
        // storage – auto⇨apcu⇨redis⇨filesystem
        'storage' => [
            'type'   => 'auto',      // auto|apcu|redis|fs
            'prefix' => 'antiddos_',
            // redis conn
            'redis'  => ['host' => '127.0.0.1', 'port' => 6379, 'auth' => null, 'db' => 0],
        ],

        // primary rate‑limit (hard ban)
        'rate_limit' => [
            'enabled'       => true,
            'max_requests'  => 30,      // per window seconds
            'window'        => 10,      // seconds
            'block_seconds' => 900,     // ban duration (15 min)
        ],

        // JS challenge (soft limit before hard ban)
        'js_challenge' => [
            'enabled'       => true,
            'threshold'     => 20,      // requests within window before showing challenge
            'cookie_name'   => 'ddos_token',
            'cookie_ttl'    => 3600,
            'delay'         => 3,       // seconds of enforced delay
        ],

        // simple math CAPTCHA fallback
        'captcha' => [
            'enabled'   => false,
            'threshold' => 3,           // failed challenges before captcha appears
        ],

        // user‑agent / referrer blacklist
        'bad_bot' => [
            'enabled' => true,
            'patterns'=> [
                '/curl/i', '/wget/i', '/sqlmap/i', '/bot|spider|crawler/i',
            ],
        ],

        // basic GET/POST payload scan (SQLi/XSS signature)
        'payload_filter' => [
            'enabled'  => true,
            'patterns' => [
                '/(union\s+select|sleep\s*\(|benchmark\s*\()/i',
                '/(<script|javascript:|onerror=)/i',
            ],
        ],

        // geo‑blocking
        'geo_block' => [
            'enabled'   => false,
            'mode'      => 'white',   // white|black
            'countries' => ['US','RU','CN'],
            // path to GeoLite2‑Country.mmdb (MaxMind)
            'db_path'   => '/usr/share/GeoIP/GeoLite2-Country.mmdb',
        ],

        // logging
        'log' => [
            'enabled'  => false,
            'file'     => '/var/log/antiddos.log',
        ],
    ];

    /* ---------------------------------------------------------------------
     |  Instance properties
     |--------------------------------------------------------------------- */

    private string $ip;
    private Storage $store;

    private function __construct()
    {
        $this->ip    = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $this->store = $this->bootStorage();
    }

    /* ---------------------------------------------------------------------
     |  Main Request Handler
     |--------------------------------------------------------------------- */

    private function handleRequest(): void
    {
        header('X-Firewall: AntiDDoS v1.0');

        // 1) Bad‑Bot detection
        if (self::$cfg['bad_bot']['enabled'] && $this->isBadBot()) {
            $this->block(403, 'Bad bot detected');
        }

        // 2) Payload filter
        if (self::$cfg['payload_filter']['enabled'] && $this->hasMaliciousPayload()) {
            $this->block(403, 'Malicious payload');
        }

        // 3) Geo‑blocking
        if (self::$cfg['geo_block']['enabled'] && !$this->geoAllowed()) {
            $this->block(403, 'Geo‑blocked');
        }

        // 4) Rate‑Limit check
        if (self::$cfg['rate_limit']['enabled']) {
            $this->enforceRateLimit();
        }
    }

    /* ---------------------------------------------------------------------
     |  Module Implementations
     |--------------------------------------------------------------------- */

    private function enforceRateLimit(): void
    {
        $window       = self::$cfg['rate_limit']['window'];
        $max          = self::$cfg['rate_limit']['max_requests'];
        $key          = 'rl:' . $this->ip;
        $count        = (int)$this->store->incr($key, $window);

        // JS challenge soft threshold
        if (self::$cfg['js_challenge']['enabled'] && $count > self::$cfg['js_challenge']['threshold']) {
            if (!$this->hasValidJsCookie()) {
                $this->renderJsChallenge();
            }
        }

        // Hard ban
        if ($count > $max) {
            $this->store->set('ban:' . $this->ip, 1, self::$cfg['rate_limit']['block_seconds']);
            $this->block(503, 'Rate limit exceeded');
        }

        // If IP already banned
        if ($this->store->has('ban:' . $this->ip)) {
            $this->block(503, 'Banned');
        }
    }

    private function hasValidJsCookie(): bool
    {
        $name = self::$cfg['js_challenge']['cookie_name'];
        if (!isset($_COOKIE[$name])) {
            return false;
        }
        // simple HMAC: token = SHA1(ip + secret)
        $expected = sha1($this->ip . PHP_VERSION);
        return hash_equals($expected, $_COOKIE[$name]);
    }

    private function renderJsChallenge(): void
    {
        $delay   = (int)self::$cfg['js_challenge']['delay'];
        $name    = self::$cfg['js_challenge']['cookie_name'];
        $token   = sha1($this->ip . PHP_VERSION);
        $ttl     = self::$cfg['js_challenge']['cookie_ttl'];

        http_response_code(503);
        header('Retry-After: ' . $delay);
        echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Just a moment…</title>';
        echo "<script>setTimeout(function(){document.cookie='{$name}={$token};max-age={$ttl};path=/';location.reload();}," . ($delay * 1000) . ');</script>';
        echo '</head><body><h3 style="text-align:center;margin-top:20vh">Checking your browser before accessing…</h3></body></html>';
        exit;
    }

    private function isBadBot(): bool
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        foreach (self::$cfg['bad_bot']['patterns'] as $pattern) {
            if (preg_match($pattern, $ua)) {
                return true;
            }
        }
        $ref = $_SERVER['HTTP_REFERER'] ?? '';
        if ($ref && preg_match('/semalt|buttons-for-website|crawler/i', $ref)) {
            return true;
        }
        return false;
    }

    private function hasMaliciousPayload(): bool
    {
        $data = array_merge($_GET, $_POST);
        $flat = urldecode(http_build_query($data));
        foreach (self::$cfg['payload_filter']['patterns'] as $p) {
            if (preg_match($p, $flat)) {
                return true;
            }
        }
        return false;
    }

    private function geoAllowed(): bool
    {
        if (!extension_loaded('maxminddb')) {
            return true; // no DB available; skip
        }
        $db     = self::$cfg['geo_block']['db_path'];
        $reader = new \MaxMind\Db\Reader($db);
        try {
            $rec = $reader->get($this->ip);
            $iso = $rec['country']['iso_code'] ?? 'ZZ';
        } catch (Exception $e) {
            return true;
        } finally {
            $reader->close();
        }
        $list = self::$cfg['geo_block']['countries'];
        $mode = self::$cfg['geo_block']['mode'];
        return $mode === 'white' ? in_array($iso, $list, true) : !in_array($iso, $list, true);
    }

    private function block(int $code, string $msg): void
    {
        http_response_code($code);
        header('Content-Type: text/plain; charset=utf-8');
        echo $msg;
        if (self::$cfg['log']['enabled']) {
            error_log(sprintf('[%s] %s – %s', (new DateTimeImmutable())->format(DateTimeImmutable::ATOM), $this->ip, $msg), 3, self::$cfg['log']['file']);
        }
        exit;
    }

    /* ---------------------------------------------------------------------
     |  Storage Abstraction (APCu → Redis → Filesystem)
     |--------------------------------------------------------------------- */

    private function bootStorage(): Storage
    {
        $type = self::$cfg['storage']['type'];
        if ($type === 'auto') {
            if (extension_loaded('apcu')) $type = 'apcu';
            elseif (extension_loaded('redis')) $type = 'redis';
            else $type = 'fs';
        }
        return match ($type) {
            'apcu'  => new Storage\Apcu(self::$cfg['storage']['prefix']),
            'redis' => new Storage\Redis(self::$cfg['storage']['prefix'], self::$cfg['storage']['redis']),
            default => new Storage\Filesystem(sys_get_temp_dir(), self::$cfg['storage']['prefix']),
        };
    }
}

/* -------------------------------------------------------------------------
 |  Storage drivers namespace AntiDDoS\Storage
 |----------------------------------------------------------------------- */

namespace AntiDDoS\Storage;

interface Storage
{
    /** Increment a counter and return new value (window TTL resets each call). */
    public function incr(string $key, int $ttl): int;
    /** Set arbitrary key for ttl seconds. */
    public function set(string $key, mixed $value, int $ttl): void;
    /** Does key exist? */
    public function has(string $key): bool;
}

final class Apcu implements Storage
{
    public function __construct(private string $prefix) {}

    public function incr(string $key, int $ttl): int
    {
        $k = $this->p($key);
        if (!apcu_exists($k)) apcu_store($k, 0, $ttl);
        return apcu_inc($k);
    }
    public function set(string $key, mixed $value, int $ttl): void { apcu_store($this->p($key), $value, $ttl); }
    public function has(string $key): bool { return apcu_exists($this->p($key)); }
    private function p(string $k): string { return $this->prefix . $k; }
}

final class Redis implements Storage
{
    private \Redis $r;
    public function __construct(private string $prefix, array $cfg)
    {
        $this->r = new \Redis();
        $this->r->connect($cfg['host'], $cfg['port']);
        if ($cfg['auth']) $this->r->auth($cfg['auth']);
        if ($cfg['db'])   $this->r->select($cfg['db']);
    }
    public function incr(string $key, int $ttl): int
    {
        $k = $this->p($key);
        $val = $this->r->incr($k);
        if ($val === 1) $this->r->expire($k, $ttl);
        return $val;
    }
    public function set(string $key, mixed $value, int $ttl): void { $this->r->setex($this->p($key), $ttl, serialize($value)); }
    public function has(string $key): bool { return $this->r->exists($this->p($key)) > 0; }
    private function p(string $k): string { return $this->prefix . $k; }
}

final class Filesystem implements Storage
{
    public function __construct(private string $dir, private string $prefix) {}
    private function path(string $key): string { return $this->dir . '/' . $this->prefix . md5($key); }
    public function incr(string $key, int $ttl): int
    {
        $file = $this->path($key);
        $data = 0;
        if (file_exists($file)) {
            [$exp, $cnt] = explode(':', file_get_contents($file));
            if ((int)$exp > time()) $data = (int)$cnt;
        }
        $data++;
        file_put_contents($file, (time() + $ttl) . ':' . $data, LOCK_EX);
        return $data;
    }
    public function set(string $key, mixed $value, int $ttl): void { file_put_contents($this->path($key), (time()+$ttl) . ':1', LOCK_EX); }
    public function has(string $key): bool
    {
        $file = $this->path($key);
        if (!file_exists($file)) return false;
        [$exp] = explode(':', file_get_contents($file));
        if ((int)$exp < time()) { @unlink($file); return false; }
        return true;
    }
}