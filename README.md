# Anti-DDoS & Web Security Firewall (PHP 8.2+)

Lightweight firewall that mitigates Layer‑7 DDoS floods, bad‑bot traffic and common web‑intrusion patterns — perfect for shared hosting.

**Author:** [ishayanabad](https://github.com/ishayanabad) • **License:** MIT

---

## Quick Integration

### Option A – Global (recommended)

**.htaccess**

```apacheconf
php_value auto_prepend_file "/absolute/path/src/AntiDDoS.php"
```

### Option B – Per Script

```php
require_once __DIR__ . '/src/AntiDDoS.php';
AntiDDoS\Firewall::init();   // add overrides if needed
```

That’s all—every request now passes through the firewall.

---

## Toggleable Features (defaults)

| Key                       | Default | Purpose                                 |
|---------------------------|---------|-----------------------------------------|
| `rate_limit.enabled`      | ✓       | Burst + sliding‑window IP throttling    |
| `js_challenge.enabled`    | ✓       | 3‑second cookie test for headless bots  |
| `captcha.enabled`         | ✗       | Math CAPTCHA after repeated offences    |
| `bad_bot.enabled`         | ✓       | UA / referrer regex blacklist           |
| `payload_filter.enabled`  | ✓       | Basic SQLi / XSS pattern scan           |
| `geo_block.enabled`       | ✗       | ISO whitelist / blacklist (GeoLite2)    |

---

## Requirements

Works out‑of‑the‑box. Optional extensions for better performance:

* **APCu** – in‑RAM counters (auto‑detected)  
* **Redis** – shared counters across servers (`storage.type = redis`)

---

For advanced configuration, see the Wiki.
