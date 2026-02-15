[![Build](https://github.com/dkhalife/traefik-country-block/actions/workflows/build.yml/badge.svg)](https://github.com/dkhalife/traefik-country-block/actions/workflows/build.yml) [![codecov](https://codecov.io/gh/dkhalife/traefik-country-block/graph/badge.svg)](https://codecov.io/gh/dkhalife/traefik-country-block)

# Traefik Country Block

**Privacy First, Zero External Calls.**

Traefik Country Block is a [Traefik](https://traefik.io/) middleware plugin that filters HTTP requests based on the client's country of origin or explicit IP/CIDR rules. Every lookup is performed locally using an embedded [IP2Location LITE](https://lite.ip2location.com/) database — no data ever leaves your infrastructure. Decisions are cached in memory for blazing-fast repeat lookups.

## 🎯 Goals and Principles

* **No external API calls** — all geolocation lookups happen locally against an in-memory database
* **Your data stays yours** — client IPs are never sent to third-party services
* **Blazing fast** — IP decisions are cached in memory after first evaluation; CIDR lists are pre-parsed at startup
* **Flexible** — supports allowlist and blocklist modes with per-route configuration
* **Kubernetes-friendly** — private/internal ranges are allowed by default so health checks and pod-to-pod traffic are never disrupted

## 🚀 Getting Started

### 1. Register the plugin

Add the plugin to your Traefik **static configuration**:

```yaml
experimental:
  plugins:
    countryblock:
      moduleName: github.com/dkhalife/traefik-country-block
      version: v0.1.0
```

### 2. Configure the middleware

Add the middleware to your Traefik **dynamic configuration**:

```yaml
http:
  middlewares:
    my-countryblock:
      plugin:
        countryblock:
          mode: blocklist
          databasePath: /etc/traefik/IP2LOCATION-LITE-DB1.BIN
          defaultAction: "403"
          allowPrivateRanges: true
          blockedCountries:
            - CN
            - RU
```

### 3. Attach to a router

```yaml
http:
  routers:
    my-router:
      rule: Host(`example.com`)
      middlewares:
        - my-countryblock
      service: my-service
```

## ⚙️ Configuration Reference

| Field | Type | Default | Description |
|---|---|---|---|
| `mode` | `string` | *(required)* | `"allowlist"` or `"blocklist"`. Mutually exclusive — only one mode's fields may be populated. |
| `databasePath` | `string` | *(required)* | Path to the IP2Location `.BIN` database file. |
| `defaultAction` | `string` | `"403"` | Action when a request is denied: `"403"` (Forbidden), `"404"` (Not Found), or `"close"` (silently close the connection). |
| `allowPrivateRanges` | `bool` | `true` | Automatically allow RFC 1918, loopback, and link-local addresses (IPv4 and IPv6). |
| `internalIPs` | `[]string` | `[]` | Additional CIDRs that are always allowed regardless of mode (e.g., custom pod CIDRs). |
| `allowedCountries` | `[]string` | `[]` | ISO 3166-1 alpha-2 country codes to allow. Only valid when `mode` is `"allowlist"`. |
| `allowedIPs` | `[]string` | `[]` | IP addresses or CIDRs to allow. IPs without `/` are treated as `/32`. Only valid when `mode` is `"allowlist"`. |
| `blockedCountries` | `[]string` | `[]` | ISO 3166-1 alpha-2 country codes to block. Only valid when `mode` is `"blocklist"`. |
| `blockedIPs` | `[]string` | `[]` | IP addresses or CIDRs to block. IPs without `/` are treated as `/32`. Only valid when `mode` is `"blocklist"`. |

## 📝 Examples

### Blocklist Mode

Block traffic from specific countries while allowing everything else:

```yaml
http:
  middlewares:
    block-countries:
      plugin:
        countryblock:
          mode: blocklist
          databasePath: /etc/traefik/IP2LOCATION-LITE-DB1.BIN
          defaultAction: "403"
          allowPrivateRanges: true
          blockedCountries:
            - CN
            - RU
          blockedIPs:
            - 203.0.113.0/24
```

### Allowlist Mode

Only allow traffic from specific countries and IPs — block everything else:

```yaml
http:
  middlewares:
    allow-countries:
      plugin:
        countryblock:
          mode: allowlist
          databasePath: /etc/traefik/IP2LOCATION-LITE-DB1.BIN
          defaultAction: close
          allowPrivateRanges: true
          internalIPs:
            - 100.64.0.0/10
          allowedCountries:
            - US
            - CA
          allowedIPs:
            - 198.51.100.0/24
```

## 🔭 Scoping Rules

The same plugin can be applied at different scopes using standard Traefik configuration:

### Cluster-wide (all requests)

Attach the middleware to an entrypoint in the **static configuration**:

```yaml
entryPoints:
  web:
    address: ":80"
    http:
      middlewares:
        - my-countryblock@file
```

### Per-namespace (Kubernetes)

Create a `Middleware` CRD in the target namespace:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: countryblock
  namespace: my-app
spec:
  plugin:
    countryblock:
      mode: blocklist
      databasePath: /etc/traefik/IP2LOCATION-LITE-DB1.BIN
      blockedCountries:
        - CN
```

Then reference it from `IngressRoute` resources in that namespace.

### Per-host or per-route

Attach the middleware to a specific router:

```yaml
http:
  routers:
    admin-router:
      rule: Host(`admin.example.com`)
      middlewares:
        - strict-countryblock
      service: admin-service
```

Each scope can use a different plugin instance with its own configuration.

## 🤝 Contributing

Contributions are welcome! Feel free to fork the repo and submit pull requests.
If you have ideas but aren't familiar with code, you can also [open issues](https://github.com/dkhalife/traefik-country-block/issues).

## 🔒 License

See the [LICENSE](LICENSE) file for more details.

This product includes IP2Location LITE data available from [https://lite.ip2location.com](https://lite.ip2location.com).
