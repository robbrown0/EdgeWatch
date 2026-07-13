# EdgeWatch configuration reference

Runtime configuration is stored outside immutable releases:

```text
/etc/edgewatch/config.toml
/etc/edgewatch/site.toml
/etc/edgewatch/secrets.toml
```

`config.toml` contains general application settings. `site.toml` is an optional private overlay for environment-specific domains, addresses, aliases, topology, and Caddy log sources. `secrets.toml` contains credentials and remains root-only.

The loader merges dictionaries from `site.toml` over `config.toml`. Repeated tables and lists in `site.toml` replace the corresponding values from `config.toml`. If `app.site_config_path` is omitted, EdgeWatch looks for `site.toml` beside `config.toml`.

## File permissions

```text
root:edgewatch 0640 /etc/edgewatch/config.toml
root:edgewatch 0640 /etc/edgewatch/site.toml
root:root      0600 /etc/edgewatch/secrets.toml
```

Verify:

```bash
sudo stat -c '%U:%G %a %n' \
  /etc/edgewatch/config.toml \
  /etc/edgewatch/site.toml \
  /etc/edgewatch/secrets.toml
sudo -u edgewatch test ! -r /etc/edgewatch/secrets.toml && echo protected
```

## App settings

`[app]` controls sampling, retention, timezone, storage paths, and the private overlay path.

```toml
[app]
sample_interval_seconds = 5
history_interval_seconds = 15
security_interval_seconds = 30
maintenance_interval_seconds = 900
retention_days = 14
history_points_max = 2880
timezone = "UTC"
data_dir = "/var/lib/edgewatch"
runtime_dir = "/run/edgewatch"
secrets_path = "/etc/edgewatch/secrets.toml"
site_config_path = "/etc/edgewatch/site.toml"
```

## Web settings

The web service must remain loopback-only. Put the public hostname in the private site overlay.

```toml
[web]
bind_host = "127.0.0.1"
bind_port = 8765
allowed_hosts = ["monitor.example.com", "127.0.0.1", "localhost"]
```

## Identity display metadata

`[identity]` contains safe values shown in the signed-in account drawer. These are identifiers and display settings, not credentials.

```toml
[identity]
provider = "Microsoft Entra ID"
directory_name = "Example Directory"
tenant_id = "11111111-2222-3333-4444-555555555555"
application_name = "EdgeWatch"
client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
access_label = "Assigned enterprise application user"
session_lifetime = "8 hours"
session_refresh = "Every 1 hour"
```

The installer fills blank values from oauth2-proxy when possible. Never place client secrets, cookie secrets, tokens, or cookies in this section.

## Monitoring and security

`[monitoring]` defines the public interface, transfer reference, expected systemd services, WireGuard interfaces, flow retention, and expected public DNS names.

`[security]` defines expected public listeners and warning thresholds. Listener lists are posture expectations, not firewall rules.

```toml
[security]
allowed_public_tcp_ports = [22, 80, 443]
allowed_public_udp_ports = [443, 51820]
```

## Environment-specific private overlay

Start from `deploy/site.toml.example`. Use documentation addresses and domains only in the public repository. Put real values only in `/etc/edgewatch/site.toml`.

### Custom service port labels

```toml
[service_ports]
"5055" = "Request service"
```

Built-in generic labels cover SSH, DNS, HTTP, HTTPS, WireGuard, and Plex. Old or environment-specific ports should not be added to application source.

### Connection and WireGuard aliases

```toml
[[peer_aliases]]
name = "Media Node A"
allowed_ip = "10.200.0.2/32"
scope = "private"

[[peer_aliases]]
name = "Known Remote Service"
allowed_ip = "198.51.100.54/32"
scope = "public"
```

Supported scopes are `any`, `public`, `private`, and `wireguard`. A public alias is applied only when a matching connection is actually observed. It does not create a permanent map or topology entry.

### Plex servers and URL checks

```toml
[[plex_servers]]
name = "Media Node A"
url = "https://10.200.0.2:32400"
timeout_seconds = 4
tls_verify = false

[[url_checks]]
name = "Media Node A public"
url = "https://media-a.example.com/identity"
timeout_seconds = 4
tls_verify = true
expected_status_min = 200
expected_status_max = 499
certificate_warn_days = 21
```

### Caddy activity sources

Caddy log paths, hostnames, and application labels are configuration, not source-code constants.

```toml
[[caddy_activity_sources]]
name = "Media Node A"
log_path = "/var/log/caddy/media-a-access.log"
hosts = ["media-a.example.com"]
kind = "plex"
label = "Plex request"
```

Supported `kind` values are free-form labels. The frontend recognizes `edgewatch` as an administrative dashboard connection and `plex_notification` as a service connection. A source with `kind = "plex"` receives additional Plex path classification automatically.

### Configured topology services

The topology view reads service nodes from configuration. No media node, request application, address, or hostname is hardcoded in JavaScript.

```toml
[[topology_services]]
name = "Media Node A"
eyebrow = "MEDIA BACKEND"
peer_name = "Media Node A"
check_names = ["Media Node A public", "Media Node A tunnel"]
path = "wireguard"
link_label = "Plex"
```

`path` may be `wireguard` or `edge`. Only configured topology services are rendered. Public connection aliases are never promoted into topology nodes automatically.

## GeoIP, Linode, and notifications

GeoIP database paths belong in `[geoip]`. Linode resource identifiers belong in `[linode]`, while the API token belongs only in `secrets.toml`. Notification behavior belongs in `[notifications]`; the dashboard URL may be placed in the private site overlay.

## Secrets format

Start from `deploy/secrets.toml.example`.

```toml
[plex]
token = "COMMON_PLEX_TOKEN"

[[plex_tokens]]
name = "Optional server-specific name"
token = "OPTIONAL_OVERRIDE"

[ntfy]
url = "https://ntfy.sh/LONG_RANDOM_PRIVATE_TOPIC"
token = ""

[linode]
api_token = "READ_ONLY_TOKEN"
```

## Apply changes

```bash
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh test
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh restart
```
