from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "discover-identity.py"
SPEC = importlib.util.spec_from_file_location("edgewatch_discover_identity", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Could not load discover-identity.py")
identity_discovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(identity_discovery)


class IdentityMetadataTests(unittest.TestCase):
    def test_microsoft_issuer_extracts_tenant_and_durations(self) -> None:
        tenant = "11111111-2222-3333-4444-555555555555"
        tenant_id, directory_name = identity_discovery.tenant_from_issuer(
            f"https://login.microsoftonline.com/{tenant}/v2.0"
        )
        self.assertEqual(tenant_id, tenant)
        self.assertEqual(directory_name, "")
        self.assertEqual(identity_discovery.human_duration("8h"), "8 hours")
        self.assertEqual(
            identity_discovery.human_duration("1h", recurring=True),
            "Every 1 hour",
        )
        self.assertEqual(
            identity_discovery.human_duration("1h30m"),
            "1 hour 30 minutes",
        )

    def test_legacy_azure_tenant_is_supported_without_secrets(self) -> None:
        values = {
            "provider": "azure",
            "azure_tenant": "11111111-2222-3333-4444-555555555555",
            "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        }
        identity = identity_discovery.identity_section(values)
        self.assertEqual(
            identity["tenant_id"],
            "11111111-2222-3333-4444-555555555555",
        )
        self.assertEqual(identity["provider"], "Microsoft Entra ID")

    def test_inline_systemd_environment_uses_only_allowlisted_keys(self) -> None:
        values = identity_discovery.parse_safe_environment_lines(
            'Environment="OAUTH2_PROXY_CLIENT_ID=safe-client" '
            '"OAUTH2_PROXY_COOKIE_EXPIRE=8h" '
            '"OAUTH2_PROXY_CLIENT_SECRET=must-not-leak"'
        )
        self.assertEqual(values["client_id"], "safe-client")
        self.assertEqual(values["cookie_expire"], "8h")
        self.assertNotIn("client_secret", values)

    def test_config_parser_only_collects_safe_values(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            oauth_config = Path(folder) / "oauth2-proxy.cfg"
            oauth_config.write_text(
                '''
provider = "oidc"
oidc_issuer_url = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
client_secret = "must-not-leak"
cookie_secret = "must-not-leak-either"
cookie_expire = "8h"
cookie_refresh = "1h"
''',
                encoding="utf-8",
            )
            values = identity_discovery.parse_config_file(oauth_config)
            self.assertEqual(values["provider"], "oidc")
            self.assertEqual(
                values["client_id"],
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            )
            self.assertNotIn("client_secret", values)
            self.assertNotIn("cookie_secret", values)

    def test_migration_fills_blank_sample_fields_without_overwriting_names(self) -> None:
        discovered = {
            "provider": "oidc",
            "oidc_issuer_url": (
                "https://login.microsoftonline.com/"
                "11111111-2222-3333-4444-555555555555/v2.0"
            ),
            "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "cookie_expire": "8h",
            "cookie_refresh": "1h",
        }
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.toml"
            config.write_text(
                '''
[app]
data_dir = "/tmp/edgewatch"
[identity]
provider = "Custom Entra Label"
directory_name = "Example Directory"
tenant_id = ""
application_name = "EdgeWatch Production"
client_id = ""
access_label = "Custom access policy"
session_lifetime = ""
session_refresh = ""
''',
                encoding="utf-8",
            )
            with patch.object(
                identity_discovery,
                "discover",
                return_value=(discovered, ["fixture oauth2-proxy config"]),
            ):
                changed, _ = identity_discovery.migrate(config)
            self.assertTrue(changed)
            rendered = config.read_text(encoding="utf-8")
            self.assertIn('provider = "Custom Entra Label"', rendered)
            self.assertIn('directory_name = "Example Directory"', rendered)
            self.assertIn('application_name = "EdgeWatch Production"', rendered)
            self.assertIn('access_label = "Custom access policy"', rendered)
            self.assertIn(
                'tenant_id = "11111111-2222-3333-4444-555555555555"',
                rendered,
            )
            self.assertIn(
                'client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"',
                rendered,
            )
            self.assertIn('session_lifetime = "8 hours"', rendered)
            self.assertIn('session_refresh = "Every 1 hour"', rendered)

    def test_migration_appends_safe_identity_and_preserves_existing_section(self) -> None:
        discovered = {
            "provider": "oidc",
            "oidc_issuer_url": (
                "https://login.microsoftonline.com/"
                "11111111-2222-3333-4444-555555555555/v2.0"
            ),
            "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "cookie_expire": "8h",
            "cookie_refresh": "1h",
        }
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.toml"
            config.write_text(
                '[app]\ndata_dir = "/tmp/edgewatch"\n',
                encoding="utf-8",
            )
            with patch.object(
                identity_discovery,
                "discover",
                return_value=(discovered, ["fixture oauth2-proxy config"]),
            ):
                changed, sources = identity_discovery.migrate(config)
                changed_again, sources_again = identity_discovery.migrate(config)
            self.assertTrue(changed)
            self.assertEqual(sources, ["fixture oauth2-proxy config"])
            rendered = config.read_text(encoding="utf-8")
            self.assertIn("[identity]", rendered)
            self.assertIn(
                'tenant_id = "11111111-2222-3333-4444-555555555555"',
                rendered,
            )
            self.assertIn(
                'client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"',
                rendered,
            )
            self.assertIn('session_lifetime = "8 hours"', rendered)
            self.assertIn('session_refresh = "Every 1 hour"', rendered)
            self.assertNotIn("client_secret", rendered)
            self.assertNotIn("cookie_secret", rendered)

            self.assertFalse(changed_again)
            self.assertEqual(sources_again, [])
            self.assertEqual(rendered, config.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
