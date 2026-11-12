"""Contract checks for the dormant EC2 Wazuh push configuration."""
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from wazuh.manager.integrations.validate_push_config import validate_hostname, validate_template


ROOT = Path(__file__).parents[4]
TEMPLATE = ROOT / "wazuh/manager/ossec.b89-integrations.xml.tmpl"
EDGE = ROOT / "infra/aws-poweruser/host/edge.conf.template"
COMPOSE = ROOT / "infra/aws-poweruser/host/compose.b89.yaml"
PREPARE = ROOT / "infra/aws-poweruser/scripts/prepare-wazuh-push-secret.sh"
ACTIVATE = ROOT / "infra/aws-poweruser/scripts/activate-wazuh-push.sh"
DEPLOY = ROOT / "infra/aws-poweruser/scripts/deploy-host.sh"
AWS_INSTALLER = ROOT / "wazuh/aws-events/install-aws-events.sh"


class WazuhPushConfigTests(unittest.TestCase):
    def test_xml_template_renders_single_exact_hmac_route_and_non_secret_marker(self):
        validate_template(TEMPLATE, "soc.example.invalid")
        rendered = TEMPLATE.read_text(encoding="utf-8").replace(
            "${SOC_HOSTNAME}", "soc.example.invalid"
        )
        root = ET.fromstring(rendered)
        integrations = [
            node for node in root.findall("integration")
            if node.findtext("name") == "custom-b89"
        ]
        self.assertEqual(len(integrations), 1)
        integration = integrations[0]
        self.assertEqual(
            integration.findtext("hook_url"),
            "https://soc.example.invalid/api/ingest/wazuh",
        )
        self.assertEqual(integration.findtext("api_key"), "B89_SECRET_FILE_V1")
        self.assertEqual(integration.findtext("level"), "3")
        self.assertEqual(
            {group.strip() for group in integration.findtext("group").split(",")},
            {"b89_provider", "office365"},
        )
        self.assertNotIn("${B89_INGEST_HMAC_KEY}", rendered)
        self.assertNotIn("${B89_INGEST_URL}", rendered)

    def test_hostname_validator_rejects_url_and_xml_injection_characters(self):
        validate_hostname("soc-01.security.example")
        for invalid in (
            "soc.example.invalid/path",
            "soc.example.invalid:443",
            "soc.example.invalid\t",
            'soc.example.invalid"/><evil',
            "soc.example.invalid'><evil>",
            "soc.example.invalid&evil;",
            "soc.example.invalid\\evil",
            "sóc.example.invalid",
        ):
            with self.subTest(hostname=invalid), self.assertRaises(ValueError):
                validate_hostname(invalid)

    def test_edge_exposes_only_exact_post_route_with_bounded_body(self):
        edge = EDGE.read_text(encoding="utf-8")
        match = re.search(
            r"location\s*=\s*/api/ingest/wazuh\s*\{(?P<body>.*?)\n\s*\}",
            edge,
            re.S,
        )
        self.assertIsNotNone(match)
        route = match.group("body")
        self.assertIn("limit_except POST { deny all; }", route)
        self.assertIn("client_max_body_size 64k;", route)
        self.assertIn("proxy_pass http://b89_api;", route)
        self.assertIn('proxy_set_header Authorization "";', route)
        self.assertIn('proxy_set_header Cookie "";', route)
        self.assertIn("proxy_buffering off;", route)
        self.assertIn("limit_req zone=b89_wazuh_push", route)
        self.assertIn("limit_req_zone $binary_remote_addr zone=b89_wazuh_push", edge)
        self.assertIn("location = /health/live", edge)

    def test_manager_uses_private_edge_resolution_and_sync_is_prepare_only(self):
        compose = COMPOSE.read_text(encoding="utf-8")
        manager = compose.split("  wazuh.manager:", 1)[1].split("\n  wazuh.indexer:", 1)[0]
        self.assertIn("${SOC_HOSTNAME}:172.30.89.11", manager)
        prepare = PREPARE.read_text(encoding="utf-8")
        self.assertIn("validate_push_config.py", prepare)
        self.assertIn("B89_WAZUH_PUSH_PREPARE:-", prepare)
        self.assertIn("integration was not enabled", prepare)
        self.assertNotIn("docker compose", prepare)
        self.assertIn("trap rollback EXIT", prepare)
        self.assertIn("manager.old.secret", prepare)
        self.assertIn("api.env.backup", prepare)
        self.assertIn("os.replace(replacement, target)", prepare)
        self.assertNotIn('echo "$value"', prepare)

    def test_provider_and_office365_rulesets_are_scoped_by_integration_filter(self):
        aws_rules = (ROOT / "wazuh/aws-events/rules/b89_aws_rules.xml").read_text(encoding="utf-8")
        m365_rules = (ROOT / "wazuh/office365/rules/b89_office365_rules.xml").read_text(encoding="utf-8")
        self.assertRegex(aws_rules, r'<group name="b89_provider,aws,">')
        self.assertRegex(m365_rules, r'<group name="office365,b89_m365,b89_provider,">')

    def test_deploy_orders_manager_localfile_before_aws_receiver(self):
        deploy = DEPLOY.read_text(encoding="utf-8")
        manager_start = deploy.index('up -d wazuh.indexer wazuh.manager postgres --wait')
        localfile_setup = deploy.index('bash "$SRC/wazuh/aws-events/install-aws-events.sh"')
        receiver_start = deploy.index('up -d --wait aws-events')
        later_services = deploy.index('up -d --force-recreate wazuh.dashboard api edge')
        self.assertLess(manager_start, localfile_setup)
        self.assertLess(localfile_setup, receiver_start)
        self.assertLess(receiver_start, later_services)
        self.assertIn("B89_RESTART=true", deploy)
        compose = (ROOT / "infra/aws-poweruser/host/compose.b89.yaml").read_text(encoding="utf-8")
        self.assertRegex(compose, r"(?m)^  aws-events:")
        installer = AWS_INSTALLER.read_text(encoding="utf-8")
        self.assertIn("wazuh-analysisd", installer)
        self.assertIn("reinicio falló; configuración AWS revertida", installer)
        self.assertIn("hostbak", installer)

    def test_push_activation_is_explicit_and_has_rollback_without_deploy_hook(self):
        activation = ACTIVATE.read_text(encoding="utf-8")
        deploy = DEPLOY.read_text(encoding="utf-8")
        self.assertIn("B89_WAZUH_PUSH_ACTIVATE:-", activation)
        self.assertIn("wazuh-analysisd", activation)
        self.assertIn("wazuh-integratord", activation)
        self.assertIn("trap rollback EXIT", activation)
        self.assertIn("old.manager.ossec.conf", activation)
        self.assertIn("old.host.ossec.conf", activation)
        self.assertIn("manager_changed=1\ndocker exec -u 0", activation)
        self.assertIn('sh -c \'printf %s "$B89_WAZUH_PUSH_SECRET"\'', activation)
        self.assertNotIn(".Config.Env", activation)
        self.assertNotIn("activate-wazuh-push.sh", deploy)


if __name__ == "__main__":
    unittest.main()
