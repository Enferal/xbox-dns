import unittest

import helpers
from egress_ui.firewall import FirewallError, Ufw, parse_rule, parse_status, rule_argv

NUMBERED = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 2] 53                         ALLOW IN    Anywhere
[ 3] 80/tcp                     ALLOW IN    Anywhere
[ 4] 443/tcp                    ALLOW IN    203.0.113.8                # дом
[ 5] 8443/tcp                   ALLOW IN    203.0.113.8                # egress-ui
[ 6] 15000:15099/tcp            ALLOW IN    Anywhere
[ 7] OpenSSH (v6)               ALLOW IN    Anywhere (v6)
[ 8] 53 (v6)                    ALLOW IN    Anywhere (v6)
[ 9] 25/tcp                     DENY IN     Anywhere
"""
VERBOSE = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip
"""


class ParseTest(unittest.TestCase):
    def test_status(self):
        status = parse_status(NUMBERED, VERBOSE)
        self.assertTrue(status["active"])
        self.assertIn("deny (incoming)", status["defaults"])
        rules = status["rules"]
        self.assertEqual(len(rules), 9)
        self.assertEqual((rules[0].port, rules[0].proto), ("22", "tcp"))
        self.assertEqual((rules[1].port, rules[1].proto), ("53", "any"))
        self.assertEqual(rules[3].source, "203.0.113.8")
        self.assertEqual(rules[3].comment, "дом")
        self.assertEqual(rules[5].port, "15000:15099")
        self.assertTrue(rules[7].v6)
        self.assertTrue(rules[7].anywhere)
        self.assertEqual(rules[8].action, "DENY")
        self.assertFalse(parse_status("Status: inactive\n")["active"])

    def test_garbage(self):
        self.assertIsNone(parse_rule("     To   Action   From"))


class ArgvTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(
            rule_argv("allow", "15000-15099", "tcp", "203.0.113.0/24"),
            ["ufw", "allow", "from", "203.0.113.0/24", "to", "any", "port", "15000:15099", "proto", "tcp", "comment", "egress-ui"],
        )
        self.assertEqual(rule_argv("allow", "53", "any", "any", "")[-2:], ["port", "53"])
        self.assertEqual(rule_argv("deny", "25", "tcp", "203.0.113.8/32")[3], "203.0.113.8")

    def test_invalid(self):
        for args in (
            ("drop", "80", "tcp", "any"),
            ("allow", "80", "icmp", "any"),
            ("allow", "", "tcp", "any"),
            ("allow", "70000", "tcp", "any"),
            ("allow", "80;rm", "tcp", "any"),
            ("allow", "1000-2000", "any", "any"),
            ("allow", "80", "tcp", "evil.com"),
        ):
            with self.assertRaises(FirewallError, msg=str(args)):
                rule_argv(*args)
        with self.assertRaises(FirewallError):
            rule_argv("allow", "80", "tcp", "any", "a\nb")


def ufw_with(numbered=NUMBERED):
    runner = helpers.FakeRunner()
    runner.add(["ufw", "status", "numbered"], 0, numbered)
    runner.add(["ufw", "status", "verbose"], 0, VERBOSE)
    return runner, Ufw(runner, ["22", "8443"])


class UfwTest(unittest.TestCase):
    def test_protected(self):
        runner, ufw = ufw_with()
        snapshot = ufw.snapshot()
        protected = {rule["num"]: rule["protected"] for rule in snapshot["rules"]}
        self.assertTrue(protected[1])
        self.assertTrue(protected[5])
        self.assertFalse(protected[3])
        with self.assertRaises(FirewallError):
            ufw.delete(1, "[ 1] OpenSSH                    ALLOW IN    Anywhere")

    def test_delete_checks_text(self):
        runner, ufw = ufw_with()
        with self.assertRaises(FirewallError):
            ufw.delete(3, "[ 3] 81/tcp ALLOW IN Anywhere")
        result = ufw.delete(3, "[ 3] 80/tcp                     ALLOW IN    Anywhere")
        self.assertTrue(result["ok"])
        self.assertEqual(runner.calls[-1], ["ufw", "--force", "delete", "3"])

    def test_plan_all(self):
        runner, ufw = ufw_with()
        plan = ufw.plan("all", "53", "80,443,15000-15099", "")
        self.assertEqual(plan["add"], ["ufw allow from any to any port 443 proto tcp comment egress-ui"])
        self.assertEqual([item["num"] for item in plan["delete"]], [4])

    def test_plan_clients(self):
        runner, ufw = ufw_with()
        plan = ufw.plan("clients", "53", "80,443", "203.0.113.8")
        self.assertIn("ufw allow from 203.0.113.8 to any port 53 proto tcp comment egress-ui", plan["add"])
        self.assertIn("ufw allow from 203.0.113.8 to any port 80 proto tcp comment egress-ui", plan["add"])
        self.assertNotIn("ufw allow from 203.0.113.8 to any port 443 proto tcp comment egress-ui", plan["add"])
        deleted = [item["num"] for item in plan["delete"]]
        self.assertEqual(deleted, sorted(deleted, reverse=True))
        self.assertIn(2, deleted)
        self.assertIn(3, deleted)
        self.assertIn(8, deleted)
        self.assertNotIn(1, deleted)
        self.assertNotIn(4, deleted)
        self.assertNotIn(6, deleted, "15000:15099 не в PROXY_PORTS")
        with self.assertRaises(FirewallError):
            ufw.plan("clients", "53", "80,443", "")
        with self.assertRaises(FirewallError):
            ufw.plan("nobody", "53", "80", "")

    def test_apply_mode_runs_commands(self):
        runner, ufw = ufw_with()
        result = ufw.apply_mode("all", "53", "80,443", "")
        self.assertTrue(result["ok"])
        commands = [" ".join(call) for call in runner.calls if call[:2] != ["ufw", "status"]]
        self.assertEqual(commands[0], "ufw allow from any to any port 443 proto tcp comment egress-ui")
        self.assertIn("ufw --force delete 4", commands)

    def test_enable_opens_ssh_first(self):
        runner, ufw = ufw_with()
        result = ufw.enable(["22", "2222"])
        self.assertTrue(result["ok"])
        self.assertEqual(runner.calls[0], ["ufw", "allow", "OpenSSH"])
        self.assertEqual(runner.calls[1], ["ufw", "allow", "2222/tcp"])
        self.assertEqual(runner.calls[-1], ["ufw", "--force", "enable"])

    def test_missing_ufw(self):
        runner = helpers.FakeRunner()
        runner.add(["ufw"], 127, "", "Нет программы ufw")
        self.assertFalse(Ufw(runner, ["22"]).snapshot()["available"])


if __name__ == "__main__":
    unittest.main()
