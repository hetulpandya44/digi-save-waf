"""
Digi Save WAF — Detection Engine Orchestrator

Supports three detection modes:
  - strict:   All modules active, aggressive matching (may have higher false positives)
  - balance:  Recommended default, tuned for low false positives with high detection
  - disabled: Module is turned off
"""

import re
import urllib.parse
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from detection import sqli, xss, rce, path_traversal, ssrf, xxe, ssti, scanner, sensitive, crlf, ldap, xpath

logger = logging.getLogger("waf_engine.detection")

# All available detection modules
ALL_MODULES = [
    sqli, xss, rce, path_traversal, ssrf, xxe, ssti,
    scanner, sensitive, crlf, ldap, xpath,
]

# Pre-compile all regex patterns for performance
_COMPILED_PATTERNS: Dict[str, List[re.Pattern]] = {}


def _compile_module_patterns(module) -> List[re.Pattern]:
    """Compile and cache all regex patterns for a module."""
    key = module.MODULE_INFO["key"]
    if key not in _COMPILED_PATTERNS:
        compiled = []
        for p in module.PATTERNS:
            try:
                compiled.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                logger.warning(f"Invalid regex in module {key}: {p} — {e}")
        _COMPILED_PATTERNS[key] = compiled
    return _COMPILED_PATTERNS[key]


# Initialize all patterns at import time
for _mod in ALL_MODULES:
    _compile_module_patterns(_mod)


@dataclass
class DetectionResult:
    """Result of running the detection engine on a request."""
    is_attack: bool = False
    module_key: str = ""
    module_name: str = ""
    attack_type: int = 0
    risk_level: int = 0        # 0=none, 1=low, 2=medium, 3=high
    rule_id: str = ""
    matched_pattern: str = ""
    matched_payload: str = ""
    action: int = 0            # 0=allow, 1=deny


class DetectionEngine:
    """
    Main WAF detection engine. Runs HTTP requests through all enabled detection
    modules and returns a DetectionResult.

    Module modes (per-module configuration from DB):
      - 'strict':   Use all patterns, aggressive matching
      - 'default':  Use all patterns, standard matching
      - 'disabled': Skip this module entirely
    """

    def __init__(self, module_configs: Optional[Dict[str, dict]] = None):
        """
        Args:
            module_configs: dict keyed by module key, e.g.
                {"sqli": {"mode": "default", "high_risk_action": "deny"}, ...}
        """
        self.module_configs = module_configs or {}

    def _get_mode(self, module_key: str) -> str:
        cfg = self.module_configs.get(module_key, {})
        return cfg.get("mode", "default")

    def _get_action(self, module_key: str, risk: str = "high") -> str:
        cfg = self.module_configs.get(module_key, {})
        return cfg.get(f"{risk}_risk_action", "deny")

    def _decode_layers(self, value: str) -> List[str]:
        """Apply multiple decoding layers to catch simple encoding-based evasion."""
        variants = [value]
        # URL decode
        try:
            decoded = urllib.parse.unquote(value)
            if decoded != value:
                variants.append(decoded)
                # Double URL decode
                double = urllib.parse.unquote(decoded)
                if double != decoded:
                    variants.append(double)
        except Exception:
            pass
        return variants

    def _inspect_value(self, value: str, module, strict: bool = False) -> Optional[Tuple[str, str]]:
        """
        Inspect a single value against a module's compiled patterns.
        Returns (matched_pattern_str, matched_payload) or None.
        """
        patterns = _compile_module_patterns(module)
        variants = self._decode_layers(value)

        for variant in variants:
            for i, compiled_pat in enumerate(patterns):
                m = compiled_pat.search(variant)
                if m:
                    payload = variant[max(0, m.start() - 50):m.end() + 50]
                    return module.PATTERNS[i], payload[:500]
        return None

    def detect(self, request_data: Dict[str, Any], db_rules: Optional[List[dict]] = None) -> DetectionResult:
        """
        Run the full detection pipeline on a request.

        Args:
            request_data: dict with keys: url, path, query, method, headers (dict), body (str), user_agent
            db_rules:     optional list of custom policy rules from the database

        Returns:
            DetectionResult
        """
        url = str(request_data.get("url", ""))
        path = str(request_data.get("path", ""))
        query = str(request_data.get("query", ""))
        body = str(request_data.get("body", ""))
        headers_dict = request_data.get("headers", {})
        headers_str = str(headers_dict)
        user_agent = str(headers_dict.get("user-agent", ""))
        method = str(request_data.get("method", "GET"))

        # --- Stage 1: Large request body check ---
        if len(body) > 1048576:  # >1MB
            return DetectionResult(
                is_attack=True, module_key="mass_package", module_name="Mass Package",
                attack_type=-4, risk_level=1, rule_id="mass_package",
                matched_payload="Request body exceeds 1MB", action=0  # log only, don't block
            )

        # --- Stage 2: Custom policy rules ---
        if db_rules:
            result = self._check_db_rules(request_data, db_rules)
            if result and result.is_attack:
                return result

        # --- Stage 3: Module-based detection ---
        # Define what to inspect for each module type
        module_targets = {
            "sqli":           [url, query, body, headers_str],
            "xss":            [url, query, body, headers_str],
            "rce":            [url, query, body],
            "path_traversal": [url, path, query],
            # Do not inspect the full request URL for SSRF. In local demos the
            # WAF itself legitimately runs on localhost/127.0.0.1, and scanning
            # the absolute request URL creates false positives on clean traffic.
            "ssrf":           [query, body],
            "xxe":            [body, headers_str],
            "ssti":           [url, query, body],
            "scanner":        [user_agent],
            "sensitive":      [path, url],
            "crlf":           [url, query, headers_str],
            "ldap":           [url, query, body],
            "xpath":          [url, query, body],
        }

        for module in ALL_MODULES:
            key = module.MODULE_INFO["key"]
            mode = self._get_mode(key)

            if mode == "disabled":
                continue

            targets = module_targets.get(key, [url, query, body])
            strict = (mode == "strict")

            for target_value in targets:
                if not target_value:
                    continue
                match = self._inspect_value(target_value, module, strict)
                if match:
                    pattern_str, payload = match
                    risk = 3 if strict else 2  # strict → high risk, default → medium
                    action_str = self._get_action(key, "high" if risk >= 3 else "medium")
                    action = 1 if action_str == "deny" else 0

                    return DetectionResult(
                        is_attack=True,
                        module_key=key,
                        module_name=module.MODULE_INFO["name"],
                        attack_type=module.MODULE_INFO["attack_type"],
                        risk_level=risk,
                        rule_id=f"m_{key}",
                        matched_pattern=pattern_str,
                        matched_payload=payload,
                        action=action,
                    )

        # No attack detected
        return DetectionResult(is_attack=False)

    def _check_db_rules(self, request_data: Dict[str, Any], rules: List[dict]) -> Optional[DetectionResult]:
        """Check custom policy rules from the database."""
        url = urllib.parse.unquote(str(request_data.get("url", "")))
        path = str(request_data.get("path", ""))
        body = str(request_data.get("body", ""))
        headers = request_data.get("headers", {})
        user_agent = str(headers.get("user-agent", ""))

        for rule in rules:
            if not rule.get("is_enabled"):
                continue
            pattern = rule.get("pattern", "")
            if not pattern:
                continue

            target = rule.get("target", "url")
            if target == "url":
                value = url
            elif target == "header":
                value = str(headers)
            elif target == "body":
                value = body
            elif target == "user-agent":
                value = user_agent
            elif target == "path":
                value = path
            else:
                value = url

            if not value:
                continue

            matched = False
            try:
                ptype = rule.get("pattern_type", "regex")
                if ptype == "regex":
                    matched = bool(re.search(pattern, value, re.IGNORECASE))
                elif ptype == "exact":
                    matched = (pattern == value)
                elif ptype == "prefix":
                    matched = value.lower().startswith(pattern.lower())
                elif ptype == "suffix":
                    matched = value.lower().endswith(pattern.lower())
                else:  # substring
                    matched = pattern.lower() in value.lower()
            except re.error:
                pass

            if matched:
                action = 1 if rule.get("action", "deny") == "deny" else 0
                risk_map = {"low": 1, "medium": 2, "high": 3, "critical": 3}
                return DetectionResult(
                    is_attack=True,
                    module_key="custom_rule",
                    module_name="Custom Policy Rule",
                    attack_type=-3,
                    risk_level=risk_map.get(rule.get("risk_level", "medium"), 2),
                    rule_id=f"rule_{rule.get('id', 0)}",
                    matched_pattern=pattern,
                    matched_payload=value[:500],
                    action=action,
                )
        return None


def get_all_module_info() -> List[dict]:
    """Return info about all detection modules for the API / frontend."""
    return [mod.MODULE_INFO for mod in ALL_MODULES]
