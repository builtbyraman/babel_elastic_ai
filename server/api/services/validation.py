"""
Sigma rule validation using pySigma's built-in validator framework.

Runs the rule through pySigma's SigmaValidator with the standard set of
correctness, quality, and consistency checks, returning structured issues.
"""

from __future__ import annotations

import logging
from typing import Any

import yaml

logger = logging.getLogger(__name__)


def validate_rule(rule_yaml: str) -> list[dict[str, str]]:
    """
    Validate a Sigma rule YAML string.

    Returns a list of issue dicts: { type: 'error'|'warning', rule: str, message: str }.
    An empty list means the rule is valid.
    """
    issues: list[dict[str, str]] = []

    # ── Structural / YAML parse check ────────────────────────────────────────
    try:
        data = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as e:
        return [{"type": "error", "rule": "yaml_parse", "message": f"YAML parse error: {e}"}]

    if not isinstance(data, dict):
        return [{"type": "error", "rule": "yaml_structure", "message": "Rule must be a YAML mapping"}]

    # ── Required field presence ───────────────────────────────────────────────
    required = ["title", "status", "logsource", "detection"]
    for field in required:
        if field not in data:
            issues.append({"type": "error", "rule": "required_field", "message": f"Missing required field: '{field}'"})

    # ── pySigma validator ─────────────────────────────────────────────────────
    try:
        from sigma.rule import SigmaRule
        from sigma.collection import SigmaCollection
        from sigma.validators.core.metadata import (
            TitleLengthValidator,
            StatusExistenceValidator,
            StatusUnsupportedValidator,
            LevelExistenceValidator,
            DateExistenceValidator,
            DescriptionExistenceValidator,
        )
        from sigma.validators.core.condition import AllOfThemConditionValidator
        from sigma.validators.core.tags import ATTACKTagValidator

        validators = [
            TitleLengthValidator(),
            StatusExistenceValidator(),
            StatusUnsupportedValidator(),
            LevelExistenceValidator(),
            DateExistenceValidator(),
            DescriptionExistenceValidator(),
            AllOfThemConditionValidator(),
            ATTACKTagValidator(),
        ]

        collection = SigmaCollection.from_yaml(rule_yaml)
        for rule in collection:
            for validator in validators:
                try:
                    errors = validator.validate(rule)
                    for err in errors:
                        severity = "error" if _is_error(validator) else "warning"
                        issues.append({
                            "type": severity,
                            "rule": type(validator).__name__,
                            "message": str(err),
                        })
                except Exception as ve:
                    logger.debug(f"Validator {type(validator).__name__} raised: {ve}")

    except ImportError:
        issues.append({
            "type": "warning",
            "rule": "validator_unavailable",
            "message": "pySigma validators not available — only structural checks performed",
        })
    except Exception as e:
        issues.append({
            "type": "error",
            "rule": "sigma_parse",
            "message": f"pySigma parse error: {e}",
        })

    return issues


def _is_error(validator: Any) -> bool:
    """Treat metadata existence checks as warnings, structural as errors."""
    from sigma.validators.core.metadata import (
        DateExistenceValidator,
        DescriptionExistenceValidator,
        LevelExistenceValidator,
    )
    return not isinstance(validator, (DateExistenceValidator, DescriptionExistenceValidator, LevelExistenceValidator))
