"""
Sigma rule conversion service.

Wraps pySigma conversion logic and handles:
- YAML validation
- Format conversion
- Pipeline application
- Idempotency (hash-based conversion IDs)
- Subprocess execution of sigma_converter.py
"""

from schemas.models import ConversionResponse
from middleware.errors import InvalidRuleError, UnsupportedFormatError, ConversionTimeoutError
from config import Settings
import hashlib
import logging
import asyncio
import tempfile
import os
import base64
from pathlib import Path
import yaml

logger = logging.getLogger(__name__)


class ConversionService:
    """Service for converting Sigma rules to various formats."""

    SUPPORTED_FORMATS = {
        "es-qs",
        "default",
        "dsl_lucene",
        "kibana",
        "kibana_ndjson",
        "siem_rule",
        "siem_rule_ndjson",
        "elasticsearch-rule",
        "xpack-watcher",
        "xpack-watcher-sp",
        "eql",
        "esql",
        "elastalert",
    }

    SUPPORTED_PIPELINES = {
        "ecs_windows",
        "ecs_windows_old",
        "ecs_linux",
        "ecs_zeek_beats",
        "ecs_zeek_corelight",
        "zeek_raw",
        "ecs_kubernetes",
        "ecs_macos_esf",
    }

    def __init__(self):
        """Initialize conversion service."""
        self.plugin_root = None
        self.converter_script = None
        self.venv_python = None

    def _find_converter_paths(self, settings: Settings):
        """Locate the Python converter script and virtual environment."""
        if self.converter_script:
            return  # Already found

        plugin_root = Path(settings.plugin_root)
        converter_script = plugin_root / "server" / "translation_script" / "sigma" / "sigma_converter.py"

        if not converter_script.exists():
            raise FileNotFoundError(
                f"sigma_converter.py not found at {converter_script}. "
                "Ensure PLUGIN_ROOT is set correctly and server/translation_script/sigma/ is present."
            )

        # Use the venv inside translation_script if present; otherwise fall back to system Python.
        venv_python = plugin_root / "server" / "translation_script" / ".venv" / "bin" / "python"
        if not venv_python.exists():
            venv_python = Path("python3")

        self.converter_script = converter_script
        self.venv_python = venv_python
        self.plugin_root = plugin_root
        logger.info(f"Found converter script: {self.converter_script}")

    async def convert_rule(
        self,
        rule_yaml: str,
        format: str,
        pipeline: str = "ecs_windows",
        settings: Settings = None,
    ) -> ConversionResponse:
        """
        Convert a Sigma rule to the specified format.

        Args:
            rule_yaml: Sigma rule as YAML string
            format: Target format (eql, lucene, etc.)
            pipeline: Field mapping pipeline (ecs_windows, etc.)
            settings: Configuration settings

        Returns:
            ConversionResponse with conversion_id, query_result, format

        Raises:
            InvalidRuleError: If rule YAML is invalid
            UnsupportedFormatError: If format not supported
            ConversionTimeoutError: If conversion exceeds timeout
        """
        # Validate format
        if format not in self.SUPPORTED_FORMATS:
            raise UnsupportedFormatError(format, instance="/v1/conversions")

        # Validate pipeline
        if pipeline not in self.SUPPORTED_PIPELINES:
            raise UnsupportedFormatError(
                f"Unknown pipeline: {pipeline}", instance="/v1/conversions"
            )

        # Validate YAML
        try:
            yaml.safe_load(rule_yaml)
        except yaml.YAMLError as e:
            raise InvalidRuleError(
                f"Invalid YAML: {str(e)}", instance="/v1/conversions"
            )

        logger.info(f"Converting rule to {format} using pipeline {pipeline}")

        # Generate conversion ID (idempotency: same rule+format+pipeline = same ID)
        conversion_id = self._generate_conversion_id(rule_yaml, format, pipeline)

        # Call pySigma converter (async subprocess)
        try:
            query_result = await self._execute_conversion(
                rule_yaml, format, pipeline, settings
            )
        except Exception as e:
            logger.error(f"Conversion failed: {e}")
            raise InvalidRuleError(
                f"Conversion failed: {str(e)}", instance="/v1/conversions"
            )

        return ConversionResponse(
            conversion_id=conversion_id,
            query_result=query_result,
            format=format,
        )

    async def _execute_conversion(
        self,
        rule_yaml: str,
        format: str,
        pipeline: str,
        settings: Settings,
    ) -> str:
        """
        Execute the pySigma converter script via subprocess.

        Args:
            rule_yaml: Sigma rule YAML
            format: Target format
            pipeline: Field mapping pipeline
            settings: Configuration

        Returns:
            Converted query string (may be base64-encoded)

        Raises:
            ConversionTimeoutError: If conversion exceeds timeout
            InvalidRuleError: If conversion fails
        """
        self._find_converter_paths(settings)

        # Create temporary file for rule
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(rule_yaml)
            tmp_path = tmp.name

        try:
            # Run converter script asynchronously
            proc = await asyncio.create_subprocess_exec(
                str(self.venv_python),
                str(self.converter_script),
                tmp_path,
                format,
                "--pipeline",
                pipeline,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=30,  # TODO: Use settings.conversion_timeout_seconds
                )
            except asyncio.TimeoutError:
                proc.kill()
                raise ConversionTimeoutError(30, instance="/v1/conversions")

            # Handle errors from converter
            if proc.returncode != 0:
                error_msg = stderr.decode("utf-8", errors="replace").strip()
                logger.error(f"Converter error (code {proc.returncode}): {error_msg}")
                raise InvalidRuleError(
                    f"Converter error: {error_msg}", instance="/v1/conversions"
                )

            # Return result (may be base64 from converter)
            result = stdout.decode("utf-8", errors="replace").strip()
            return result

        finally:
            # Clean up temp file
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _generate_conversion_id(self, rule_yaml: str, format: str, pipeline: str) -> str:
        """Generate idempotent conversion ID from inputs."""
        combined = f"{rule_yaml}:{format}:{pipeline}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16]
