"""Controlled synthetic OTLP log payloads for integration tests."""

import json
import time

PROBE_SERVICE_NAME = "aic-otlp-ingestion-probe"
PROBE_CANARY = "AIC_SYNTHETIC_TEST_ONLY"


def build_redaction_probe(trace_id: str) -> dict[str, object]:
    """Build a synthetic log with a unique correlation identifier."""
    probe_body = {
        "event": "redaction_probe",
        "trace_id": trace_id,
        "synthetic_canary": PROBE_CANARY,
    }

    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "service.name",
                            "value": {
                                "stringValue": PROBE_SERVICE_NAME,
                            },
                        },
                        {
                            "key": "deployment.environment.name",
                            "value": {"stringValue": "local"},
                        },
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {
                            "name": "aic-redaction-integration",
                        },
                        "logRecords": [
                            {
                                "timeUnixNano": str(time.time_ns()),
                                "severityNumber": 9,
                                "severityText": "INFO",
                                "body": {
                                    "stringValue": json.dumps(probe_body),
                                },
                            }
                        ],
                    }
                ],
            }
        ]
    }
