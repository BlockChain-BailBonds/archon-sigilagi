package nap.authorization
import rego.v1

default decision := {"allow": false, "mode": "escalate", "reasons": ["fail closed"]}
autonomous := {"block_ioc_temporarily", "rate_limit_route", "disable_feature_flag", "quarantine_workload", "rollback_container_image"}

decision := {"allow": true, "mode": "canary", "reasons": ["all gates passed"]} if {
  input.plan.primitive.name in autonomous
  input.evidence.independent_source_count >= 2
  input.evidence.maximum_confidence >= 0.90
  input.applicability.component_present
  input.applicability.version_affected
  input.applicability.path_reachable
  input.plan.rollback.automatic
  input.telemetry.coverage_percent >= 95
}

