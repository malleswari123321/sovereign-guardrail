package system.sovereign_guardrail

import future.keywords.in

default allow = false

# Approved sovereign regions per data classification
approved_sovereign_regions := {
    "RESTRICTED_PII": ["eu-central-1", "eu-west-1", "ap-south-1"],
    "CONFIDENTIAL": ["eu-central-1", "eu-west-1", "us-east-1", "ap-south-1"]
}

# Evaluate incoming deployment or request
allow {
    input.action == "provision_resource"
    input.data_classification in object.keys(approved_sovereign_regions)
    input.target_region in approved_sovereign_regions[input.data_classification]
    not violation_detected
}

# Catch cross-border data egress violations
violation_detected {
    input.action == "egress_data"
    input.destination_region != input.source_region
    input.data_classification == "RESTRICTED_PII"
}

