package terraform.iam

deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "google_project_iam_binding"
    dangerous_roles := [
        "roles/owner",
        "roles/editor",
        "roles/iam.serviceAccountAdmin"
    ]
    resource.values.role in dangerous_roles
    msg := sprintf("IAM binding grants overly permissive role '%s'. Use principle of least privilege.", [resource.values.role])
}

deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "google_service_account"
    not regex.match("^[a-z0-9-]+-[a-z]+-sa$", resource.values.account_id)
    msg := sprintf("Service account '%s' does not follow naming convention: {service}-{environment}-sa", [resource.values.account_id])
}
