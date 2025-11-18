package terraform.iam

# Helper to get all resources
resources[resource] {
    resource := input.planned_values.root_module.resources[_]
}

resources[resource] {
    resource := input.resource_changes[_]
}

# Deny overly permissive IAM roles
deny[msg] {
    resource := resources[_]
    resource.type == "google_project_iam_binding"
    
    dangerous_roles := [
        "roles/owner",
        "roles/editor",
        "roles/iam.serviceAccountAdmin",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/resourcemanager.organizationAdmin"
    ]
    
    role := object.get(resource.values, "role", "")
    dangerous_role := dangerous_roles[_]
    role == dangerous_role
    
    msg := sprintf("IAM binding grants overly permissive role '%s'. Use principle of least privilege with specific roles.", [role])
}

# Also check google_project_iam_member
deny[msg] {
    resource := resources[_]
    resource.type == "google_project_iam_member"
    
    dangerous_roles := [
        "roles/owner",
        "roles/editor",
        "roles/iam.serviceAccountAdmin",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/resourcemanager.organizationAdmin"
    ]
    
    role := object.get(resource.values, "role", "")
    dangerous_role := dangerous_roles[_]
    role == dangerous_role
    
    msg := sprintf("IAM member grants overly permissive role '%s'. Use principle of least privilege with specific roles.", [role])
}

# Deny service accounts with non-compliant naming
deny[msg] {
    resource := resources[_]
    resource.type == "google_service_account"
    
    account_id := object.get(resource.values, "account_id", "")
    not regex.match("^[a-z0-9-]+-[a-z]+-sa$", account_id)
    
    msg := sprintf("Service account '%s' does not follow naming convention: {service}-{environment}-sa (e.g., compute-prod-sa)", [account_id])
}
