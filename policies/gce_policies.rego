package terraform.gce

# Helper to get all resources from plan
resources[resource] {
    resource := input.planned_values.root_module.resources[_]
}

resources[resource] {
    resource := input.resource_changes[_]
}

# Deny GCE instances with public IP addresses
deny[msg] {
    resource := resources[_]
    resource.type == "google_compute_instance"
    
    # Check if instance has external IP in network_interface
    network_interface := resource.values.network_interface[_]
    count(network_interface.access_config) > 0
    
    msg := sprintf("GCE instance '%s' has public IP address (access_config). Public IPs should be avoided for security.", [resource.name])
}

# Alternative check for resource_changes structure
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_instance"
    resource.change.after.network_interface[_].access_config
    count(resource.change.after.network_interface[_].access_config) > 0
    
    msg := sprintf("GCE instance '%s' has public IP address (access_config). Public IPs should be avoided for security.", [resource.name])
}

# Deny instances without proper labels
deny[msg] {
    resource := resources[_]
    resource.type == "google_compute_instance"
    
    # Check required labels
    required_labels := ["environment", "team", "project"]
    labels := object.get(resource.values, "labels", {})
    
    missing := [label | 
        label := required_labels[_]
        not labels[label]
    ]
    
    count(missing) > 0
    
    msg := sprintf("GCE instance '%s' missing required labels: %v. Required: environment, team, project", [resource.name, missing])
}

# Deny instances with overly permissive service account scopes
deny[msg] {
    resource := resources[_]
    resource.type == "google_compute_instance"
    
    service_account := resource.values.service_account[_]
    scopes := service_account.scopes
    scope := scopes[_]
    scope == "https://www.googleapis.com/auth/cloud-platform"
    
    msg := sprintf("GCE instance '%s' uses overly broad 'cloud-platform' scope. Use specific scopes instead.", [resource.name])
}

# Deny instances without disk encryption
deny[msg] {
    resource := resources[_]
    resource.type == "google_compute_instance"
    
    boot_disk := resource.values.boot_disk[_]
    not boot_disk.disk_encryption_key
    
    msg := sprintf("GCE instance '%s' boot disk is not encrypted with customer-managed key (CMEK).", [resource.name])
}
