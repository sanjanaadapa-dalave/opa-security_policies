package terraform.gce

# Deny GCE instances with public IP addresses
deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "google_compute_instance"
    
    # Check if instance has external IP
    network_interface := resource.values.network_interface[_]
    count(network_interface.access_config) > 0
    
    msg := sprintf("GCE instance '%s' has public IP address. Public IPs should be avoided for security.", [resource.name])
}

# Deny instances without proper labels
deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "google_compute_instance"
    
    # Check required labels
    required_labels := ["environment", "team", "project"]
    missing_labels := [label | 
        label := required_labels[_]
        not resource.values.labels[label]
    ]
    
    count(missing_labels) > 0
    
    msg := sprintf("GCE instance '%s' missing required labels: %v", [resource.name, missing_labels])
}

# Deny instances with overly permissive service account scopes
deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "google_compute_instance"
    
    service_account := resource.values.service_account[_]
    "https://www.googleapis.com/auth/cloud-platform" in service_account.scopes
    
    msg := sprintf("GCE instance '%s' uses overly broad 'cloud-platform' scope. Use specific scopes instead.", [resource.name])
}

# Deny instances without disk encryption
deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "google_compute_instance"
    
    boot_disk := resource.values.boot_disk[_]
    initialize_params := boot_disk.initialize_params[_]
    not initialize_params.kms_key_self_link
    
    msg := sprintf("GCE instance '%s' boot disk is not encrypted with customer-managed key.", [resource.name])
}
