package terraform.storage

# Helper to get all resources
resources[resource] {
    resource := input.planned_values.root_module.resources[_]
}

resources[resource] {
    resource := input.resource_changes[_]
}

# Deny storage buckets without public access prevention
deny[msg] {
    resource := resources[_]
    resource.type == "google_storage_bucket"
    
    # Check if public access prevention is not enforced
    pap := object.get(resource.values, "public_access_prevention", "inherited")
    pap != "enforced"
    
    msg := sprintf("Storage bucket '%s' does not enforce public access prevention (currently: %s). Set to 'enforced'.", [resource.name, pap])
}

# Deny buckets without uniform bucket-level access
deny[msg] {
    resource := resources[_]
    resource.type == "google_storage_bucket"
    
    # Check uniform bucket level access (it's a boolean in newer provider versions)
    ubla := object.get(resource.values, "uniform_bucket_level_access", false)
    ubla == false
    
    msg := sprintf("Storage bucket '%s' does not have uniform bucket-level access enabled.", [resource.name])
}

# Deny buckets without versioning
deny[msg] {
    resource := resources[_]
    resource.type == "google_storage_bucket"
    
    # Check versioning - it's a nested object with enabled field
    versioning := object.get(resource.values, "versioning", [])
    count(versioning) > 0
    version_config := versioning[0]
    not version_config.enabled
    
    msg := sprintf("Storage bucket '%s' does not have versioning enabled.", [resource.name])
}

# Alternative check for missing versioning entirely
deny[msg] {
    resource := resources[_]
    resource.type == "google_storage_bucket"
    
    not resource.values.versioning
    
    msg := sprintf("Storage bucket '%s' does not have versioning configured.", [resource.name])
}
