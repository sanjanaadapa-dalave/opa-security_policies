package terraform.storage

# Deny storage buckets without public access prevention
deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "google_storage_bucket"
    
    # Check if public access prevention is not enforced
    resource.values.public_access_prevention != "enforced"
    
    msg := sprintf("Storage bucket '%s' does not enforce public access prevention.", [resource.name])
}

# Deny buckets without uniform bucket-level access
deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "google_storage_bucket"
    
    # Check uniform bucket level access
    uniform_access := resource.values.uniform_bucket_level_access[_]
    not uniform_access.enabled
    
    msg := sprintf("Storage bucket '%s' does not have uniform bucket-level access enabled.", [resource.name])
}

# Deny buckets without versioning
deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "google_storage_bucket"
    
    # Check versioning
    versioning := resource.values.versioning[_]
    not versioning.enabled
    
    msg := sprintf("Storage bucket '%s' does not have versioning enabled.", [resource.name])
}