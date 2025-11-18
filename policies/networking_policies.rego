package terraform.networking

# Helper to get all resources
resources[resource] {
    resource := input.planned_values.root_module.resources[_]
}

resources[resource] {
    resource := input.resource_changes[_]
}

# Deny firewall rules with dangerous ports open to the internet
deny[msg] {
    resource := resources[_]
    resource.type == "google_compute_firewall"
    
    # Check if source includes 0.0.0.0/0
    source_ranges := object.get(resource.values, "source_ranges", [])
    "0.0.0.0/0" in source_ranges
    
    # Check for dangerous ports
    dangerous_ports := ["22", "3389", "1433", "3306", "5432", "5984", "6379", "7000", "7001", "8020", "8888", "9042", "9160", "9200", "9300", "11211", "27017", "50070"]
    
    allow_rule := resource.values.allow[_]
    ports := object.get(allow_rule, "ports", [])
    port := ports[_]
    port in dangerous_ports
    
    msg := sprintf("Firewall rule '%s' allows dangerous port %s from 0.0.0.0/0 (internet). Restrict source ranges.", [resource.name, port])
}

# Deny subnetworks without private Google access
deny[msg] {
    resource := resources[_]
    resource.type == "google_compute_subnetwork"
    
    private_access := object.get(resource.values, "private_ip_google_access", false)
    not private_access
    
    msg := sprintf("Subnetwork '%s' does not have private Google access enabled. Enable for secure API access.", [resource.name])
}
