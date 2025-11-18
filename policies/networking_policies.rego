package terraform.networking

deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "google_compute_firewall"
    "0.0.0.0/0" in resource.values.source_ranges
    dangerous_ports := ["22", "3389", "1433", "3306", "5432"]
    allow_rule := resource.values.allow[_]
    port := allow_rule.ports[_]
    port in dangerous_ports
    msg := sprintf("Firewall rule '%s' allows dangerous port %s from 0.0.0.0/0.", [resource.name, port])
}

deny contains msg if {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "google_compute_subnetwork"
    not resource.values.private_ip_google_access
    msg := sprintf("Subnetwork '%s' does not have private Google access enabled.", [resource.name])
}
