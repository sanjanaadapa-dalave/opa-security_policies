# OPA Security Policies for GCP Terraform

Security policies for validating Google Cloud Platform Terraform configurations using Open Policy Agent (OPA).

## Policies

### GCE Policies (`gce_policies.rego`)
- ❌ **No public IPs**: Instances must not have `access_config` blocks
- ❌ **Required labels**: Instances must have `environment`, `team`, and `project` labels
- ❌ **Restricted scopes**: Service accounts cannot use `cloud-platform` scope

### Storage Policies (`storage_policies.rego`)
- ❌ **Public access prevention**: Buckets must have `public_access_prevention = "enforced"`
- ❌ **Uniform bucket access**: Buckets must have `uniform_bucket_level_access = true`
- ❌ **Versioning enabled**: Buckets must have versioning enabled

### Networking Policies (`networking_policies.rego`)
- ❌ **No dangerous ports to internet**: Firewall rules cannot allow SSH (22), RDP (3389), or database ports from `0.0.0.0/0`
- ❌ **Private Google access**: Subnetworks must have `private_ip_google_access = true`

### IAM Policies (`iam_policies.rego`)
- ❌ **No overly permissive roles**: Cannot grant `roles/owner`, `roles/editor`, or admin roles
- ❌ **Service account naming**: Must follow pattern `{service}-{environment}-sa`

## Usage

These policies are automatically fetched by Cloud Build during the validation pipeline.

## Testing Locally

```bash
# Generate Terraform plan
cd terraform/
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > plan.json

# Run OPA evaluation
opa eval --data policies/ --input plan.json --format pretty 'data.terraform'
```

## Policy Structure

Each policy file defines a `deny` rule that returns violation messages when conditions are not met.

```rego
package terraform.{category}

deny[msg] {
    # Condition that triggers violation
    msg := "Violation message"
}
```
