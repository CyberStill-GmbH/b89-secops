terraform {
  backend "s3" {
    bucket       = "b89-secops-terraform-state-955200662475"
    key          = "demo/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}