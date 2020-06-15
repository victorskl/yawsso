terraform {
  required_version = "~> 0.12"
}

provider "aws" {
  version = "~> 2.66"
}

data "aws_vpc" "default_vpc" {
  default = true
}

output "default_vpc_id" {
  value = data.aws_vpc.default_vpc.id
}
