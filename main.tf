terraform {
  required_version = "~> 0.13"

  required_providers {
    aws = {
      version = "~> 3.11.0"
    }
  }
}

provider "aws" {
  profile = "dev"
  region  = "ap-southeast-2"
}

data "aws_vpc" "default_vpc" {
  default = true
}

output "default_vpc_id" {
  value = data.aws_vpc.default_vpc.id
}
