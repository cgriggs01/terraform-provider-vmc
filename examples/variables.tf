variable "api_token"{
  description = "API token used to auntheicate when calling the VMware Cloud Services API."
  default = ""
}

variable "org_id"{
  description = "Organization Identifier."
  default = ""
}

variable "sddc_name"{
  description = "Name of SDDC."
  default = "sddc-test"
}

variable "sddc_region" {
  description = "The AWS region."
  default     = "US_WEST_2"
}


variable "vpc_cidr" {
  description = "AWS VPC IP range. Only prefix of 16 or 20 is currently supported."
  default     = "10.2.0.0/16"
}

variable "vxlan_subnet" {
  description = "VXLAN IP subnet in CIDR for compute gateway."
  default     = "192.168.1.0/24"
}

variable "private_ip" {
  description = "The private IP of SDDC."
  default     = "10.2.33.45"
}
