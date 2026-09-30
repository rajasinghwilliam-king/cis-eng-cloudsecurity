variable "name" {
  type        = string
  description = "Name of the private endpoint."
}

variable "location" {
  type        = string
  description = "Azure region."
}

variable "resource_group_name" {
  type        = string
  description = "Resource group that hosts the private endpoint."
}

variable "subnet_id" {
  type        = string
  description = "Subnet resource ID where the private endpoint NIC is created."
}

variable "target_resource_id" {
  type        = string
  description = "Resource ID of the service the private endpoint connects to."
}

variable "subresource_names" {
  type        = list(string)
  description = "Sub-resource (group ID) names, e.g. ['sites'] or ['blob']."
}

variable "private_dns_zone_ids" {
  type        = list(string)
  description = "Private DNS zone IDs to auto-register the endpoint in. Empty list skips the DNS zone group."
  default     = []
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to the private endpoint."
  default     = {}
}
