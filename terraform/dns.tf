########################################
# Private DNS zones (optional, created + VNet-linked by Terraform)
########################################

locals {
  # Sub-resource key -> private DNS zone name.
  private_dns_zone_names = {
    sites = "privatelink.azurewebsites.net"
    blob  = "privatelink.blob.core.windows.net"
    file  = "privatelink.file.core.windows.net"
    queue = "privatelink.queue.core.windows.net"
    table = "privatelink.table.core.windows.net"
    vault = "privatelink.vaultcore.azure.net"
  }
}

resource "azurerm_private_dns_zone" "this" {
  for_each            = local.create_private_dns_zones ? local.private_dns_zone_names : {}
  name                = each.value
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  for_each              = local.create_private_dns_zones ? local.private_dns_zone_names : {}
  name                  = "link-${local.network.virtual_network_name}-${each.key}"
  resource_group_name   = azurerm_resource_group.this.name
  private_dns_zone_name  = azurerm_private_dns_zone.this[each.key].name
  virtual_network_id    = data.azurerm_virtual_network.this.id
  registration_enabled  = false
  tags                  = local.common_tags
}

locals {
  # Effective zone ID per sub-resource: Terraform-created zones when enabled,
  # otherwise the IDs supplied in the JSON (centrally-managed zones).
  effective_private_dns_zone_ids = local.create_private_dns_zones ? {
    for k, z in azurerm_private_dns_zone.this : k => z.id
  } : local.private_dns_zone_ids
}
