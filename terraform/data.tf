# Resolve subnets from the existing (referenced) virtual network described in the JSON config.
data "azurerm_subnet" "integration" {
  name                 = local.network.integration_subnet_name
  virtual_network_name = local.network.virtual_network_name
  resource_group_name  = local.network.virtual_network_resource_group
}

data "azurerm_subnet" "private_endpoint" {
  name                 = local.network.private_endpoint_subnet_name
  virtual_network_name = local.network.virtual_network_name
  resource_group_name  = local.network.virtual_network_resource_group
}
