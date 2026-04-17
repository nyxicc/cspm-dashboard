output "scan_credentials" {
  description = "Paste these into the CSPM Dashboard Azure scan form"
  value = {
    subscription_id = var.subscription_id
    tenant_id       = "ff07bbf3-5636-4101-af34-d5c05a564d16"
    client_id       = "57958eec-8625-48e7-bd7a-db9672f8c444"
    note            = "client_secret was set when you created the service principal"
  }
}

output "resource_group" {
  value = azurerm_resource_group.test.name
}
