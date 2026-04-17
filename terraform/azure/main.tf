terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
    random  = { source = "hashicorp/random",  version = "~> 3.0" }
    tls     = { source = "hashicorp/tls",     version = "~> 4.0" }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "azurerm_resource_group" "test" {
  name     = "cspm-test-insecure"
  location = var.location
}

data "azurerm_client_config" "current" {}

# ── Blob Storage ─────────────────────────────────────────────────
# Triggers: public blob access, HTTP allowed, TLS < 1.2

resource "azurerm_storage_account" "insecure" {
  name                     = "cspminsc${random_id.suffix.hex}"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = azurerm_resource_group.test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = true    # finding: public blob access
  https_traffic_only_enabled      = false   # finding: HTTP allowed
  min_tls_version                 = "TLS1_0" # finding: below 1.2
}

# ── Key Vault ─────────────────────────────────────────────────────
# Triggers: no purge protection, network ACL default allow, no RBAC auth

resource "azurerm_key_vault" "insecure" {
  name                      = "cspm-kv-${random_id.suffix.hex}"
  location                  = azurerm_resource_group.test.location
  resource_group_name       = azurerm_resource_group.test.name
  sku_name                  = "standard"
  tenant_id                 = data.azurerm_client_config.current.tenant_id

  purge_protection_enabled  = false  # finding
  rbac_authorization_enabled = false  # finding

  network_acls {
    default_action = "Allow"         # finding: public access
    bypass         = "AzureServices"
  }
}

# ── Virtual Machine + insecure NSG ───────────────────────────────
# Triggers: disk encryption off, unrestricted SSH/RDP/DB ports

resource "azurerm_virtual_network" "test" {
  name                = "cspm-test-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
}

resource "azurerm_subnet" "test" {
  name                 = "cspm-test-subnet"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_security_group" "insecure" {
  name                = "cspm-test-nsg"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name

  security_rule {
    name                       = "allow-ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"   # finding: unrestricted SSH
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-rdp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"   # finding: unrestricted RDP
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-db-ports"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["3306", "5432", "1433", "27017"]
    source_address_prefix      = "*"   # finding: unrestricted DB ports
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface" "test" {
  name                = "cspm-test-nic"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.test.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface_security_group_association" "test" {
  network_interface_id      = azurerm_network_interface.test.id
  network_security_group_id = azurerm_network_security_group.insecure.id
}

resource "tls_private_key" "test" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "azurerm_linux_virtual_machine" "insecure" {
  name                = "cspm-test-vm"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  size                = "Standard_B2s"
  admin_username      = "adminuser"

  network_interface_ids = [azurerm_network_interface.test.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    # No disk_encryption_set_id = finding: disk encryption off
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  admin_ssh_key {
    username   = "adminuser"
    public_key = tls_private_key.test.public_key_openssh
  }
}

# ── Azure SQL ─────────────────────────────────────────────────────
# Triggers: public network access on, no auditing, TDE disabled

resource "azurerm_mssql_server" "insecure" {
  name                         = "cspm-sql-${random_id.suffix.hex}"
  resource_group_name          = azurerm_resource_group.test.name
  location                     = azurerm_resource_group.test.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "CspmTest123!"

  public_network_access_enabled = true  # finding
}

resource "azurerm_mssql_database" "insecure" {
  name      = "cspmtestdb"
  server_id = azurerm_mssql_server.insecure.id
  sku_name  = "Basic"
  # TDE cannot be disabled on non-DW SKUs; public_network_access finding on the server covers SQL
}

# Activity Log: no diagnostic settings and no alert rules are intentionally
# absent — the scanner will flag their absence automatically.
