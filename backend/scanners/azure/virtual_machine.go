package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"cspm-dashboard/backend/models"
)

// VirtualMachineScanner checks Azure Virtual Machines and their associated
// Network Security Groups for security misconfigurations including unrestricted
// inbound access on sensitive ports and missing disk encryption.
// It is the Azure equivalent of the AWS EC2 scanner.
type VirtualMachineScanner struct {
	vmClient       *armcompute.VirtualMachinesClient
	nicClient      *armnetwork.InterfacesClient
	nsgClient      *armnetwork.SecurityGroupsClient
	subscriptionID string
}

// NewVirtualMachineScanner creates a VirtualMachineScanner from an Azure credential.
func NewVirtualMachineScanner(cred *azidentity.ClientSecretCredential, subscriptionID string) *VirtualMachineScanner {
	vmClient, _ := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)
	nicClient, _ := armnetwork.NewInterfacesClient(subscriptionID, cred, nil)
	nsgClient, _ := armnetwork.NewSecurityGroupsClient(subscriptionID, cred, nil)
	return &VirtualMachineScanner{
		vmClient:       vmClient,
		nicClient:      nicClient,
		nsgClient:      nsgClient,
		subscriptionID: subscriptionID,
	}
}

// ServiceName satisfies the Scanner interface.
func (s *VirtualMachineScanner) ServiceName() string { return "VirtualMachines" }

// Scan paginates over all VMs in the subscription and checks disk encryption
// and NSG rules for each.
func (s *VirtualMachineScanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	pager := s.vmClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("virtualmachines: listing VMs: %w", err)
		}

		for _, vm := range page.Value {
			if vm.Properties == nil {
				continue
			}
			vmName := strVal(vm.Name)
			vmID := strVal(vm.ID)
			location := strVal(vm.Location)
			resourceType := "Microsoft.Compute/virtualMachines"

			if f := s.checkDiskEncryption(vm, vmID, vmName, resourceType, location); f != nil {
				findings = append(findings, *f)
			}

			// Collect NSG findings from all attached network interfaces
			nsgFindings := s.checkVMNetworkSecurity(ctx, vm, vmID, vmName, resourceType, location)
			findings = append(findings, nsgFindings...)
		}
	}
	return findings, nil
}

// checkDiskEncryption detects VMs without Azure Disk Encryption (ADE) enabled
// on the OS disk. ADE encrypts the OS and data disks inside the guest OS using
// BitLocker (Windows) or DM-Crypt (Linux).
func (s *VirtualMachineScanner) checkDiskEncryption(vm *armcompute.VirtualMachine, id, name, resourceType, location string) *models.Finding {
	if vm.Properties.StorageProfile == nil || vm.Properties.StorageProfile.OSDisk == nil {
		return nil
	}
	osDisk := vm.Properties.StorageProfile.OSDisk
	if osDisk.EncryptionSettings != nil && boolVal(osDisk.EncryptionSettings.Enabled) {
		return nil
	}
	// Also check if managed disk has disk encryption set (platform-side encryption)
	// For Azure Disk Encryption (guest-level), only EncryptionSettings.Enabled matters
	f := newFinding(
		id, resourceType, name, s.ServiceName(), location, s.subscriptionID,
		models.SeverityHigh,
		"Virtual Machine OS disk does not have Azure Disk Encryption enabled",
		fmt.Sprintf("VM '%s' has Azure Disk Encryption (ADE) disabled on its OS disk. "+
			"While Azure encrypts managed disks at rest with platform-managed keys by default, "+
			"ADE provides an additional layer of encryption using customer-controlled keys stored "+
			"in Azure Key Vault. Without ADE, disk snapshots and VHD exports are not protected "+
			"by customer-managed encryption.", name),
		fmt.Sprintf("Enable Azure Disk Encryption for VM '%s': "+
			"az vm encryption enable --resource-group <rg> --name %s --disk-encryption-keyvault <keyvault-id>. "+
			"Ensure the Key Vault has disk encryption enabled and that the VM has a managed identity "+
			"or appropriate Key Vault access policy.", name, name),
		"CIS Azure 7.6",
		[]string{"CIS", "SOC2", "PCI-DSS", "HIPAA"},
	)
	return &f
}

// sensitivePort maps a port number to a human-readable service name.
var sensitivePort = map[int]string{
	22:    "SSH",
	3389:  "RDP",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	1433:  "MSSQL",
	27017: "MongoDB",
	6379:  "Redis",
	9200:  "Elasticsearch",
}

// checkVMNetworkSecurity follows VM → NIC → NSG links and checks for
// security rules that allow unrestricted inbound access to sensitive ports.
func (s *VirtualMachineScanner) checkVMNetworkSecurity(
	ctx context.Context,
	vm *armcompute.VirtualMachine,
	vmID, vmName, resourceType, location string,
) []models.Finding {
	var findings []models.Finding

	if vm.Properties.NetworkProfile == nil {
		return nil
	}

	// Track which port violations have already been reported for this VM
	// to avoid duplicate findings (same port, different NICs).
	reportedPorts := make(map[int]bool)

	for _, nicRef := range vm.Properties.NetworkProfile.NetworkInterfaces {
		if nicRef.ID == nil {
			continue
		}
		nicID := *nicRef.ID
		nicRG := resourceGroupFromID(nicID)
		nicName := resourceNameFromID(nicID)
		if nicRG == "" || nicName == "" {
			continue
		}

		nicResp, err := s.nicClient.Get(ctx, nicRG, nicName, nil)
		if err != nil {
			continue
		}
		if nicResp.Properties == nil || nicResp.Properties.NetworkSecurityGroup == nil {
			continue
		}

		nsgRef := nicResp.Properties.NetworkSecurityGroup
		if nsgRef.ID == nil {
			continue
		}
		nsgID := *nsgRef.ID
		nsgRG := resourceGroupFromID(nsgID)
		nsgName := resourceNameFromID(nsgID)
		if nsgRG == "" || nsgName == "" {
			continue
		}

		nsgResp, err := s.nsgClient.Get(ctx, nsgRG, nsgName, nil)
		if err != nil {
			continue
		}
		if nsgResp.Properties == nil {
			continue
		}

		for _, rule := range nsgResp.Properties.SecurityRules {
			if rule.Properties == nil {
				continue
			}
			rp := rule.Properties
			if rp.Access == nil || *rp.Access != armnetwork.SecurityRuleAccessAllow {
				continue
			}
			if rp.Direction == nil || *rp.Direction != armnetwork.SecurityRuleDirectionInbound {
				continue
			}
			if !isUnrestrictedSource(rp) {
				continue
			}

			// Collect exposed ports from this rule
			for port, serviceName := range sensitivePort {
				if reportedPorts[port] {
					continue
				}
				if ruleExposesPort(rp, port) {
					reportedPorts[port] = true
					severity := models.SeverityCritical
					if port != 22 && port != 3389 {
						severity = models.SeverityHigh
					}
					f := newFinding(
						vmID, resourceType, vmName, s.ServiceName(), location, s.subscriptionID,
						severity,
						fmt.Sprintf("VM '%s' NSG allows unrestricted inbound %s (port %d) from the internet", vmName, serviceName, port),
						fmt.Sprintf("Network Security Group '%s' attached to VM '%s' has an inbound rule "+
							"allowing %s traffic on port %d from any IP address (0.0.0.0/0 or *). "+
							"This exposes the service directly to the internet, enabling brute-force attacks, "+
							"exploitation of known vulnerabilities, and credential stuffing.", nsgName, vmName, serviceName, port),
						fmt.Sprintf("Remove or restrict the unrestricted inbound rule in NSG '%s': "+
							"az network nsg rule update --resource-group %s --nsg-name %s --name <rule-name> "+
							"--source-address-prefixes <trusted-ip-range>. "+
							"Use Azure Bastion for SSH/RDP access instead of exposing ports directly.", nsgName, nsgRG, nsgName),
						"CIS Azure 6.1",
						[]string{"CIS", "SOC2", "PCI-DSS"},
					)
					findings = append(findings, f)
				}
			}
		}
	}
	return findings
}

// isUnrestrictedSource returns true if a security rule's source allows
// traffic from any IP address.
func isUnrestrictedSource(rp *armnetwork.SecurityRulePropertiesFormat) bool {
	if rp.SourceAddressPrefix != nil {
		src := *rp.SourceAddressPrefix
		return src == "*" || src == "0.0.0.0/0" || src == "Internet" || src == "Any"
	}
	// Also check SourceAddressPrefixes slice
	for _, prefix := range rp.SourceAddressPrefixes {
		if prefix == nil {
			continue
		}
		if *prefix == "*" || *prefix == "0.0.0.0/0" || *prefix == "Internet" || *prefix == "Any" {
			return true
		}
	}
	return false
}

// ruleExposesPort returns true if the security rule's destination port range
// covers the given port number.
func ruleExposesPort(rp *armnetwork.SecurityRulePropertiesFormat, port int) bool {
	portStr := fmt.Sprintf("%d", port)

	// Single port or range in DestinationPortRange
	if rp.DestinationPortRange != nil {
		if portInRange(*rp.DestinationPortRange, port, portStr) {
			return true
		}
	}
	// Multiple ranges in DestinationPortRanges
	for _, r := range rp.DestinationPortRanges {
		if r == nil {
			continue
		}
		if portInRange(*r, port, portStr) {
			return true
		}
	}
	return false
}

// portInRange checks whether a port range string ("*", "22", "80-443") includes
// the given port number.
func portInRange(rangeStr string, port int, portStr string) bool {
	if rangeStr == "*" || rangeStr == "0-65535" {
		return true
	}
	if rangeStr == portStr {
		return true
	}
	// Handle "start-end" ranges
	if idx := strings.Index(rangeStr, "-"); idx >= 0 {
		var start, end int
		_, err := fmt.Sscanf(rangeStr, "%d-%d", &start, &end)
		if err == nil && port >= start && port <= end {
			return true
		}
	}
	return false
}

// resourceNameFromID extracts the resource name (last path segment) from an ARM resource ID.
func resourceNameFromID(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
