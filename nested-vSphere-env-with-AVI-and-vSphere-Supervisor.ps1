# PowerShell script which results in the creation of a nested vSphere 8 environment where vSphere Supervisor is enabled and using AVI for load balancing
# 
# Script will... 
# - Deploy vCenter, ESXi hosts, and AVI controller
# - Configure nested environment including vSphere cluster, vSAN, & networking
# - Configure AVI for L4 LB (not GSLB yet)
# - Create a storage policy and content library for vSphere Supervisor
# - Enable the vSphere Supervisor
# - ToDo: Install contour service
# - ToDo: Install harbor service
# - ToDo: Install consumption service
# - ToDo: Configure AVI GSLB
#
# Script based off the orginal work of William Lam's (Broadcom) nested vSphere 7 with NSX ALB https://github.com/lamw/vsphere-with-tanzu-nsx-advanced-lb-automated-lab-deployment and https://github.com/lamw/VMware.WorkloadManagement, and Italy Talmi (TeraSky) vSphere 8 enhacements https://github.com/itaytalmi/tkgs-nsxalb-lab-deployment/tree/vsphere-8


# Full path to the nested ESXi OVA, Extracted VCSA ISO, & AVI OVA
$NestedESXiApplianceOVA = "C:\Users\Administrator\Downloads\nested-install\Nested_ESXi8.0u3c_Appliance_Template_v1.ova"  #Download from https://community.broadcom.com/flings/home and unzip
$VCSAInstallerPath = "C:\Users\Administrator\Downloads\nested-install\VMware-VCSA-all-8.0.3-24322831\"                   #Download from https://support.broadcom.com and extract/mount the ISO
$AVIOVA = "C:\Users\Administrator\Downloads\nested-install\controller-22.1.7-9093.ova"                                   #Download from https://support.broadcom.com

# vCenter Server used to deploy nested vSphere env
$VIServer = "FILL-ME-IN"
$VIUsername = "FILL-ME-IN"
$VIPassword = "FILL-ME-IN"

# General deployment configuration for the nested ESXi, VCSA, & AVI VMs 
$VMDatacenter = "FILL-ME-IN"
$VMCluster = "FILL-ME-IN"
$VMDatastore = "FILL-ME-IN"
$VMResourcePool = "nested-vsphere-avi-lab"
$VMFolder = "nested-vsphere-avi-lab"
$VMNetwork = "nested-vmnetwork-40"
$VMNetmask = "255.255.255.0"
$VMGateway = "10.0.40.1"
$VMDNS = "10.0.40.1"
$VMNTP = "10.0.40.1"
$WorkloadNetwork = "nested-workload-50"
$VIPNetworkName = "nested-vips-60"
$VMPassword = "VMware123!VMware123!"
$VMDomain = "tanzu.lab"
$VMSearchPath = "tanzu.lab"
$VMSyslog = $VIServer #can use vCenter

# Nested ESXi VMs to deploy
$NestedESXiHostnameToIPs = @{
    "esxi-01" = "10.0.40.11"
    "esxi-02" = "10.0.40.12"
    "esxi-03" = "10.0.40.13"
}

# Nested ESXi VM resources
$NestedESXivCPU = "12"
$NestedESXivMEM = "128" #GB
$NestedESXiCachingvDisk = "90" #GB
$NestedESXiCapacityvDisk = "900" #GB

# Applicable to Nested ESXi only
$VMSSH = "true"
$VMVMFS = "false"

# Nested vCenter Server deployment configuration
$VCSADeploymentSize = "small"
$VCSADisplayName = "vcsa-01"
$VCSAIPAddress = "10.0.40.10"
$VCSAPrefix = "24"
$VCSAHostname = "nested-vcenter.tanzu.lab" #Change to IP if you don't have valid DNS
$VCSASSODomainName = "vsphere.local"
$VCSASSOPassword = "VMware123!VMware123!"
$VCSARootPassword = "VMware123!VMware123!"
$VCSASSHEnable = "true"

# Names for Nested vCenter objects 
$NewVCDatacenterName = "tanzu-datacenter"
$NewVCVSANClusterName = "tanzu-cluster"
$NewVCVDSName = "tanzu-vds"
$NewVCMgmtPortgroupName = "dvpg-mgmt-network"
$NewVCWorkloadPortgroupName = "dvpg-workload-network"
$NewVCVIPPortgroupName = "dvpg-vip-network"
$vSANDatastoreName = "vsanDatastore"

# AVI Configuration
$AVIVersion = "22.1.7"
$AVIDisplayName = "avi-01"
$AVIManagementIPAddress = "10.0.40.20"
$AVIHostname = "avi.tanzu.lab"
$AVIAdminPassword = "VMware123!VMware123!"
$AVIvCPU = "8" #GB
$AVIvMEM = "24" #GB
$AVIPassphrase = "VMware123!VMware123!"
$AVIIPAMName = "vip-ipam"
$AVILicenseType = "ENTERPRISE" #Note ESSENTIALS only has L4 LB
$AVIDefaultAdminPassword = "58NFaGDJm(PJH0G"
$AVISEVMFolder = "avi-service-engines"
$AVISENamePrefix = "avi"

# AVI Service Engine Management Network Configuration
$AVIManagementNetwork = "10.0.40.0"
$AVIManagementNetworkPrefix = "24"
$AVIManagementNetworkStartRange = "10.0.40.21"
$AVIManagementNetworkEndRange = "10.0.40.40"

# AVI VIP Network Configuration
$AVIVIPNetwork = "10.0.60.0"
$AVIVIPNetworkGateway = "10.0.60.1"
$AVIVIPNetworkPrefix = "24"
$AVIVIPNetworkStartRange = "10.0.60.10"
$AVIVIPNetworkEndRange = "10.0.60.99"

# AVI Self-Signed TLS Certificate
$AVISSLCertName = "avi-cert"
$AVISSLCertExpiry = "365" # Days
$AVISSLCertEmail = "admin@tanzu.lab"
$AVISSLCertOrganizationUnit = "k8s"
$AVISSLCertOrganization = "k8s"
$AVISSLCertLocation = "PA"
$AVISSLCertState = "CA"
$AVISSLCertCountry = "US"

# vSphere Supervisor Configuration
$StoragePolicyName = "sup-storage-policy"
$StoragePolicyTagCategory = "sup-tag-category"
$StoragePolicyTagName = "sup-storage"
$VKrContentLibraryName = "vkr-content-library"
$VKrContentLibraryURL = "https://wp-content.vmware.com/v2/latest/lib.json"
$SupervisorClusterName = "svc-01"
$ControlPlaneSize = "SMALL" #TINY, SMALL, MEDIUM, LARGE
$MgmtNetworkStartIP = "10.0.40.100" #Starting IP Address for Control Plane VMs (5 consecutive free addresses)
$MgmtNetworkPrefix = "24"
$WorkloadNetworkStartIP = "10.0.50.10"        
$WorkloadNetworkPrefix = "24"
$WorkloadNetworkIPCount = 100                  
$WorkloadNetworkGateway = "10.0.50.1"       
$WorkloadNetworkDNS = @("10.0.50.1")         
$WorkloadNetworkDNSDomain = "tanzu.lab"    
$WorkloadNetworkNTP = @("10.0.50.1")    
$WorkloadNetworkServiceStartIP = "10.96.0.0" #Starting IP Address for K8S Service (default: 10.96.0.0)
$WorkloadNetworkServiceStartCount = "512" #Number of IP Addrsses to allocate from WorkloadNetworkServiceStartIP (default: 256). Use 256 for TINY control plane. Use 512 for SMALL control plane.


# Advanced Configurations
# Set to 1 only if you have DNS (forward/reverse) for ESXi hostnames
$addHostByDnsName = 1


#### DO NOT EDIT BEYOND HERE ####
$verboseLogFile = "nested-vsphere-avi-lab-deployment.log"
$random_string = -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
$VAppName = "Nested-vSphere-AVI-Lab-$random_string"

$preCheck = 1
$confirmDeployment = 1
$deployAVI = 1
$deployNestedESXiVMs = 1
$deployVCSA = 1
$moveVMsIntovApp = 1 # need DRS enabled
$setupNewVC = 1
$addESXiHostsToVC = 1
$configureVSANDiskGroup = 1
$configureVDS = 1
$clearVSANHealthCheckAlarm = 1
$setupStoragePolicy = 1
$setupContentLibrary = 1
$setupAVI = 1
$enableVsphereSupervisor = 1


$vcsaSize2MemoryStorageMap = @{
    "tiny"   = @{"cpu" = "2"; "mem" = "12"; "disk" = "415" };
    "small"  = @{"cpu" = "4"; "mem" = "19"; "disk" = "480" };
    "medium" = @{"cpu" = "8"; "mem" = "28"; "disk" = "700" };
    "large"  = @{"cpu" = "16"; "mem" = "37"; "disk" = "1065" };
    "xlarge" = @{"cpu" = "24"; "mem" = "56"; "disk" = "1805" }
}

$esxiTotalCPU = 0
$vcsaTotalCPU = 0
$esxiTotalMemory = 0
$vcsaTotalMemory = 0
$esxiTotalStorage = 0
$vcsaTotalStorage = 0
$AVITotalStorage = 128

$StartTime = Get-Date

Function GetNetworkSubnetMaskByPrefixLength {
    param(
        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)
        ]
        [Alias('NetworkPrefixLength')]
        [String]$PrefixLength
    )

    $bitString = ('1' * $PrefixLength).PadRight(32, '0')

    $ipString = [String]::Empty

    # make 1 string combining a string for each byte and convert to int
    for ($i = 0; $i -lt 32; $i += 8) {
        $byteString = $bitString.Substring($i, 8)
        $ipString += "$([Convert]::ToInt32($byteString, 2))."
    }

    Return $ipString.TrimEnd('.')
}

Function Get-SSLThumbprint {
    param(
        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)
        ]
        [Alias('FullName')]
        [String]$URL
    )

    $Code = @'
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
namespace CertificateCapture
{
    public class Utility
    {
        public static Func<HttpRequestMessage,X509Certificate2,X509Chain,SslPolicyErrors,Boolean> ValidationCallback =
            (message, cert, chain, errors) => {
                var newCert = new X509Certificate2(cert);
                var newChain = new X509Chain();
                newChain.Build(newCert);
                CapturedCertificates.Add(new CapturedCertificate(){
                    Certificate =  newCert,
                    CertificateChain = newChain,
                    PolicyErrors = errors,
                    URI = message.RequestUri
                });
                return true;
            };
        public static List<CapturedCertificate> CapturedCertificates = new List<CapturedCertificate>();
    }
    public class CapturedCertificate
    {
        public X509Certificate2 Certificate { get; set; }
        public X509Chain CertificateChain { get; set; }
        public SslPolicyErrors PolicyErrors { get; set; }
        public Uri URI { get; set; }
    }
}
'@
    if ($PSEdition -ne 'Core') {
        Add-Type -AssemblyName System.Net.Http
        if (-not ("CertificateCapture" -as [type])) {
            Add-Type $Code -ReferencedAssemblies System.Net.Http
        }
    }
    else {
        if (-not ("CertificateCapture" -as [type])) {
            Add-Type $Code
        }
    }

    $Certs = [CertificateCapture.Utility]::CapturedCertificates

    $Handler = [System.Net.Http.HttpClientHandler]::new()
    $Handler.ServerCertificateCustomValidationCallback = [CertificateCapture.Utility]::ValidationCallback
    $Client = [System.Net.Http.HttpClient]::new($Handler)
    $Client.GetAsync($Url).Result | Out-Null

    $sha1 = [Security.Cryptography.SHA1]::Create()
    $certBytes = $Certs[-1].Certificate.GetRawCertData()
    $hash = $sha1.ComputeHash($certBytes)
    $thumbprint = [BitConverter]::ToString($hash).Replace('-', ':')
    return $thumbprint.toLower()
}

Function MyLogger {
    param(
        [Parameter(Mandatory = $true)][String]$message,
        [Parameter(Mandatory = $false)][String]$color = "green"
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_hh:mm:ss"

    Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
    Write-Host -ForegroundColor $color " $message"
    $logMessage = "[$timeStamp] $message"
    $logMessage | Out-File -Append -LiteralPath $verboseLogFile
}


Function New-vSphereSupervisor {
    <#
        .NOTES
        ===========================================================================
        Created by:    Keith Lee (based off William Lam's previous work)
        Date:          03/01/2025
        Organization:  Broadcom
        ===========================================================================

        .SYNOPSIS
            Enable vSphere Supervisor on vSphere 8 cluster using vSphere networking with AVI
        .DESCRIPTION
            Enable vSphere Supervisor on vSphere 8 cluster using vSphere networking with AVI
        .PARAMETER SupervisorClusterName
            Name of the Supervisor Cluster (default: svc-01)
        .PARAMETER ClusterName
            Name of vSphere Cluster to enable Workload Management
        .PARAMETER NestedvCenterServer
            Hostname/IP of the Nested vCenter Server
        .PARAMETER NestedvCenterServerUsername
            Username to connect to Nested vCenter Server
        .PARAMETER NestedvCenterServerPassword
            Password to connect to Nested vCenter Server
        .PARAMETER VKrContentLibrary
            Name of the vSphere Kubernetes releases subscribed Content Library
        .PARAMETER ControlPlaneSize
            Size of Control Plane VMs (TINY, SMALL, MEDIUM, LARGE)
        .PARAMETER MgmtNetwork
            Supervisor Management Network for Control Plane VMs
        .PARAMETER MgmtNetworkStartIP
            Starting IP Address for Control Plane VMs (5 consecutive free addresses)
        .PARAMETER MgmtNetworkSubnet
            Netmask for Management Network
        .PARAMETER MgmtNetworkGateway
            Gateway for Management Network
        .PARAMETER MgmtNetworkDNS
            DNS Server(s) to use for Management Network
        .PARAMETER MgmtNetworkDNSDomain
            DNS Domain(s) to use for Management Network
        .PARAMETER MgmtNetworkNTP
            NTP Server(s) to use for Management Network
        .PARAMETER WorkloadNetworkLabel
            Workload Network label defined in vSphere Supervisor (default: workload-1)
        .PARAMETER WorkloadNetwork
            Workload Network
        .PARAMETER WorkloadNetworkStartIP
            Starting IP Address for Workload VMs
        .PARAMETER WorkloadNetworkIPCount
            Number of IP Addresses to allocate from starting from WorkloadNetworkStartIP
        .PARAMETER WorkloadNetworkSubnet
            Subnet for Workload Network
        .PARAMETER WorkloadNetworkGateway
            Gateway for Workload Network
        .PARAMETER WorkloadNetworkDNS
            DNS Server(s) to use for Workloads
        .PARAMETER WorkloadNetworkDNSDomain
            DNS Domain(s) to use for Workloads
        .PARAMETER WorkloadNetworkNTP
            NTP Server(s) to use for Workloads
        .PARAMETER WorkloadNetworkServiceStartIP
            Starting IP Address for K8S Service (default: 10.96.0.0)
        .PARAMETER WorkloadNetworkServiceCount
            Number of IP Addrsses to allocate from WorkloadNetworkServiceStartIP (default: 256)
        .PARAMETER StoragePolicyName
            Name of VM Storage Policy to use for Control Plane VMs, Ephemeral Disks & Image Cache
        .EXAMPLE
            $vSphereSupervisorParams = @{                
                SupervisorClusterName = "svc-01";         
                NestedvCenterServer = "nested-vcenter.keithlee.lab"; 
                NestedvCenterServerUsername = "administrator@vsphere.local";
                NestedvCenterServerPassword = "VMware123!VMware123!";
                ClusterName = "tanzu-cluster";         
                VKrContentLibrary = "vkr-content-library"; 
                ControlPlaneSize = "TINY";                   
                MgmtNetwork = "dvpg-mgmt-network";         
                MgmtNetworkStartIP = "10.0.40.100";  
                MgmtNetworkPrefix = "24";              
                MgmtNetworkGateway = "10.0.40.1";   
                MgmtNetworkDNS = @("10.0.40.1");   
                MgmtNetworkDNSDomain = "keithlee.lab";  
                MgmtNetworkNTP = @("10.0.40.1"); 
                WorkloadNetworkLabel="workload-1";            
                WorkloadNetwork = "dvpg-workload-network";                
                WorkloadNetworkStartIP = "10.0.50.10";        
                WorkloadNetworkIPCount = 90;                  
                WorkloadNetworkPrefix = "24";                 
                WorkloadNetworkGateway = "10.0.50.1";       
                WorkloadNetworkDNS = @("10.0.50.1");         
                WorkloadNetworkDNSDomain = "keithlee.lab";    
                WorkloadNetworkNTP = @("10.0.50.1");    
                WorkloadNetworkServiceStartIP = "10.96.0.0";
                WorkloadNetworkServiceStartCount = "256";       
                AVIIPAddress = "10.0.40.20";   
                AVIPort = "443";                
                AVICertName = "avi-cert"      
                AVIUsername = "admin";          
                AVIPassword = "VMware123!VMware123!";
                StoragePolicyName = "wcp-storage-policy";
				EnableDebug = $true;
            }

            New-vSphereSupervisor @vSphereSupervisorParams
    #>
	
    Param (
        [Parameter(Mandatory=$True)][string]$SupervisorClusterName,
        [Parameter(Mandatory=$True)][string]$NestedvCenterServer,
        [Parameter(Mandatory=$True)][string]$NestedvCenterServerUsername,
        [Parameter(Mandatory=$True)][string]$NestedvCenterServerPassword,
        [Parameter(Mandatory=$True)][string]$ClusterName,
        [Parameter(Mandatory=$True)][string]$VKrContentLibrary,
        [Parameter(Mandatory=$True)][ValidateSet("TINY","SMALL","MEDIUM","LARGE")][string]$ControlPlaneSize,
        [Parameter(Mandatory=$False)]$MgmtNetwork,
        [Parameter(Mandatory=$True)][string]$MgmtNetworkStartIP,
        [Parameter(Mandatory=$True)][string]$MgmtNetworkPrefix,
        [Parameter(Mandatory=$True)][string]$MgmtNetworkGateway,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkDNS,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkDNSDomain,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkNTP,
        [Parameter(Mandatory=$False)][string]$WorkloadNetworkLabel, 
        [Parameter(Mandatory=$False)][string]$WorkloadNetwork,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkStartIP,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkIPCount,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkPrefix,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkGateway,
        [Parameter(Mandatory=$True)][string[]]$WorkloadNetworkDNS,
        [Parameter(Mandatory=$True)][string[]]$WorkloadNetworkDNSDomain,
        [Parameter(Mandatory=$True)][string[]]$WorkloadNetworkNTP,
        [Parameter(Mandatory=$False)][string]$WorkloadNetworkServiceStartIP,
        [Parameter(Mandatory=$False)][string]$WorkloadNetworkServiceStartCount,
        [Parameter(Mandatory=$True)][string]$AVIIPAddress,
        [Parameter(Mandatory=$True)][string]$AVIUsername,
        [Parameter(Mandatory=$True)][string]$AVIPassword,
        [Parameter(Mandatory=$False)][string]$AVIPort,
        [Parameter(Mandatory=$True)][string]$AVICertName,
        [Parameter(Mandatory=$True)]$StoragePolicyName,
        [Switch]$EnableDebug
    )
	

    # Retrieve TLS certificate from AVI Controller using basic auth
    $pair = "${AVIUsername}:${AVIPassword}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)

    $headers = @{
        "Authorization" = "basic $base64";
        "Content-Type"  = "application/json";
        "Accept"        = "application/json";
        "x-avi-version" = $AVIVersion;
    }

    try {
        MyLogger "Extracting TLS certificate from AVI Controller ${AVIIPAddress} ..."
        $certResult = ((Invoke-WebRequest -Uri https://${AVIIPAddress}/api/sslkeyandcertificate?include_name -Method GET -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json).results | where {$_.name -eq $AVICertName}
    } catch {
        Write-Host -ForegroundColor Red "Error in extracting TLS certificate"
        Write-Error "`n($_.Exception.Message)`n"
        break
    }

    $aviCert = $certResult.certificate.certificate
    if($aviCert -eq $null) {
        Write-Host -ForegroundColor Red "Unable to locate TLS certificate in AVI Controller named ${AVICertName}"
        break
    }


    MyLogger "Connecting to Nested vCenter Server to enable vSphere Supervisor ..."
    Connect-VIServer $NestedvCenterServer -User $NestedvCenterServerUsername -Password $NestedvCenterServerPassword -WarningAction SilentlyContinue -Force | Out-Null

    if( (Get-ContentLibrary -Name $VKrContentLibrary).syncdate -eq $NULL ) {
        MyLogger "VKr Content Library has not fully sync'ed, please try again later"
        Disconnect-VIServer * -Confirm:$false
        break
    } else {
		Connect-CisServer $NestedvCenterServer -User $NestedvCenterServerUsername -Password $NestedvCenterServerPassword -WarningAction SilentlyContinue -Force | Out-Null

        # Cluster Moref
        $clusterService = Get-CisService "com.vmware.vcenter.cluster"
        $clusterFilterSpec = $clusterService.help.list.filter.Create()
        $clusterFilterSpec.names = @("$ClusterName")
        $clusterMoRef = $clusterService.list($clusterFilterSpec).cluster.Value
        if ($clusterMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Cluster ${ClusterName}"
            break
        }

        # Management Network Moref
        $networkService = Get-CisService "com.vmware.vcenter.network"
        $networkFilterSpec = $networkService.help.list.filter.Create()
        $networkFilterSpec.names = @("$MgmtNetwork")
        $mgmtNetworkMoRef = $networkService.list($networkFilterSpec).network.Value
        if ($mgmtNetworkMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Management Network ${MgmtNetwork}"
            break
        }

        # Workload Network Moref
        $networkFilterSpec = $networkService.help.list.filter.Create()
        $networkFilterSpec.names = @("$WorkloadNetwork")
        $workloadNetworkMoRef = $networkService.list($networkFilterSpec).network.Value
        if ($workloadNetworkMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Workload Network ${WorkloadNetwork}"
            break
        }

        $storagePolicyService = Get-CisService "com.vmware.vcenter.storage.policies"
        $sps= $storagePolicyService.list()
        $supervisorSP = ($sps | where {$_.name -eq $StoragePolicyName}).Policy.Value

        $vsphereSupervisor = Get-CisService "com.vmware.vcenter.namespace_management.supervisors"
        $spec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.Create()
        $spec.name = $SupervisorClusterName

        ## Control Plane Spec ##
        $cpNetworkSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.control_plane.network.Create()
        $cpNetworkSpec.network = $mgmtNetworkMoRef

        # Backing Network
        $backingSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.control_plane.network.backing.Create()
        $backingSpec.backing = "NETWORK"
        $backingSpec.network = $mgmtNetworkMoRef
        $cpNetworkSpec.backing = $backingSpec

        # IP Management
        $cpIpMgmtSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.control_plane.network.ip_management.Create()
        $cpIpMgmtSpec.dhcp_enabled = $False

        $cpRangeSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.control_plane.network.ip_management.ip_assignments.Element.ranges.Element.Create()
        $cpRangeSpec.address = $MgmtNetworkStartIP
        $cpRangeSpec.count = 5

        $cpIpMgmtSpec.gateway_address = "$MgmtNetworkGateway/$MgmtNetworkPrefix"
        $cpIpAssignmentSpec =  $vsphereSupervisor.Help.enable_on_compute_cluster.spec.control_plane.network.ip_management.ip_assignments.Element.Create()
        $cpIpAssignmentSpec.assignee = "NODE"
        $cpIpAssignmentSpec.ranges = @($cpRangeSpec)
        $cpIpMgmtSpec.ip_assignments = @($cpIpAssignmentSpec)
        $cpNetworkSpec.ip_management = $cpIpMgmtSpec
        
        # Services (DNS & NTP)
        $cpServiceSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.control_plane.network.services.Create()
        $cpDnsSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.control_plane.network.services.dns.Create()
        $cpDnsSpec.servers = @($MgmtNetworkDNS)
        $cpDnsSpec.search_domains = @($MgmtNetworkDNSDomain)
        $cpServiceSpec.dns = $cpDnsSpec
        $cpNtpSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.control_plane.network.services.ntp.Create()
        $cpNtpSpec.servers = @($MgmtNetworkNTP)
        $cpServiceSpec.ntp = $cpNtpSpec
        $cpNetworkSpec.services = $cpServiceSpec

        $spec.control_plane.network = $cpNetworkSpec
        $spec.control_plane.size = $ControlPlaneSize
        $spec.control_plane.storage_policy = $supervisorSP

        ## Workloads Spec ##
        $wlSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.Create()

        # Network
        $wlNetworkSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.network.Create()
        $wlNetworkSpec.network_type = "VSPHERE"
        $wlNetworkSpec.network = $WorkloadNetworkLabel #If unset, an ID will be generated.
        $vsphereNetworkSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.network.vsphere.Create()
        $vsphereNetworkSpec.dvpg = $workloadNetworkMoRef
        $wlNetworkSpec.vsphere = $vsphereNetworkSpec

        # Services (DNS & NTP)
        $wlServiceSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.network.services.Create()
        $wlDnsSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.network.services.dns.Create()
        $wlDnsSpec.servers = @($WorkloadNetworkDNS)
        $wlDnsSpec.search_domains = @($WorkloadNetworkDNSDomain)
        $wlServiceSpec.dns = $wlDnsSpec
        $wlNtpSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.network.services.ntp.Create()
        $wlNtpSpec.servers = $WorkloadNetworkNTP
        $wlServiceSpec.ntp = $wlNtpSpec
        $wlNetworkSpec.services = $wlServiceSpec

        # Workload & Workload Service IP Management
        $wlIpMgmtSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.network.ip_management.Create()
        $wlIpMgmtSpec.dhcp_enabled = $False
        $wlIpMgmtSpec.gateway_address = "$WorkloadNetworkGateway/$WorkloadNetworkPrefix"

        $wlIpAssignmentSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.network.ip_management.ip_assignments.Element.Create()
        $wlRangeSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.network.ip_management.ip_assignments.Element.ranges.Element.Create()
        $wlRangeSpec.address = $WorkloadNetworkStartIP
        $wlRangeSpec.count = $WorkloadNetworkIPCount
        $wlIpAssignmentSpec.ranges = @($wlRangeSpec)
        $wlIpAssignmentSpec.assignee = "NODE"

        $wlServiceIpAssignmentSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.network.ip_management.ip_assignments.Element.Create()
        $wlServiceRangeSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.network.ip_management.ip_assignments.Element.ranges.Element.Create()
        $wlServiceRangeSpec.address = $WorkloadNetworkServiceStartIP
        $wlServiceRangeSpec.count = $WorkloadNetworkServiceStartCount
        $wlServiceIpAssignmentSpec.ranges = @($wlServiceRangeSpec)
        $wlServiceIpAssignmentSpec.assignee = "SERVICE"

        $wlIpMgmtSpec.ip_assignments = @($wlIpAssignmentSpec, $wlServiceIpAssignmentSpec)
        $wlNetworkSpec.ip_management = $wlIpMgmtSpec

        $wlSpec.network = $wlNetworkSpec

        # Edge
        $wlEdgeSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.edge.Create()      
        $wlEdgeSpec.provider = "NSX_ADVANCED"    

        $nsxAlbServerSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.edge.nsx_advanced.server.Create()
        $nsxAlbServerSpec.host = $AVIIPAddress
        $nsxAlbServerSpec.port = $AVIPort
		$nsxAlbSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.edge.nsx_advanced.Create()
        $nsxAlbSpec.server = $nsxAlbServerSpec
        $nsxAlbSpec.username = $AVIUsername
        $nsxAlbSpec.password = [VMware.VimAutomation.Cis.Core.Types.V1.Secret]$AVIPassword
        $nsxAlbSpec.certificate_authority_chain = $aviCert
        #$nsxAlbSpec.cloudname #Only set if custom cloud name is configured for this Avi Controller. If unset, it defaults to "Default-Cloud".
        $wlEdgeSpec.nsx_advanced = $nsxAlbSpec

        $wlSpec.edge = $wlEdgeSpec

        # Images
        $wlImagesSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.images.Create()
        $wlImagesSpec.kubernetes_content_library = (Get-ContentLibrary -Name $VKrContentLibrary)[0].id
        $wlSpec.images = $wlImagesSpec

        # Storage
        $wlStorageSpec = $vsphereSupervisor.Help.enable_on_compute_cluster.spec.workloads.storage.Create()
        $wlStorageSpec.ephemeral_storage_policy = $supervisorSP 
        $wlStorageSpec.image_storage_policy = $supervisorSP 
        $wlSpec.storage = $wlStorageSpec

        $spec.workloads = $wlSpec
        
        # Output JSON payload
        if($EnableDebug) {
            $spec | ConvertTo-Json -Depth 10
        }

        try {
            MyLogger "Enabling vSphere Supervisor on vSphere Cluster ${ClusterName} ..."
            $task = $vsphereSupervisor.enable_on_compute_cluster($clusterMoRef,$spec)
        } catch {
            Write-host -ForegroundColor red "Error in attempting to enable vSphere Supervisor on vSphere Cluster ${ClusterName}"
            Write-host -ForegroundColor red "($_.Exception.Message)"
            Disconnect-VIServer * -Confirm:$false | Out-Null
            Disconnect-CisServer $global:DefaultCisServers -Confirm:$false | Out-Null
            break
        }
        MyLogger "Please refer to the Workload Management UI in vCenter Server to monitor the progress of this operation. It can take up to approximately 30 minutes to complete"

        MyLogger "Disconnecting from Nested vCenter Server ..."
        Disconnect-VIServer * -Confirm:$false | Out-Null
        Disconnect-CisServer $global:DefaultCisServers -Confirm:$false | Out-Null
    }
}

if ($preCheck -eq 1) {
    if (!(Test-Path $NestedESXiApplianceOVA)) {
        Write-Host -ForegroundColor Red "`nUnable to find $NestedESXiApplianceOVA ...`n"
        exit
    }

    if (!(Test-Path $VCSAInstallerPath)) {
        Write-Host -ForegroundColor Red "`nUnable to find $VCSAInstallerPath ...`n"
        exit
    }

    if (!(Test-Path $AVIOVA) -and $deployAVI -eq 1) {
        Write-Host -ForegroundColor Red "`nUnable to find $AVIOVA ...`n"
        exit
    }

    if ($PSVersionTable.PSEdition -ne "Core") {
        Write-Host -ForegroundColor Red "`tPowerShell Core was not detected, please install that before continuing ... `n"
        exit
    }
}

if ($confirmDeployment -eq 1) {
    Write-Host -ForegroundColor Magenta "`nPlease confirm the following configuration will be deployed:`n"

    Write-Host -ForegroundColor Yellow "---- Nested vSphere Lab Deployment Configuration ---- "
    Write-Host -NoNewline -ForegroundColor Green "Nested ESXi Image Path: "
    Write-Host -ForegroundColor White $NestedESXiApplianceOVA
    Write-Host -NoNewline -ForegroundColor Green "VCSA Image Path: "
    Write-Host -ForegroundColor White $VCSAInstallerPath
    Write-Host -NoNewline -ForegroundColor Green "AVI Image Path: "
    Write-Host -ForegroundColor White $AVIOVA

    Write-Host -ForegroundColor Yellow "`n---- vCenter Server Deployment Target Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "vCenter Server Address: "
    Write-Host -ForegroundColor White $VIServer
    Write-Host -NoNewline -ForegroundColor Green "VM Network: "
    Write-Host -ForegroundColor White $VMNetwork

    Write-Host -NoNewline -ForegroundColor Green "VM Storage: "
    Write-Host -ForegroundColor White $VMDatastore
    Write-Host -NoNewline -ForegroundColor Green "VM Cluster: "
    Write-Host -ForegroundColor White $VMCluster
    Write-Host -NoNewline -ForegroundColor Green "VM vApp: "
    Write-Host -ForegroundColor White $VAppName

    Write-Host -ForegroundColor Yellow "`n---- vESXi Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "# of Nested ESXi VMs: "
    Write-Host -ForegroundColor White $NestedESXiHostnameToIPs.count
    Write-Host -NoNewline -ForegroundColor Green "vCPU: "
    Write-Host -ForegroundColor White $NestedESXivCPU
    Write-Host -NoNewline -ForegroundColor Green "vMEM: "
    Write-Host -ForegroundColor White "$NestedESXivMEM GB"
    Write-Host -NoNewline -ForegroundColor Green "Caching VMDK: "
    Write-Host -ForegroundColor White "$NestedESXiCachingvDisk GB"
    Write-Host -NoNewline -ForegroundColor Green "Capacity VMDK: "
    Write-Host -ForegroundColor White "$NestedESXiCapacityvDisk GB"
    Write-Host -NoNewline -ForegroundColor Green "IP Address(s): "
    Write-Host -ForegroundColor White $NestedESXiHostnameToIPs.Values
    Write-Host -NoNewline -ForegroundColor Green "Netmask "
    Write-Host -ForegroundColor White $VMNetmask
    Write-Host -NoNewline -ForegroundColor Green "Gateway: "
    Write-Host -ForegroundColor White $VMGateway
    Write-Host -NoNewline -ForegroundColor Green "DNS: "
    Write-Host -ForegroundColor White $VMDNS
    Write-Host -NoNewline -ForegroundColor Green "NTP: "
    Write-Host -ForegroundColor White $VMNTP
    Write-Host -NoNewline -ForegroundColor Green "Syslog: "
    Write-Host -ForegroundColor White $VMSyslog
    Write-Host -NoNewline -ForegroundColor Green "Enable SSH: "
    Write-Host -ForegroundColor White $VMSSH
    Write-Host -NoNewline -ForegroundColor Green "Create VMFS Volume: "
    Write-Host -ForegroundColor White $VMVMFS

    Write-Host -ForegroundColor Yellow "`n---- VCSA Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "Deployment Size: "
    Write-Host -ForegroundColor White $VCSADeploymentSize
    Write-Host -NoNewline -ForegroundColor Green "SSO Domain: "
    Write-Host -ForegroundColor White $VCSASSODomainName
    Write-Host -NoNewline -ForegroundColor Green "Enable SSH: "
    Write-Host -ForegroundColor White $VCSASSHEnable
    Write-Host -NoNewline -ForegroundColor Green "Hostname: "
    Write-Host -ForegroundColor White $VCSAHostname
    Write-Host -NoNewline -ForegroundColor Green "IP Address: "
    Write-Host -ForegroundColor White $VCSAIPAddress
    Write-Host -NoNewline -ForegroundColor Green "Netmask "
    Write-Host -ForegroundColor White $VMNetmask
    Write-Host -NoNewline -ForegroundColor Green "Gateway: "
    Write-Host -ForegroundColor White $VMGateway

    Write-Host -ForegroundColor Yellow "`n---- AVI Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "Hostname: "
    Write-Host -ForegroundColor White $AVIHostname
    Write-Host -NoNewline -ForegroundColor Green "Management IP Address: "
    Write-Host -ForegroundColor White $AVIManagementIPAddress
    Write-Host -ForegroundColor Green "Service Engine: "
    Write-Host -NoNewline -ForegroundColor Green "   Portgroup: "
    Write-Host -ForegroundColor White $VMNetwork
    Write-Host -NoNewline -ForegroundColor Green "   Network: "
    Write-Host -ForegroundColor White $AVIManagementNetwork/$AVIManagementNetworkPrefix
    Write-Host -NoNewline -ForegroundColor Green "   Range: "
    Write-Host -ForegroundColor White "$AVIManagementNetworkStartRange to $AVIManagementNetworkEndRange"
    Write-Host -ForegroundColor Green "VIP: "
    Write-Host -NoNewline -ForegroundColor Green "   Portgroup: "
    Write-Host -ForegroundColor White $VIPNetworkName
    Write-Host -NoNewline -ForegroundColor Green "   Network: "
    Write-Host -ForegroundColor White $AVIVIPNetwork/$AVIVIPNetworkPrefix
    Write-Host -NoNewline -ForegroundColor Green "   Range: "
    Write-Host -ForegroundColor White "$AVIVIPNetworkStartRange to $AVIVIPNetworkEndRange"

    $esxiTotalCPU = $NestedESXiHostnameToIPs.count * [int]$NestedESXivCPU
    $esxiTotalMemory = $NestedESXiHostnameToIPs.count * [int]$NestedESXivMEM
    $esxiTotalStorage = ($NestedESXiHostnameToIPs.count * [int]$NestedESXiCachingvDisk) + ($NestedESXiHostnameToIPs.count * [int]$NestedESXiCapacityvDisk)
    $vcsaTotalCPU = $vcsaSize2MemoryStorageMap.$VCSADeploymentSize.cpu
    $vcsaTotalMemory = $vcsaSize2MemoryStorageMap.$VCSADeploymentSize.mem
    $vcsaTotalStorage = $vcsaSize2MemoryStorageMap.$VCSADeploymentSize.disk

    Write-Host -ForegroundColor Yellow "`n---- Resource Requirements ----"
    Write-Host -NoNewline -ForegroundColor Green "ESXi VM CPU: "
    Write-Host -NoNewline -ForegroundColor White $esxiTotalCPU
    Write-Host -NoNewline -ForegroundColor Green "   ESXi VM Memory: "
    Write-Host -NoNewline -ForegroundColor White $esxiTotalMemory "GB "
    Write-Host -NoNewline -ForegroundColor Green "  ESXi VM Storage: "
    Write-Host -ForegroundColor White $esxiTotalStorage "GB"
    Write-Host -NoNewline -ForegroundColor Green "VCSA VM CPU: "
    Write-Host -NoNewline -ForegroundColor White $vcsaTotalCPU
    Write-Host -NoNewline -ForegroundColor Green "    VCSA VM Memory: "
    Write-Host -NoNewline -ForegroundColor White $vcsaTotalMemory "GB "
    Write-Host -NoNewline -ForegroundColor Green "   VCSA VM Storage: "
    Write-Host -ForegroundColor White $vcsaTotalStorage "GB"
    Write-Host -NoNewline -ForegroundColor Green "AVI  VM CPU: "
    Write-Host -NoNewline -ForegroundColor White $AVIvCPU
    Write-Host -NoNewline -ForegroundColor Green "     AVI VM Memory: "
    Write-Host -NoNewline -ForegroundColor White $AVIvMEM "GB "
    Write-Host -NoNewline -ForegroundColor Green "    AVI VM Storage: "
    Write-Host -ForegroundColor White $AVITotalStorage "GB"

    Write-Host -ForegroundColor White "---------------------------------------------"
    Write-Host -NoNewline -ForegroundColor Green "Total CPU: "
    Write-Host -ForegroundColor White ($esxiTotalCPU + $vcsaTotalCPU + $nsxManagerTotalCPU + $AVIvCPU)
    Write-Host -NoNewline -ForegroundColor Green "Total Memory: "
    Write-Host -ForegroundColor White ($esxiTotalMemory + $vcsaTotalMemory + $AVIvMEM) "GB"
    Write-Host -NoNewline -ForegroundColor Green "Total Storage: "
    Write-Host -ForegroundColor White ($esxiTotalStorage + $vcsaTotalStorage + $AVITotalStorage) "GB"

    Write-Host -ForegroundColor Magenta "`nWould you like to proceed with this deployment?`n"
    $answer = Read-Host -Prompt "Do you accept (Y or N)"
    if ($answer -ne "Y" -or $answer -ne "y") {
        exit
    }
    Clear-Host
}

if ($deployNestedESXiVMs -eq 1 -or $deployVCSA -eq 1 -or $deployAVI -eq 1) {
    MyLogger "Connecting to Management vCenter Server $VIServer ..."
    $viConnection = Connect-VIServer $VIServer -User $VIUsername -Password $VIPassword -WarningAction SilentlyContinue -Force

    $datastore = Get-Datastore -Server $viConnection -Name $VMDatastore | Select-Object -First 1
    $cluster = Get-Cluster -Server $viConnection -Name $VMCluster
    $ResourcePool = Get-ResourcePool -Server $viConnection -Name $VMResourcePool -Location $cluster
    $datacenter = $cluster | Get-Datacenter
    $vmhost = $cluster | Get-VMHost | Select-Object -First 1
}

if ($deployNestedESXiVMs -eq 1) {
    $NestedESXiHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
        $VMName = $_.Key
        $VMIPAddress = $_.Value

        $ovfconfig = Get-OvfConfiguration $NestedESXiApplianceOVA
        $networkMapLabel = ($ovfconfig.ToHashTable().keys | Where-Object { $_ -Match "NetworkMapping" }).replace("NetworkMapping.", "").replace("-", "_").replace(" ", "_")
        $ovfconfig.NetworkMapping.$networkMapLabel.value = $VMNetwork

        $ovfconfig.common.guestinfo.hostname.value = $VMName
        $ovfconfig.common.guestinfo.ipaddress.value = $VMIPAddress
        $ovfconfig.common.guestinfo.netmask.value = $VMNetmask
        $ovfconfig.common.guestinfo.gateway.value = $VMGateway
        $ovfconfig.common.guestinfo.dns.value = $VMDNS
        $ovfconfig.common.guestinfo.domain.value = $VMDomain
        $ovfconfig.common.guestinfo.ntp.value = $VMNTP
        $ovfconfig.common.guestinfo.syslog.value = $VMSyslog
        $ovfconfig.common.guestinfo.password.value = $VMPassword
        if ($VMSSH -eq "true") {
            $VMSSHVar = $true
        }
        else {
            $VMSSHVar = $false
        }
        $ovfconfig.common.guestinfo.ssh.value = $VMSSHVar

        MyLogger "Deploying Nested ESXi VM $VMName ..."
        $vm = Import-VApp -Source $NestedESXiApplianceOVA -OvfConfiguration $ovfconfig -Name $VMName -Location $ResourcePool -InventoryLocation $VMFolder -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin -Force

        MyLogger "Adding vmnic2/vmnic3/vmnic4 for $VMNetwork/$WorkloadNetwork/$VIPNetworkName to passthrough to Nested ESXi VMs ..."

        <#
		code to use vDS portgroups intead of vSwitch
        $VMNetworkPorgroup = Get-VDPortgroup $VMNetwork
        $WorkloadNetworkPortgroup = Get-VDPortgroup $WorkloadNetwork
        $AVIVIPNetworkPortgroup = Get-VDPortgroup $VIPNetworkName

        New-NetworkAdapter -VM $vm -Type Vmxnet3 -Portgroup $VMNetworkPorgroup -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        New-NetworkAdapter -VM $vm -Type Vmxnet3 -Portgroup $WorkloadNetworkPortgroup -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        New-NetworkAdapter -VM $vm -Type Vmxnet3 -Portgroup $AVIVIPNetworkPortgroup -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
		#>
		
		#code to use vSwitch networks
		New-NetworkAdapter -VM $vm -Type Vmxnet3 -NetworkName $VMNetwork -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        New-NetworkAdapter -VM $vm -Type Vmxnet3 -NetworkName $WorkloadNetwork -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
		New-NetworkAdapter -VM $vm -Type Vmxnet3 -NetworkName $VIPNetworkName -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        $vm | New-AdvancedSetting -name "ethernet2.filter4.name" -value "dvfilter-maclearn" -confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile
        $vm | New-AdvancedSetting -Name "ethernet2.filter4.onFailure" -value "failOpen" -confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile

        $vm | New-AdvancedSetting -name "ethernet3.filter4.name" -value "dvfilter-maclearn" -confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile
        $vm | New-AdvancedSetting -Name "ethernet3.filter4.onFailure" -value "failOpen" -confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile

        MyLogger "Updating vCPU Count to $NestedESXivCPU & vMEM to $NestedESXivMEM GB ..."
        Set-VM -Server $viConnection -VM $vm -NumCpu $NestedESXivCPU -MemoryGB $NestedESXivMEM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        MyLogger "Updating vSAN Cache VMDK size to $NestedESXiCachingvDisk GB & Capacity VMDK size to $NestedESXiCapacityvDisk GB ..."
        Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $NestedESXiCachingvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $NestedESXiCapacityvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        MyLogger "Powering on $vmname ..."
        $vm | Start-Vm -RunAsync | Out-Null
    }
}

if ($deployAVI -eq 1) {
    $ovfconfig = Get-OvfConfiguration $AVIOVA

    $ovfconfig.NetworkMapping.Management.value = $VMNetwork
    $ovfconfig.avi.CONTROLLER.mgmt_ip.value = $AVIManagementIPAddress

    $ovfconfig.avi.CONTROLLER.mgmt_mask.value = GetNetworkSubnetMaskByPrefixLength($AVIManagementNetworkPrefix)
    $ovfconfig.avi.CONTROLLER.default_gw.value = $VMGateway

    MyLogger "Deploying AVI Controller VM $AVIDisplayName ..."
    $vm = Import-VApp -Source $AVIOVA -OvfConfiguration $ovfconfig -Name $AVIDisplayName -Location $ResourcePool -InventoryLocation $VMFolder -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin -Force

    MyLogger "Updating vCPU Count to $AVIvCPU & vMEM to $AVIvMEM GB ..."
    Set-VM -Server $viConnection -VM $vm -NumCpu $AVIvCPU -MemoryGB $AVIvMEM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

    MyLogger "Powering on $AVIDisplayName ..."
    $vm | Start-Vm -RunAsync | Out-Null
}

if ($deployVCSA -eq 1) {
    if ($IsWindows) {
        $config = (Get-Content -Raw "$($VCSAInstallerPath)\vcsa-cli-installer\templates\install\embedded_vCSA_on_VC.json") | convertfrom-json
    }
    else {
        $config = (Get-Content -Raw "$($VCSAInstallerPath)/vcsa-cli-installer/templates/install/embedded_vCSA_on_VC.json") | convertfrom-json
    }

    $config.'new_vcsa'.vc.hostname = $VIServer
    $config.'new_vcsa'.vc.username = $VIUsername
    $config.'new_vcsa'.vc.password = $VIPassword
    $config.'new_vcsa'.vc.deployment_network = $VMNetwork
    $config.'new_vcsa'.vc.datastore = $datastore.Name
    $config.'new_vcsa'.vc.datacenter = $datacenter.Name
    $config.'new_vcsa'.vc.target = @($VMCluster, "Resources", $ResourcePool.Name)
    $config.'new_vcsa'.appliance.thin_disk_mode = $true
    $config.'new_vcsa'.appliance.deployment_option = $VCSADeploymentSize
    $config.'new_vcsa'.appliance.name = $VCSADisplayName
    $config.'new_vcsa'.network.ip_family = "ipv4"
    $config.'new_vcsa'.network.mode = "static"
    $config.'new_vcsa'.network.ip = $VCSAIPAddress
    $config.'new_vcsa'.network.dns_servers[0] = $VMDNS
    $config.'new_vcsa'.network.prefix = $VCSAPrefix
    $config.'new_vcsa'.network.gateway = $VMGateway
    $config.'new_vcsa'.os.ntp_servers = $VMNTP
    $config.'new_vcsa'.network.system_name = $VCSAHostname
    $config.'new_vcsa'.os.password = $VCSARootPassword

    $vcsaConfigOvftoolArgs = @{
        "prop:vami.domain.VMware-vCenter-Server-Appliance"      = $VMDomain;
        "prop:vami.searchpath.VMware-vCenter-Server-Appliance"  = $VMSearchPath;
    }

    $config.'new_vcsa' | Add-Member -MemberType NoteProperty -Name ovftool_arguments -Value $vcsaConfigOvftoolArgs


    if ($VCSASSHEnable -eq "true") {
        $VCSASSHEnableVar = $true
    }
    else {
        $VCSASSHEnableVar = $false
    }
    $config.'new_vcsa'.os.ssh_enable = $VCSASSHEnableVar
    $config.'new_vcsa'.sso.password = $VCSASSOPassword
    $config.'new_vcsa'.sso.domain_name = $VCSASSODomainName

    if ($IsWindows) {
        MyLogger "Creating VCSA JSON configuration file for deployment ..."
        $config | ConvertTo-Json -Depth 3 | Set-Content -Path "$($ENV:Temp)\jsontemplate.json"

        MyLogger "Deploying the VCSA ..."
        Invoke-Expression "$($VCSAInstallerPath)\vcsa-cli-installer\win32\vcsa-deploy.exe install --no-esx-ssl-verify --accept-eula --acknowledge-ceip $($ENV:Temp)\jsontemplate.json" | Out-File -Append -LiteralPath $verboseLogFile
    }
    elseif ($IsMacOS) {
        MyLogger "Creating VCSA JSON configuration file for deployment ..."
        $config | ConvertTo-Json -Depth 3 | Set-Content -Path "$($ENV:TMPDIR)jsontemplate.json"

        MyLogger "Deploying the VCSA ..."
        Invoke-Expression "$($VCSAInstallerPath)/vcsa-cli-installer/mac/vcsa-deploy install --no-esx-ssl-verify --accept-eula --acknowledge-ceip $($ENV:TMPDIR)jsontemplate.json" | Out-File -Append -LiteralPath $verboseLogFile
    }
    elseif ($IsLinux) {
        MyLogger "Creating VCSA JSON configuration file for deployment ..."
        $config | ConvertTo-Json -Depth 3 | Set-Content -Path "/tmp/jsontemplate.json"

        MyLogger "Deploying the VCSA ..."
        Invoke-Expression "$($VCSAInstallerPath)/vcsa-cli-installer/lin64/vcsa-deploy install --no-esx-ssl-verify --accept-eula --acknowledge-ceip /tmp/jsontemplate.json" | Out-File -Append -LiteralPath $verboseLogFile
    }
}

if ($moveVMsIntovApp -eq 1) {
    # Check whether DRS is enabled as that is required to create vApp
    if ((Get-Cluster -Server $viConnection $cluster).DrsEnabled) {
        MyLogger "Creating vApp $VAppName ..."
        $VApp = New-VApp -Name $VAppName -Server $viConnection -Location $cluster

        if (-Not (Get-Folder $VMFolder -ErrorAction Ignore)) {
            MyLogger "Creating VM Folder $VMFolder ..."
            New-Folder -Name $VMFolder -Server $viConnection -Location (Get-Datacenter $VMDatacenter | Get-Folder vm) | Out-Null
        }

        if ($deployNestedESXiVMs -eq 1) {
            MyLogger "Moving Nested ESXi VMs into $VAppName vApp ..."
            $NestedESXiHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
                $vm = Get-VM -Name $_.Key -Server $viConnection
                Move-VM -VM $vm -Server $viConnection -Destination $VApp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            }
        }

        if ($deployVCSA -eq 1) {
            $vcsaVM = Get-VM -Name $VCSADisplayName -Server $viConnection
            MyLogger "Moving $VCSADisplayName into $VAppName vApp ..."
            Move-VM -VM $vcsaVM -Server $viConnection -Destination $VApp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }

        if ($deployAVI -eq 1) {
            $AVIVM = Get-VM -Name $AVIDisplayName -Server $viConnection
            MyLogger "Moving $AVIDisplayName into $VAppName vApp ..."
            Move-VM -VM $AVIVM -Server $viConnection -Destination $VApp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }

        MyLogger "Moving $VAppName to VM Folder $VMFolder ..."
        Move-VApp -Server $viConnection $VAppName -Destination (Get-Folder -Server $viConnection $VMFolder) | Out-File -Append -LiteralPath $verboseLogFile
    }
    else {
        MyLogger "vApp $VAppName will NOT be created as DRS is NOT enabled on vSphere Cluster ${cluster} ..."
    }
}

if ($deployNestedESXiVMs -eq 1 -or $deployVCSA -eq 1 -or $deployAVI -eq 1) {
    MyLogger "Disconnecting from $VIServer ..."
    Disconnect-VIServer * -Confirm:$false
}

if ($setupNewVC -eq 1) {
    MyLogger "Connecting to the new VCSA ..."
    $vc = Connect-VIServer $VCSAIPAddress -User "administrator@$VCSASSODomainName" -Password $VCSASSOPassword -WarningAction SilentlyContinue -Force

    $d = Get-Datacenter -Server $vc $NewVCDatacenterName -ErrorAction Ignore
    if (-Not $d) {
        MyLogger "Creating Datacenter $NewVCDatacenterName ..."
        New-Datacenter -Server $vc -Name $NewVCDatacenterName -Location (Get-Folder -Type Datacenter -Server $vc) | Out-File -Append -LiteralPath $verboseLogFile
    }

    $c = Get-Cluster -Server $vc $NewVCVSANClusterName -ErrorAction Ignore
    if (-Not $c) {
        MyLogger "Creating vSAN Cluster $NewVCVSANClusterName ..."
        New-Cluster -Server $vc -Name $NewVCVSANClusterName -Location (Get-Datacenter -Name $NewVCDatacenterName -Server $vc) -DrsEnabled -HAEnabled -VsanEnabled | Out-File -Append -LiteralPath $verboseLogFile

        (Get-Cluster $NewVCVSANClusterName) | New-AdvancedSetting -Name "das.ignoreRedundantNetWarning" -Type ClusterHA -Value $true -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
    }

    if ($addESXiHostsToVC -eq 1) {
        $NestedESXiHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
            $VMName = $_.Key
            $VMIPAddress = $_.Value

            $targetVMHost = $VMIPAddress
            if ($addHostByDnsName -eq 1) {
                $targetVMHost = "$VMName.$VMDomain"
            }
            MyLogger "Adding ESXi host $targetVMHost to Cluster ..."
            Add-VMHost -Server $vc -Location (Get-Cluster -Name $NewVCVSANClusterName) -User "root" -Password $VMPassword -Name $targetVMHost -Force | Out-File -Append -LiteralPath $verboseLogFile
        }

        $haRuntime = (Get-Cluster $NewVCVSANClusterName).ExtensionData.RetrieveDasAdvancedRuntimeInfo
        $totalHaHosts = $haRuntime.TotalHosts
        $totalHaGoodHosts = $haRuntime.TotalGoodHosts
        while ($totalHaGoodHosts -ne $totalHaHosts) {
            MyLogger "Waiting for vSphere HA configuration to complete ..."
            Start-Sleep -Seconds 60
            $haRuntime = (Get-Cluster $NewVCVSANClusterName).ExtensionData.RetrieveDasAdvancedRuntimeInfo
            $totalHaHosts = $haRuntime.TotalHosts
            $totalHaGoodHosts = $haRuntime.TotalGoodHosts
        }
    }

    if ($configureVSANDiskGroup -eq 1) {
        MyLogger "Enabling vSAN & disabling vSAN Health Check ..."
        Get-VsanClusterConfiguration -Server $vc -Cluster $NewVCVSANClusterName | Set-VsanClusterConfiguration -HealthCheckIntervalMinutes 0 | Out-File -Append -LiteralPath $verboseLogFile

        foreach ($vmhost in Get-Cluster -Server $vc | Get-VMHost) {
            $luns = $vmhost | Get-ScsiLun | Select-Object CanonicalName, CapacityGB

            MyLogger "Querying ESXi host disks to create vSAN Diskgroups ..."
            foreach ($lun in $luns) {
                if (([int]($lun.CapacityGB)).toString() -eq "$NestedESXiCachingvDisk") {
                    $vsanCacheDisk = $lun.CanonicalName
                }
                if (([int]($lun.CapacityGB)).toString() -eq "$NestedESXiCapacityvDisk") {
                    $vsanCapacityDisk = $lun.CanonicalName
                }
            }
            MyLogger "Creating vSAN DiskGroup for $vmhost ..."
            New-VsanDiskGroup -Server $vc -VMHost $vmhost -SsdCanonicalName $vsanCacheDisk -DataDiskCanonicalName $vsanCapacityDisk | Out-File -Append -LiteralPath $verboseLogFile
        }
    }

    if ($configureVDS -eq 1) {
        # vmnic0 = Management on VSS
        # vmnic1 = unused
        # vmnic2 = Management on VDS (uplink1)
        # vmnic3 = Wrokload on VDS (uplink2)
        # vmnic4 = Frontend / VIP on VDS (uplink3)

        $vds = New-VDSwitch -Server $vc -Name $NewVCVDSName -Location (Get-Datacenter -Name $NewVCDatacenterName) -Mtu 1600 -NumUplinkPorts 3

        MyLogger "Creating VDS Management Network Portgroup"
        New-VDPortgroup -Server $vc -Name $NewVCMgmtPortgroupName -Vds $vds | Out-File -Append -LiteralPath $verboseLogFile
        Get-VDPortgroup -Server $vc $NewVCMgmtPortgroupName | Get-VDUplinkTeamingPolicy | Set-VDUplinkTeamingPolicy -ActiveUplinkPort @("dvUplink1") -UnusedUplinkPort @("dvUplink2", "dvUplink3") | Out-File -Append -LiteralPath $verboseLogFile

        MyLogger "Creating VDS Supervisor Cluster Management Network Portgroup"
        New-VDPortgroup -Server $vc -Name $NewVCWorkloadPortgroupName -Vds $vds | Out-File -Append -LiteralPath $verboseLogFile
        Get-VDPortgroup -Server $vc $NewVCWorkloadPortgroupName | Get-VDUplinkTeamingPolicy | Set-VDUplinkTeamingPolicy -ActiveUplinkPort @("dvUplink2") -UnusedUplinkPort @("dvUplink1", "dvUplink3") | Out-File -Append -LiteralPath $verboseLogFile

        MyLogger "Creating VDS Frontend / VIP Network Portgroup"
        New-VDPortgroup -Server $vc -Name $NewVCVIPPortgroupName -Vds $vds | Out-File -Append -LiteralPath $verboseLogFile
        Get-VDPortgroup -Server $vc $NewVCVIPPortgroupName | Get-VDUplinkTeamingPolicy | Set-VDUplinkTeamingPolicy -ActiveUplinkPort @("dvUplink3") -UnusedUplinkPort @("dvUplink1", "dvUplink2") | Out-File -Append -LiteralPath $verboseLogFile

        foreach ($vmhost in Get-Cluster -Server $vc | Get-VMHost) {
            MyLogger "Adding $vmhost to $NewVCVDSName"
            $vds | Add-VDSwitchVMHost -VMHost $vmhost | Out-Null

            $vmhostNetworkAdapter = Get-VMHost $vmhost | Get-VMHostNetworkAdapter -Physical -Name vmnic2, vmnic3, vmnic4
            $vds | Add-VDSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter $vmhostNetworkAdapter -Confirm:$false
        }
    }

    if ($clearVSANHealthCheckAlarm -eq 1) {
        MyLogger "Clearing default vSAN Health Check Alarms, not applicable in Nested ESXi env ..."
        $alarmMgr = Get-View AlarmManager -Server $vc
        Get-Cluster -Server $vc | Where-Object { $_.ExtensionData.TriggeredAlarmState } | ForEach-Object {
            $cluster = $_
            $Cluster.ExtensionData.TriggeredAlarmState | ForEach-Object {
                $alarmMgr.AcknowledgeAlarm($_.Alarm, $cluster.ExtensionData.MoRef)
            }
        }
        $alarmSpec = New-Object VMware.Vim.AlarmFilterSpec
        $alarmMgr.ClearTriggeredAlarms($alarmSpec)
    }

    # Final configure and then exit maintanence mode in case patching was done earlier
    foreach ($vmhost in Get-Cluster -Server $vc | Get-VMHost) {
        # Disable Core Dump Warning
        Get-AdvancedSetting -Entity $vmhost -Name UserVars.SuppressCoredumpWarning | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        # Enable vMotion traffic
        $vmhost | Get-VMHostNetworkAdapter -VMKernel | Set-VMHostNetworkAdapter -VMotionEnabled $true -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        if ($vmhost.ConnectionState -eq "Maintenance") {
            Set-VMHost -VMhost $vmhost -State Connected -RunAsync -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }
    }

    if ($setupStoragePolicy) {
        MyLogger "Creating Storage Policy and attaching to $vSANDatastoreName..."
        New-TagCategory -Server $vc -Name $StoragePolicyTagCategory -Cardinality single -EntityType Datastore | Out-File -Append -LiteralPath $verboseLogFile
        New-Tag -Server $vc -Name $StoragePolicyTagName -Category $StoragePolicyTagCategory | Out-File -Append -LiteralPath $verboseLogFile
        Get-Datastore -Server $vc -Name $vSANDatastoreName | New-TagAssignment -Server $vc -Tag $StoragePolicyTagName | Out-File -Append -LiteralPath $verboseLogFile
        New-SpbmStoragePolicy -Server $vc -Name $StoragePolicyName -AnyOfRuleSets (New-SpbmRuleSet -Name "sp-ruleset" -AllOfRules (New-SpbmRule -AnyOfTags (Get-Tag $StoragePolicyTagName))) | Out-File -Append -LiteralPath $verboseLogFile
    }

    MyLogger "Disconnecting from new VCSA ..."
    Disconnect-VIServer * -Confirm:$false
}

if ($setupContentLibrary -eq 1) {
    $vc = Connect-VIServer $VCSAIPAddress -User "administrator@$VCSASSODomainName" -Password $VCSASSOPassword -WarningAction SilentlyContinue -Force

    MyLogger "Creating VKr Subscribed Content Library $VKrContentLibraryName ..."
    $clScheme = ([System.Uri]$VKrContentLibraryURL).scheme
    $clHost = ([System.Uri]$VKrContentLibraryURL).host
    $clPort = ([System.Uri]$VKrContentLibraryURL).port
    $clThumbprint = Get-SSLThumbprint -Url "${clScheme}://${clHost}:${clPort}"

    New-ContentLibrary -Server $vc -Name $VKrContentLibraryName -Description "Subscribed VKr Content Library" -Datastore (Get-Datastore -Server $vc $vSANDatastoreName) -DownloadContentOnDemand -SubscriptionUrl $VKrContentLibraryURL -SslThumbprint $clThumbprint | Out-File -Append -LiteralPath $verboseLogFile

    Disconnect-VIServer * -Confirm:$false | Out-Null
}

if ($setupAVI -eq 1) {
    # Create AVI Service Engines VM folder
    MyLogger "Creating AVI Service Engines VM folder in new VCSA..."
    $vc = Connect-VIServer $VCSAIPAddress -User "administrator@$VCSASSODomainName" -Password $VCSASSOPassword -WarningAction SilentlyContinue -Force
    New-Folder -Server $vc -Location VM -Name $AVISEVMFolder | Out-Null
    Remove-Folder -Server $vc -Folder "Discovered virtual machine" -Confirm:$false | Out-Null

    Disconnect-VIServer * -Confirm:$false | Out-Null

    # AVI can take up to several minutes to initialize upon initial power on
    while (1) {
        try {
            $response = Invoke-WebRequest -Uri http://${AVIManagementIPAddress} -SkipCertificateCheck
            if ($response.StatusCode -eq 200) {
                MyLogger "$AVIDisplayName is now ready for configuration ..."
                break
            }
        }
        catch {
            MyLogger "$AVIDisplayName is not ready, sleeping for 2 minutes ..."
            Start-Sleep -Seconds 120
        }
    }

    # Assumes Basic Auth has been enabled per automation below
    $pair = "admin:$AVIAdminPassword"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)

    $newPassbasicAuthHeaders = @{
        "Authorization" = "basic $base64";
        "Content-Type"  = "application/json";
        "Accept"        = "application/json";
        "x-avi-version" = $AVIVersion;
    }

    $enableBasicAuth = 1
    $updateAdminPassword = 1
    $updateBackupPassphrase = 1
    $updateDnsNtpSmtpSettings = 1
    $updateWelcomeWorkflow = 1
    $createSSLCertificate = 1
    $updateSSlCertificate = 1
    $registervCenter = 1
    $updateVCMgmtNetwork = 1
    $updateVCWorkloadNetwork = 1
    $createDefaultIPAM = 1
    $updateDefaultIPAM = 1
    $updateAVILicense = 1

    if ($enableBasicAuth -eq 1) {
        $headers = @{
            "Content-Type" = "application/json"
            "Accept"       = "application/json"
        }

        $payload = @{
            username = "admin";
            password = $AVIDefaultAdminPassword;
        }

        $defaultPasswordBody = $payload | ConvertTo-Json

        $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/login -Body $defaultPasswordBody -Method POST -Headers $headers -SessionVariable WebSession -SkipCertificateCheck
        $csrfToken = $WebSession.Cookies.GetCookies("https://${AVIManagementIPAddress}/login")["csrftoken"].value

        $headers = @{
            "Content-Type"  = "application/json"
            "Accept"        = "application/json"
            "x-avi-version" = $AVIVersion
            "x-csrftoken"   = $csrfToken
            "referer"       = "https://${AVIManagementIPAddress}/login"
        }

        $json = (Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/systemconfiguration -Method GET -Headers $headers -WebSession $WebSession -SkipCertificateCheck).Content | ConvertFrom-Json
        $json.portal_configuration.allow_basic_authentication = $true
        $systemConfigBody = $json | ConvertTo-Json -Depth 10

        try {
            MyLogger "Enabling basic auth ..."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/systemconfiguration -Body $systemConfigBody -Method PUT -Headers $headers -WebSession $WebSession -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to update basic auth" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully enabled basic auth for $AVIDisplayName ..."
        }
        else {
            MyLogger "Something went wrong enabling basic auth" "yellow"
            $response
            break
        }
    }

    if ($updateAdminPassword -eq 1) {
        $pair = "admin:$AVIDefaultAdminPassword"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $base64 = [System.Convert]::ToBase64String($bytes)

        $basicAuthHeaders = @{
            "Authorization" = "basic $base64"
            "Content-Type"  = "application/json"
            "Accept"        = "application/json"
        }

        $payload = @{
            old_password = $AVIDefaultAdminPassword;
            password     = $AVIAdminPassword;
            username     = "admin"
        }

        $newPasswordBody = $payload | ConvertTo-Json

        try {
            MyLogger "Changing default admin password"
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/useraccount -Body $newPasswordBody -Method PUT -Headers $basicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to change admin password" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully changed default admin password ..."
        }
        else {
            MyLogger "Something went wrong changing default admin password" "yellow"
            $response
            break
        }
    }

    if ($updateBackupPassphrase -eq 1) {
        $backupJsonResult = ((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/backupconfiguration -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results[0]

        $passPhraseJson = @{
            "add" = @{
                "backup_passphrase" = $AVIPassphrase;
            }
        }
        $newBackupJsonBody = ($passPhraseJson | ConvertTo-json)

        try {
            MyLogger "Configuring backup passphrase ..."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/backupconfiguration/$($backupJsonResult.uuid) -body $newBackupJsonBody -Method PATCH -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to update backup passphrase" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully updated backup passphrase ..."
        }
        else {
            MyLogger "Something went wrong updating backup passphrase" "yellow"
            $response
            break
        }
    }

    if ($updateDnsNtpSmtpSettings -eq 1) {
        $dnsNtpResults = (Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/systemconfiguration -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json

        $dnsNtpResults.dns_configuration.search_domain = "$VMDomain"
        $dnsNtpResults.email_configuration.smtp_type = "SMTP_NONE"

        $dnsConfig = @{
            "addr" = "$VMDNS";
            "type" = "V4";
        }

        $ntpConfig = @{
            "server" = @{
                "addr" = "$VMNTP";
                "type" = "V4";
            }
        }

        $dnsNtpResults.dns_configuration | Add-Member -Force -MemberType NoteProperty -Name server_list -Value @($dnsConfig)
        $dnsNtpResults.ntp_configuration | Add-Member -Force -MemberType NoteProperty -Name ntp_servers -Value @($ntpConfig)
        $newDnsNtpJsonBody = ($dnsNtpResults | ConvertTo-json -Depth 4)

        try {
            MyLogger "Configuring DNS, NTP and SMTP settings"
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/systemconfiguration -body $newDnsNtpJsonBody -Method PUT -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to update DNS, NTP and SMTP settings" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully updated DNS, NTP and SMTP settings ..."
        }
        else {
            MyLogger "Something went wrong with updating DNS, NTP and SMTP settings" "yellow"
            $response
            break
        }
    }

    if ($updateAVILicense -eq 1) {
        $AVISystemConfig = (Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/systemconfiguration -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json

        $AVISystemConfig.default_license_tier = $AVILicenseType

        $NewAVISystemConfig = ($AVISystemConfig | ConvertTo-json -Depth 4)

        try {
            MyLogger "Configuring licensing"
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/systemconfiguration -body $NewAVISystemConfig -Method PUT -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to update licensing" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully updated licensing..."
        }
        else {
            MyLogger "Something went wrong with updating licensing" "yellow"
            $response
            break
        }
    }

    if ($updateWelcomeWorkflow -eq 1) {
        $welcomeWorkflowJson = @{
            "replace" = @{
                "welcome_workflow_complete" = "true";
            }
        }

        $welcomeWorkflowBody = ($welcomeWorkflowJson | ConvertTo-json)

        try {
            MyLogger "Disabling initial welcome message ..."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/systemconfiguration -body $welcomeWorkflowBody -Method PATCH -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to disable welcome workflow message" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully disabled welcome workflow message ..."
        }
        else {
            MyLogger "Something went wrong disabling welcome workflow message" "yellow"
            $response
            break
        }
    }

    if ($createSSLCertificate -eq 1) {

        $selfSignCertPayload = @{
            "certificate"        = @{
                "expiry_status"     = "SSL_CERTIFICATE_GOOD";
                "days_until_expire" = $AVISSLCertExpiry;
                "self_signed"       = "true"
                "subject"           = @{
                    "common_name"       = $AVIHostname;
                    "email_address"     = $AVISSLCertEmail;
                    "organization_unit" = $AVISSLCertOrganizationUnit;
                    "organization"      = $AVISSLCertOrganization;
                    "locality"          = $AVISSLCertLocation;
                    "state"             = $AVISSLCertState;
                    "country"           = $AVISSLCertCountry;
                };
                "subject_alt_names" = @($AVIManagementIPAddress);
            };
            "key_params"         = @{
                "algorithm"  = "SSL_KEY_ALGORITHM_RSA";
                "rsa_params" = @{
                    "key_size" = "SSL_KEY_2048_BITS";
                    "exponent" = "65537";
                };
            };
            "status"             = "SSL_CERTIFICATE_FINISHED";
            "format"             = "SSL_PEM";
            "certificate_base64" = "true";
            "key_base64"         = "true";
            "type"               = "SSL_CERTIFICATE_TYPE_SYSTEM";
            "name"               = $AVISSLCertName;
        }

        $selfSignCertBody = ($selfSignCertPayload | ConvertTo-Json -Depth 8)

        try {
            MyLogger "Creating self-signed TLS certificate ..."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/sslkeyandcertificate -body $selfSignCertBody -Method POST -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Error in creating self-sign TLS certificate" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 201) {
            MyLogger "Successfully created self-sign TLS certificate ..."
        }
        else {
            MyLogger "Something went wrong creating self-sign TLS certificate" "yellow"
            $response
            break
        }
    }

    if ($updateSSlCertificate -eq 1) {
        $certJsonResults = ((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/sslkeyandcertificate?include_name -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results | Where-Object { $_.name -eq $AVISSLCertName }

        $systemConfigJsonResults = (Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/systemconfiguration -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json

        $systemConfigJsonResults.portal_configuration.sslkeyandcertificate_refs = @(${certJsonResults}.url)

        $updateSSLCertBody = $systemConfigJsonResults | ConvertTo-Json -Depth 4

        try {
            MyLogger "Updating AVI to new self-sign TLS ceretificate ..."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/systemconfiguration -body $updateSSLCertBody -Method PUT -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Error in updating self-sign TLS certificate" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully updated to new self-sign TLS certificate ..."
        }
        else {
            MyLogger "Something went wrong updating to new self-sign TLS certificate" "yellow"
            $response
            break
        }
    }

    if ($registervCenter -eq 1) {
        $cloudConfigResult = ((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/cloud -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results[0]

        $cloudConfigResult.vtype = "CLOUD_VCENTER"

        $vcConfig = @{
            "username"             = "administrator@vsphere.local"
            "password"             = "$VCSASSOPassword";
            "vcenter_url"          = "$VCSAHostname";
            "privilege"            = "WRITE_ACCESS";
            "use_content_lib"      = $False;
            "datacenter"           = "$NewVCDatacenterName";
            "management_ip_subnet" = @{
                "ip_addr" = @{
                    "addr" = "$AVIManagementNetwork";
                    "type" = "V4";
                };
                "mask"    = "$AVIManagementNetworkPrefix";
            }
        }

        $cloudConfigResult | Add-Member -MemberType NoteProperty -Name vcenter_configuration -Value $vcConfig

        $newCloudConfigBody = ($cloudConfigResult | ConvertTo-Json -Depth 4)

        try {
            MyLogger "Register Nested vCenter Server $VCSAHostname to AVI ..."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/cloud/$($cloudConfigResult.uuid) -body $newCloudConfigBody -Method PUT -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to register Nested vCenter Server" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully registered Nested vCenter Server ..."
        }
        else {
            MyLogger "Something went wrong registering Nested vCenter Server" "yellow"
            $response
            break
        }
    }

    if ($updateVCMgmtNetwork -eq 1) {
        Start-Sleep -Seconds 20

        $cloudNetworkResult = ((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/network -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results | Where-Object { $_.name -eq $NewVCMgmtPortgroupName }

        $mgmtNetworkConfig = @{
            "prefix"           = @{
                "ip_addr" = @{
                    "addr" = "$AVIManagementNetwork";
                    "type" = "V4";
                };
                "mask"    = "$AVIManagementNetworkPrefix";
            };
            "static_ip_ranges" = @(
                @{
                    "range" = @{
                        "begin" = @{
                            "addr" = $AVIManagementNetworkStartRange;
                            "type" = "V4";
                        };
                        "end"   = @{
                            "addr" = $AVIManagementNetworkEndRange;
                            "type" = "V4";
                        }
                    };
                    "type"  = "STATIC_IPS_FOR_VIP_AND_SE";
                }
            )
        }

        $cloudNetworkResult | Add-Member -MemberType NoteProperty -Name configured_subnets -Value @($mgmtNetworkConfig)

        $newCloudMgmtNetworkBody = ($cloudNetworkResult | ConvertTo-Json -Depth 10)

        # Create Subnet mapping
        try {
            MyLogger "Creating subnet mapping for Service Engine Network ..."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/network/$($cloudNetworkResult.uuid) -body $newCloudMgmtNetworkBody -Method PUT -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to create subnet mapping for $NewVCMgmtPortgroupName" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully created subnet mapping for $NewVCMgmtPortgroupName ..."
        }
        else {
            MyLogger "Something went wrong creating subnet mapping for $NewVCMgmtPortgroupName" "yellow"
            $response
            break
        }

        # Add default Gateway
        $vrfContextResult = ((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/vrfcontext -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results | Where-Object { $_.name -eq "global" }

        $staticRouteConfig = @{
            "next_hop" = @{
                "addr" = $AVIVIPNetworkGateway;
                "type" = "V4";
            };
            "route_id" = "1";
            "prefix"   = @{
                "ip_addr" = @{
                    "addr" = "0.0.0.0";
                    "type" = "V4";
                };
                "mask"    = "0"
            }
        }

        $vrfContextResult | Add-Member -Force -MemberType NoteProperty -Name static_routes -Value @($staticRouteConfig)

        $newvrfContextBody = ($vrfContextResult | ConvertTo-Json -Depth 10)

        try {
            MyLogger "Updating VRF Context for default gateway ..."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/vrfcontext/$(${vrfContextResult}.uuid) -body $newvrfContextBody -Method PUT -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to update VRF context" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully updated VRF context ..."
        }
        else {
            MyLogger "Something went wrong updating VRF context" "yellow"
            $response
            break
        }

        # Configure Service Engine group
        $ServiceEngineGroupResult = ((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/serviceenginegroup -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results | Where-Object { $_.name -eq "Default-Group" }

        $vSphereClusterRefURL = (((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/vimgrclusterruntime -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results | where-object { $_.name -eq $NewVCVSANClusterName }).url

        $ServiceEngineGroupResult.vcenter_folder = $AVISEVMFolder
        $ServiceEngineGroupResult.se_name_prefix = $AVISENamePrefix
        $ServiceEngineGroupResult.vcenter_datastores_include = $True
        $ServiceEngineGroupResult.vcenter_datastore_mode = "VCENTER_DATASTORE_SHARED"

        $AVISEGDatastore = @{
            "datastore_name" = $vSANDatastoreName
        }

        $ServiceEngineGroupResult | Add-Member -Force -MemberType NoteProperty -Name vcenter_datastores -Value @($AVISEGDatastore)

        $AVIvSphereClusterConfig = @{
            "include" = $True
            "cluster_refs" = @(
                $vSphereClusterRefURL
            )
        }

        $ServiceEngineGroupResult | Add-Member -Force NoteProperty -Name 'vcenter_clusters' -Value $AVIvSphereClusterConfig

        $NewSEGJSONBody = ($ServiceEngineGroupResult | ConvertTo-Json -Depth 10)

        try {
            MyLogger "Updating Service Engine Group configuration.."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/serviceenginegroup/$(${ServiceEngineGroupResult}.uuid) -body $NewSEGJSONBody -Method PUT -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to update Service Engine Group" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully updated Service Engine Group..."
        }
        else {
            MyLogger "Something went wrong updating Service Engine Group" "yellow"
            $response
            break
        }

        # Associate AVI Management Network to vCenter
        $cloudNetworkResult = ((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/network -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results | Where-Object { $_.name -eq $NewVCMgmtPortgroupName }

        $cloudConfigResult = ((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/cloud -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results[0]


        $cloudConfigResult.vcenter_configuration | Add-Member -MemberType NoteProperty -Name management_network -Value $(${cloudNetworkResult}.vimgrnw_ref)
        $newCloudConfigBody = ($cloudConfigResult | ConvertTo-Json -Depth 4)

        try {
            MyLogger "Associating Service Engine network to Nested vCenter Server ..."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/cloud/$(${cloudConfigResult}.uuid) -body $newCloudConfigBody -Method PUT -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to associate service engine network to Nested vCenter Server" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully associated service engine network to Nested vCenter Server ..."
        }
        else {
            MyLogger "Something went wrong associating service engine network to Nested vCenter Server" "yellow"
            $response
            break
        }
    }

    if ($updateVCWorkloadNetwork -eq 1) {
        $cloudNetworkResult = ((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/network -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results | Where-Object { $_.name -eq $NewVCVIPPortgroupName }

        $workloadNetworkConfig = @{
            "prefix"           = @{
                "ip_addr" = @{
                    "addr" = "$AVIVIPNetwork";
                    "type" = "V4";
                };
                "mask"    = "$AVIVIPNetworkPrefix";
            };
            "static_ip_ranges" = @(
                @{
                    "range" = @{
                        "begin" = @{
                            "addr" = $AVIVIPNetworkStartRange;
                            "type" = "V4";
                        };
                        "end"   = @{
                            "addr" = $AVIVIPNetworkEndRange;
                            "type" = "V4";
                        }
                    };
                    "type"  = "STATIC_IPS_FOR_VIP_AND_SE";
                }
            )
        }

        $cloudNetworkResult | Add-Member -MemberType NoteProperty -Name configured_subnets -Value @($workloadNetworkConfig)

        $newCloudWorkloadNetworkBody = ($cloudNetworkResult | ConvertTo-Json -Depth 10)

        # Create Subnet mapping
        try {
            MyLogger "Creating subnet mapping for Workload Network ..."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/network/$($cloudNetworkResult.uuid) -body $newCloudWorkloadNetworkBody -Method PUT -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to create subnet mapping for $NewVCVIPPortgroupName" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully created subnet mapping for $NewVCVIPPortgroupName ..."
        }
        else {
            MyLogger "Something went wrong creating subnet mapping for $NewVCVIPPortgroupName" "yellow"
            $response
            break
        }
    }

    if ($createDefaultIPAM -eq 1) {
        $cloudNetworkResult = ((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/network -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results | Where-Object { $_.name -eq $NewVCVIPPortgroupName }

        $ipamConfig = @{
            "name"               = $AVIIPAMName;
            "tenant_ref"         = "https://${AVIManagementIPAddress}/tenant/admin";
            "type"               = "IPAMDNS_TYPE_INTERNAL";
            "internal_profile"   = @{
                "ttl"             = "30";
                "usable_networks" = @(
                    @{
                        "nw_ref" = "$(${cloudNetworkResult}.url)"
                    }
                );
            };
            "allocate_ip_in_vrf" = "true"
        }

        $ipamBody = $ipamConfig | ConvertTo-Json -Depth 4

        try {
            MyLogger "Creating new IPAM Default Profile ..."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/ipamdnsproviderprofile -body $ipamBody -Method POST -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to create IPAM default profile" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 201) {
            MyLogger "Successfully created IPAM default profile ..."
        }
        else {
            MyLogger "Something went wrong creating IPAM default profile" "yellow"
            $response
            break
        }
    }

    if ($updateDefaultIPAM -eq 1) {
        $ipamResult = ((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/ipamdnsproviderprofile -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results | Where-Object { $_.name -eq $AVIIPAMName }

        $cloudConfigResult = ((Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/cloud -Method GET -Headers $newPassbasicAuthHeaders -SkipCertificateCheck).Content | ConvertFrom-Json).results[0]

        $cloudConfigResult | Add-Member -MemberType NoteProperty -Name ipam_provider_ref -Value $ipamResult.url

        $newClouddConfigBody = ($cloudConfigResult | ConvertTo-Json -Depth 10)

        try {
            MyLogger "Updating Default Cloud to new IPAM Profile ..."
            $response = Invoke-WebRequest -Uri https://${AVIManagementIPAddress}/api/cloud/$($cloudConfigResult.uuid) -body $newClouddConfigBody -Method PUT -Headers $newPassbasicAuthHeaders -SkipCertificateCheck
        }
        catch {
            MyLogger "Failed to update default IPAM profile" "red"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if ($response.Statuscode -eq 200) {
            MyLogger "Successfully updated default IPAM profile ..."
        }
        else {
            MyLogger "Something went wrong updating default IPAM profile" "yellow"
            $response
            break
        }
    }
}

if ($enableVsphereSupervisor -eq 1) {
    	
    $vSphereSupervisorParams = @{                
       SupervisorClusterName = $SupervisorClusterName;         
       NestedvCenterServer = $VCSAHostname; 
       NestedvCenterServerUsername = "administrator@vsphere.local";
       NestedvCenterServerPassword = $VCSASSOPassword;
       ClusterName = $NewVCVSANClusterName;         
       VKrContentLibrary = $VKrContentLibraryName; 
       ControlPlaneSize = $ControlPlaneSize                   
       MgmtNetwork = $NewVCMgmtPortgroupName;         
       MgmtNetworkStartIP = $MgmtNetworkStartIP;  
       MgmtNetworkPrefix = $MgmtNetworkPrefix;              
       MgmtNetworkGateway = $VMGateway;   
       MgmtNetworkDNS = @($VMDNS);   
       MgmtNetworkDNSDomain = $VMDomain;  
       MgmtNetworkNTP = @($VMNTP); 
       WorkloadNetworkLabel="workload-1";            
       WorkloadNetwork = $NewVCWorkloadPortgroupName;                
       WorkloadNetworkStartIP = $WorkloadNetworkStartIP;        
       WorkloadNetworkIPCount = $WorkloadNetworkIPCount;                  
       WorkloadNetworkPrefix = $WorkloadNetworkPrefix;                 
       WorkloadNetworkGateway = $WorkloadNetworkGateway;       
       WorkloadNetworkDNS = $WorkloadNetworkDNS;         
       WorkloadNetworkDNSDomain = $VMDomain;    
       WorkloadNetworkNTP = $WorkloadNetworkNTP;    
       WorkloadNetworkServiceStartIP = $WorkloadNetworkServiceStartIP;
       WorkloadNetworkServiceStartCount = $WorkloadNetworkServiceStartCount;       
       AVIIPAddress = $AVIManagementIPAddress;   
       AVIPort = "443";                
       AVICertName = $AVISSLCertName;      
       AVIUsername = "admin";          
       AVIPassword = $AVIPassphrase;
       StoragePolicyName = $StoragePolicyName;
   	   EnableDebug = $false;
   }
 	
	New-vSphereSupervisor @vSphereSupervisorParams
}

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes, 2)

MyLogger "Nested vSphere Lab Deployment Complete!"
MyLogger "StartTime: $StartTime"
MyLogger "EndTime: $EndTime"
MyLogger "Duration: $duration minutes"
