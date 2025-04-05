from ..utils.azure_cli import run_az_command

class NSGAnalyzer:
    """Core NSG Analysis Class"""
    
    def __init__(self, target_ip, logger):
        self.target_ip = target_ip
        self.logger = logger
        self.nsg_data = []

    def find_associated_nsgs(self):
        """Find associated NSGs using Azure Resource Graph
        
        This improved query checks both singular and plural forms of address prefixes
        in both source and destination rules.
        """
        self.logger.info("Querying associated NSGs...")
        query = f"""
        Resources
        | where type =~ 'microsoft.network/networksecuritygroups'
        | mv-expand rules=properties.securityRules
        | where rules.properties.destinationAddressPrefixes contains '{self.target_ip}'
           or rules.properties.sourceAddressPrefixes contains '{self.target_ip}'
           or rules.properties.destinationAddressPrefix =~ '{self.target_ip}'
           or rules.properties.sourceAddressPrefix =~ '{self.target_ip}'
           or rules.properties.destinationAddressPrefix contains '{self.target_ip}'
           or rules.properties.sourceAddressPrefix contains '{self.target_ip}'
        | project id, name, resourceGroup, location, rules
        """
        result = run_az_command(f"graph query -q \"{query}\"")
        if result and 'data' in result:
            self.nsg_data = result['data']
            return [nsg['id'] for nsg in self.nsg_data]
        return []

    def get_discovery_data(self):
        """Get discovered NSG data"""
        return {
            "total_nsgs": len(self.nsg_data),
            "nsg_list": self.nsg_data
        }