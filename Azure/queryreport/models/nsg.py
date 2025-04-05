class NSGAnalyzer:
    """NSG分析核心类"""
    
    def __init__(self, target_ip, logger):
        self.target_ip = target_ip
        self.logger = logger
        self.nsg_data = []

    def find_associated_nsgs(self):
        """通过Azure Resource Graph查找关联NSG"""
        self.logger.info("正在查询关联的NSG...")
        query = f"""
        Resources
        | where type =~ 'microsoft.network/networksecuritygroups'
        | mv-expand rules=properties.securityRules
        | where rules.properties.destinationAddressPrefixes contains '{self.target_ip}'
           or rules.properties.sourceAddressPrefixes contains '{self.target_ip}'
        | project id, name, resourceGroup
        """
        result = run_az_command(f"graph query -q \"{query}\"")
        if result and 'data' in result:
            self.nsg_data = result['data']
            return [nsg['id'] for nsg in self.nsg_data]
        return []

    def get_discovery_data(self):
        """获取发现数据"""
        return {
            "total_nsgs": len(self.nsg_data),
            "nsg_list": self.nsg_data
        }