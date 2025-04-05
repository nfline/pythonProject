from ..utils.azure_cli import run_az_command

class FlowLogsManager:
    """Flow Logs Management Class"""
    
    def __init__(self, logger):
        self.logger = logger
        self.flow_logs_config = {}

    def get_configurations(self, nsg_ids):
        """Retrieve flow logs configuration
        
        Gets detailed flow logs settings for each NSG, including:
        - Storage account information
        - Log Analytics workspace ID (if configured)
        - Enabled/disabled status
        """
        self.logger.info("Retrieving flow logs configuration...")
        for nsg_id in nsg_ids:
            result = run_az_command(f"network watcher flow-log show --nsg {nsg_id}")
            if result:
                # Correctly extract workspaceId from analytics configuration
                analytics_config = result.get("retentionPolicy", {}).get("days", 0)
                workspace_id = None
                
                # Extract the actual Log Analytics workspace resource ID
                if result.get("flowAnalyticsConfiguration") and result.get("flowAnalyticsConfiguration", {}).get("networkWatcherFlowAnalyticsConfiguration", {}).get("workspaceResourceId"):
                    workspace_id = result.get("flowAnalyticsConfiguration", {}).get("networkWatcherFlowAnalyticsConfiguration", {}).get("workspaceResourceId")
                
                self.flow_logs_config[nsg_id] = {
                    "storage_id": result.get("storageId"),
                    "workspace_id": workspace_id,
                    "enabled": result.get("enabled"),
                    "retention_days": analytics_config
                }
        return self.flow_logs_config

    def get_workspace_mapping(self, flow_configs):
        """Get workspace ID mapping
        
        Maps NSG IDs to their respective Log Analytics workspace IDs
        Returns only entries that have a valid workspace configured
        """
        return {nsg_id: cfg["workspace_id"] for nsg_id, cfg in flow_configs.items() 
                if cfg.get("workspace_id")}