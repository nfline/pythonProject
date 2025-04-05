class FlowLogsManager:
    """Flow Logs Management Class"""
    
    def __init__(self, logger):
        self.logger = logger
        self.flow_logs_config = {}

    def get_configurations(self, nsg_ids):
        """Retrieve flow logs configuration"""
        self.logger.info("Retrieving flow logs configuration...")
        for nsg_id in nsg_ids:
            result = run_az_command(f"network watcher flow-log show --nsg {nsg_id}")
            if result:
                self.flow_logs_config[nsg_id] = {
                    "workspace_id": result.get("storageId"),
                    "enabled": result.get("enabled")
                }
        return self.flow_logs_config

    def get_workspace_mapping(self, flow_configs):
        """Get workspace ID mapping"""
        return {nsg_id: cfg["workspace_id"] for nsg_id, cfg in flow_configs.items() if cfg.get("workspace_id")}