"""
Custom exceptions for the NSG Traffic Analyzer

This module contains custom exception classes used throughout the application.
"""

class InvalidIPError(Exception):
    """Raised when the input IP address is invalid or malformed.
    
    Attributes:
        message -- explanation of the error
        ip_address -- the invalid IP address
    """
    def __init__(self, ip_address: str, message: str = "Invalid IP address format"):
        self.ip_address = ip_address
        self.message = f"{message}: {ip_address}"
        super().__init__(self.message)


class AzureCLIError(Exception):
    """Raised when Azure CLI operations fail.
    
    Attributes:
        message -- explanation of the error
        command -- the failed Azure CLI command
        output -- the error output from Azure CLI
    """
    def __init__(self, command: str, output: str, message: str = "Azure CLI operation failed"):
        self.command = command
        self.output = output
        self.message = f"{message}: {command}\nError: {output}"
        super().__init__(self.message)


class NSGNotFoundError(Exception):
    """Raised when no NSGs are found for the target IP.
    
    Attributes:
        message -- explanation of the error
        ip_address -- the IP address for which NSGs were not found
    """
    def __init__(self, ip_address: str, message: str = "No NSGs found for target IP"):
        self.ip_address = ip_address
        self.message = f"{message}: {ip_address}"
        super().__init__(self.message)


class FlowLogsConfigError(Exception):
    """Raised when there's an issue with NSG flow logs configuration.
    
    Attributes:
        message -- explanation of the error
        nsg_id -- the NSG ID with configuration issues
    """
    def __init__(self, nsg_id: str, message: str = "Invalid flow logs configuration"):
        self.nsg_id = nsg_id
        self.message = f"{message}: {nsg_id}"
        super().__init__(self.message)


class WorkspaceAccessError(Exception):
    """Raised when there's an issue accessing Log Analytics workspace.
    
    Attributes:
        message -- explanation of the error
        workspace_id -- the workspace ID with access issues
    """
    def __init__(self, workspace_id: str, message: str = "Failed to access Log Analytics workspace"):
        self.workspace_id = workspace_id
        self.message = f"{message}: {workspace_id}"
        super().__init__(self.message)


class QueryExecutionError(Exception):
    """Raised when KQL query execution fails.
    
    Attributes:
        message -- explanation of the error
        query -- the failed KQL query
        workspace_id -- the workspace where the query failed
    """
    def __init__(self, query: str, workspace_id: str, message: str = "KQL query execution failed"):
        self.query = query
        self.workspace_id = workspace_id
        self.message = f"{message}: {query}\nWorkspace: {workspace_id}"
        super().__init__(self.message)
