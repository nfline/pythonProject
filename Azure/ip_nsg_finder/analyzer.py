"""
Main analysis module that orchestrates the NSG finding and KQL query processes.
"""
import os
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple
import pandas as pd

from .common import print_info, print_success, print_warning, print_error, ensure_output_dir
from .find_nsgs import find_nsgs_by_ip
from .flow_logs import get_nsg_flow_logs_config, get_log_analytics_workspaces
from .kql_query import generate_kql_query, execute_kql_query
from .logging_utils import setup_logger

def analyze_traffic(target_ip: str, time_range_hours: int = 24, logger: Optional[logging.Logger] = None, 
                 query_type: str = "standard", return_dataframe: bool = False, 
                 save_individual_excel: bool = True) -> Optional[pd.DataFrame]:
    """
    Main analysis function: Finds NSGs, gets configs, generates and executes KQL queries.
    """
    # Create logger if not provided
    if logger is None:
        app_log_dir = ensure_output_dir("log", "app")
        log_file_path = os.path.join(app_log_dir, f"analysis_{target_ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}.log")
        logger = setup_logger(log_file_path)
    
    logger.info(f"Starting analysis for IP: {target_ip}")
    logger.info(f"Time range for analysis: {time_range_hours} hours")
    
    print_info(f"\n{'='*80}")
    print_info(f"Starting IP-to-NSG-to-FlowLogs analysis for: {target_ip}")
    print_info(f"Time range: {time_range_hours} hours")
    print_info(f"{'='*80}\n")
    
    try:
        # Step 1-2: Find NSGs associated with the IP
        # Unpack both values: NSG IDs and subscription ID
        unique_nsg_ids, subscription_id = find_nsgs_by_ip(target_ip)
        
        if not unique_nsg_ids:
            logger.warning(f"No NSGs found for IP: {target_ip}, analysis cannot continue")
            print_warning(f"No NSGs found for IP: {target_ip}, analysis cannot continue")
            return
            
        logger.info(f"Found {len(unique_nsg_ids)} NSGs to analyze")
        
        # Log subscription ID if found
        if subscription_id:
            logger.info(f"Using subscription ID: {subscription_id} for Azure operations")
            print_info(f"Using subscription ID: {subscription_id} for Azure operations")
        
        # Step 4: Get flow logs configuration for the NSGs
        flow_logs_config = get_nsg_flow_logs_config(unique_nsg_ids, target_ip, subscription_id)
        
        if not flow_logs_config:
            logger.warning("No flow logs configuration found, analysis cannot continue")
            print_warning("No flow logs configuration found, analysis cannot continue")
            return
            
        logger.info(f"Retrieved flow logs configuration for {len(flow_logs_config)} NSGs")
        
        # Step 5: Get Log Analytics workspaces from flow logs configuration
        workspace_ids = get_log_analytics_workspaces(flow_logs_config, target_ip)
        
        if not workspace_ids:
            logger.warning("No workspace IDs found, cannot query flow logs")
            print_warning("No workspace IDs found, cannot query flow logs")
            return
            
        logger.info(f"Found {len(workspace_ids)} workspace IDs for querying")
        
        # Step 6: Execute KQL queries for each NSG with workspace
        print_info("\nStep 6: Executing KQL queries for each NSG with a workspace ID...")
        
        all_queries_success = True
        query_results = {}
        
        for nsg_id, workspace_id in workspace_ids.items():
            nsg_name = nsg_id.split('/')[-1]
            
            print_info(f"\nExecuting query for NSG '{nsg_name}' using workspace ID: {workspace_id}")
            
            # Generate the KQL query
            kql_query = generate_kql_query(target_ip, time_range_hours, nsg_id, query_type=query_type)
            
            # Execute the query
            raw_results, df, excel_file = execute_kql_query(
                workspace_id=workspace_id,
                kql_query=kql_query,
                target_ip=target_ip,
                nsg_id=nsg_id,
                timeout_seconds=300,  # 5 minutes timeout
                subscription_id=subscription_id,  # Pass subscription ID to query execution
                save_individual_excel=save_individual_excel  # Control individual Excel file creation
            )
            
            # Store results for logging and return value
            if raw_results:
                query_results[nsg_id] = {
                    'workspace_id': workspace_id,
                    'results': raw_results,
                    'dataframe': df
                }
                logger.info(f"Query for NSG '{nsg_name}' completed successfully with {len(raw_results)} results")
                
                # Log success message
                print_success(f"Query for NSG '{nsg_name}' completed successfully with {len(raw_results)} results")
            else:
                all_queries_success = False
                logger.warning(f"Query for NSG '{nsg_name}' failed or returned no results")
                print_warning(f"Query for NSG '{nsg_name}' failed or returned no results")
        
        # Summary
        print_info(f"\n{'='*80}")
        if all_queries_success and query_results:
            print_success(f"Analysis completed for IP {target_ip}")
            print_info(f"Queries executed for {len(query_results)} NSGs")
            total_results = sum(len(data['results']) for data in query_results.values())
            print_info(f"Total flow log records found: {total_results}")
        elif query_results:
            print_warning(f"Analysis completed with some failures for IP {target_ip}")
            print_info(f"Successful queries: {len(query_results)} of {len(workspace_ids)} NSGs")
        else:
            print_error(f"Analysis failed for IP {target_ip}")
            print_info("No query results were obtained")
        print_info(f"{'='*80}\n")
        
        print_info(f"\nAnalysis completed! Check the 'output' directory for results")
        
        # If requested, return the DataFrame for merging multiple IP results
        if return_dataframe:
            # Collect all DataFrames from all NSGs for this IP
            all_dfs = []
            for nsg_result in query_results.values():
                if 'dataframe' in nsg_result and nsg_result['dataframe'] is not None:
                    all_dfs.append(nsg_result['dataframe'])
            
            # If we found any DataFrames, merge them and return
            if all_dfs:
                return pd.concat(all_dfs, ignore_index=True)
            return None

    except Exception as e:
        logger.exception(f"Error in analysis: {e}")
        print_error(f"Error in analysis: {e}")
        return None
