import pandas as pd
from datetime import datetime
from ..utils.logger import ColorPrinter

def generate_excel_report(nsg_info, flow_configs, query_results, output_path):
    """Generate Excel analysis report"""
    try:
        # Create dataframe
        report_data = []
        
        for nsg_id, results in query_results.items():
            nsg_name = nsg_id.split('/')[-1]
            report_data.append({
                "NSG Name": nsg_name,
                "Total Flows": results.get('total_flows', 0),
                "Inbound Traffic (MB)": results.get('inbound_bytes', 0) / 1024**2,
                "Outbound Traffic (MB)": results.get('outbound_bytes', 0) / 1024**2,
                "Open Ports Count": len(results.get('ports', set()))
            })
        
        df = pd.DataFrame(report_data)
        
        # Write to Excel file
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Traffic Summary')
            
        ColorPrinter.print_success(f"Report generated: {output_path}")
        return True
    except Exception as e:
        ColorPrinter.print_error(f"Failed to generate report: {str(e)}")
        return False