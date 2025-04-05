import pandas as pd
from datetime import datetime
from ..utils.logger import ColorPrinter

def generate_excel_report(nsg_info, flow_configs, query_results, output_path):
    """生成Excel分析报告"""
    try:
        # 创建数据框架
        report_data = []
        
        for nsg_id, results in query_results.items():
            nsg_name = nsg_id.split('/')[-1]
            report_data.append({
                "NSG名称": nsg_name,
                "总流量数": results.get('total_flows', 0),
                "入站流量(MB)": results.get('inbound_bytes', 0) / 1024**2,
                "出站流量(MB)": results.get('outbound_bytes', 0) / 1024**2,
                "开放端口数": len(results.get('ports', set()))
            })
        
        df = pd.DataFrame(report_data)
        
        # 写入Excel文件
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='流量摘要')
            
        ColorPrinter.print_success(f"报告已生成：{output_path}")
        return True
    except Exception as e:
        ColorPrinter.print_error(f"生成报告失败：{str(e)}")
        return False