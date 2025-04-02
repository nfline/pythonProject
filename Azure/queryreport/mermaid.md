````mermaid
flowchart TD
    start([开始]) --> param[收集参数\nIP地址 & 天数]
    param --> init[初始化环境\n创建输出目录]
    init --> login[登录Azure]
    login --> findNICs[查找拥有IP的网络接口]
    
    subgraph ResourceDiscovery[资源发现]
        findNICs --> extractVNET[提取VNET和子网信息]
        extractVNET --> getNSGs[获取关联的NSG]
    end
    
    getNSGs --> findFlowLogs[查找NSG流日志配置]
    findFlowLogs --> identifyWorkspaces[确定Log Analytics工作区]
    
    subgraph LogAnalytics[查询和分析]
        identifyWorkspaces --> buildKQL[构建KQL查询]
        buildKQL --> executeKQL[执行KQL查询]
        executeKQL --> processResults[处理查询结果]
    end
    
    processResults --> generateReport[生成流量分析报告]
    generateReport --> saveOutput[保存数据文件]
    saveOutput --> finish([完成])
    
    classDef highlight fill:#f96,stroke:#333,stroke-width:2px;
    class LogAnalytics,buildKQL,executeKQL highlight;
````