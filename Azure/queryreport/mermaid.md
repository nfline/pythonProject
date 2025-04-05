````mermaid
flowchart TD
    start([开始]) --> param[收集参数\nIP地址 & 天数\n--timeout等选项]
    param --> init[初始化环境\n创建输出目录]
    init --> login[登录Azure]
    login --> findNICs[查找拥有IP的网络接口]
    
    subgraph ResourceDiscovery[资源发现]
        findNICs --> extractVNET[提取VNET和子网信息]
        extractVNET --> getNSGs[获取关联的NSG]
        getNSGs --> checkFlowLogs{流日志\n是否配置?}
    end
    
    checkFlowLogs -- 是 --> findFlowLogs[查找NSG流日志配置]
    checkFlowLogs -- 否 --> manualWorkspace[手动指定工作区ID]
    
    findFlowLogs --> validateWorkspaceID[验证工作区ID格式]
    manualWorkspace --> validateWorkspaceID
    
    validateWorkspaceID --> identifyWorkspaces[确定Log Analytics工作区]
    
    subgraph QueryExecution[查询执行]
        identifyWorkspaces --> buildKQL[构建KQL查询]
        buildKQL --> timeoutCheck{启用超时?}
        timeoutCheck -- 是 --> executeWithTimeout[带超时执行查询]
        timeoutCheck -- 否 --> executeKQL[执行KQL查询]
        executeWithTimeout --> processResults
        executeKQL --> processResults[处理查询结果]
        
        processResults --> checkNSGFilter{使用NSG\n过滤?}
        checkNSGFilter -- 否 --> rebuildQuery[重建无过滤查询]
    end
    
    processResults --> generateReport[生成流量分析报告]
    generateReport --> saveOutput[保存数据文件]
    saveOutput --> finish([完成])
    
    classDef highlight fill:#f96,stroke:#333,stroke-width:2px;
    class QueryExecution,validateWorkspaceID,timeoutCheck highlight;
````