flowchart TD
    start([开始]) --> param[收集参数\nIP地址 & 天数]
    param --> init[初始化环境\n创建输出目录]
    init --> login[登录Azure]
    login --> findResources[查找与IP相关的资源]
    
    subgraph ResourceDiscovery[资源发现]
        findResources --> directNICs[查找使用此IP的网络接口]
        directNICs --> findSubnets[查找包含此IP的子网]
        findSubnets --> getSubnetNSGs[获取子网相关的NSG]
        getSubnetNSGs --> getNSGs[汇总相关NSG]
        getNSGs --> findNSGRules[找到引用该IP的NSG规则]
    end
    
    findNSGRules --> findFlowLogs[查找NSG流日志配置]
    findFlowLogs --> findWorkspaces[确定相关日志分析工作区]
    
    subgraph LogAnalytics[日志分析]
        findWorkspaces --> queryWorkspaces[查询工作区中的流量数据]
        queryWorkspaces --> processResults[处理查询结果]
        processResults --> generateReport[生成分析报告]
    end
    
    generateReport --> saveOutput[保存JSON及CSV数据]
    saveOutput --> createSummary[创建摘要报告]
    createSummary --> finish([完成])
    
    classDef highlight fill:#f96,stroke:#333,stroke-width:2px;
    class ResourceDiscovery,findResources,directNICs,findSubnets,getSubnetNSGs,getNSGs,findNSGRules highlight;