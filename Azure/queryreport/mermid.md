```mermaid
flowchart TD
    start([开始]) --> param[收集参数\nIP地址 & 天数]
    param --> init[初始化环境\n创建输出目录]
    init --> login{Azure\n登录检查}
    
    login -->|未登录| doLogin[登录Azure]
    doLogin --> loginSuccess{登录\n成功?}
    loginSuccess -->|否| exit([退出])
    loginSuccess -->|是| findResources
    
    login -->|已登录| findResources[查找与IP关联的资源]
    
    subgraph ResourceDiscovery ["资源发现阶段"]
        findResources --> directNICs{找到网络\n接口?}
        directNICs -->|是| getNSGs[获取关联的NSG]
        directNICs -->|否| findNSGRules[查找包含IP的NSG规则]
        findNSGRules --> getNSGs
    end
    
    getNSGs --> findFlowLogs[查找NSG流日志配置]
    findFlowLogs --> getWorkspaces[获取关联的Log Analytics工作区]
    
    subgraph DataCollection ["数据收集阶段"]
        getWorkspaces --> queryWorkspaces[查询目标工作区]
        queryWorkspaces --> networkQuery[执行网络\n流量查询]
        networkQuery --> trafficStats[生成流量\n统计分析]
        trafficStats --> securityQuery[执行安全\n事件查询]
    end
    
    securityQuery --> createReport[创建汇总报告]
    
    subgraph Reporting ["报告生成阶段"]
        createReport --> mergeResults[合并所有\n查询结果]
        mergeResults --> createCSV[创建汇总CSV]
    end
    
    createCSV --> finish([结束])
    
    subgraph Legend ["数据类型"]
        outputDir[("输出目录:\nip_traffic_<IP>_<timestamp>")] --- |存储| jsonFiles[("JSON文件:\n- associated_resources.json\n- related_nsg_rules.json\n- flow_logs.json\n- target_workspaces.json\n- network_traffic_*.json\n- ip_stats_*.json")]
        jsonFiles --- csvFiles[("CSV文件:\n- associated_resources.csv\n- network_traffic_*.csv\n- ip_stats_*.csv\n- all_network_traffic.csv")]
    end
    
    classDef highlight fill:#f96,stroke:#333,stroke-width:2px;
    class ResourceDiscovery,findResources,directNICs,getNSGs,findNSGRules highlight;
    ````