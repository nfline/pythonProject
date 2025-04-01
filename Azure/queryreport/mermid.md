```mermaid
flowchart TD
    start([Start]) --> param[Collect Parameters\nIP Address & Days]
    param --> init[Initialize Environment\nCreate Output Directory]
    init --> login{Azure\nLogin Check}
    
    login -->|Not Logged In| doLogin[Login to Azure]
    doLogin --> loginSuccess{Login\nSuccessful?}
    loginSuccess -->|No| exit([Exit])
    loginSuccess -->|Yes| getSubInfo
    
    login -->|Already Logged In| getSubInfo[Get Subscription Info]
    
    subgraph Discovery ["Resource Discovery Phase"]
        getSubInfo --> getWorkspaces[Find Log Analytics\nWorkspaces]
        getWorkspaces --> checkWatcher[Check Network\nWatcher Status]
        checkWatcher --> findFlowLogs[Find NSG\nFlow Logs]
    end
    
    findFlowLogs --> queryData[Query Log Analytics]
    
    subgraph Queries ["Data Collection Phase"]
        queryData --> networkQuery[Execute Network\nTraffic Queries]
        networkQuery --> securityQuery[Execute Security\nEvent Queries]
    end
    
    securityQuery --> argQuery[Query Azure Resource Graph]
    
    subgraph ARG ["Azure Resource Graph Phase"]
        argQuery --> findRelatedNICs[Find Related\nNetwork Interfaces]
        findRelatedNICs -->|Found| findVMs[Query Related VMs]
        findRelatedNICs -->|Not Found| findNSGRules[Query Related\nNSG Rules]
    end
    
    findVMs --> createReport
    findNSGRules --> createReport
    
    subgraph Reporting ["Reporting Phase"]
        createReport[Create Summary Report] --> mergeResults[Merge Network\nTraffic Results]
        mergeResults --> createCSV[Create Summary CSVs]
        createCSV --> createHTML[Create HTML Report]
    end
    
    createHTML --> finish([End])
    
    subgraph Legend ["Data Types"]
        outputDir[("Output Directory:\nip_traffic_<IP>_<timestamp>")] --- |Stores| jsonFiles[("JSON Files:\n- subscriptions.json\n- workspaces.json\n- network_watchers.json\n- flow_logs.json\n- network_traffic_*.json\n- related_resources.json\n- related_vms.json")]
        jsonFiles --- csvFiles[("CSV Files:\n- network_traffic_*.csv\n- ip_stats_*.csv\n- all_network_traffic.csv\n- related_resources.csv")]
        csvFiles --- reportFile[("HTML Report:\n- report.html")]
    end
    ````