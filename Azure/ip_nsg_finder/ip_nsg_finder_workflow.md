```mermaid
flowchart TD
    A[开始] --> B[解析命令行参数]
    B --> C[检查Azure CLI安装与登录]
    C --> D[设置日志]
    D --> E[初始化输出目录]
    
    %% 主要分析流程
    E --> F[查找关联的网络接口]
    F --> G[检查网络接口关联的子网]
    G --> H[获取NSG流日志配置]
    
    %% 流日志配置获取流程
    H --> I[提取资源组和NSG名称]
    I --> J[使用Resource Graph查询流日志配置]
    J --> K[保存流日志配置信息]
    
    %% Log Analytics查询流程
    K --> L[提取Log Analytics工作区信息]
    L --> M[验证工作区ID格式]
    M --> N[保存工作区映射]
    
    %% KQL查询构建和执行
    N --> O[为每个NSG构建KQL查询]
    O --> P[创建临时查询文件]
    P --> Q[通过Azure CLI执行Log Analytics查询]
    Q --> R{查询成功?}
    
    R -->|成功| S[处理查询结果]
    R -->|失败| T[记录错误信息]
    
    S --> U[转换为DataFrame]
    U --> V[保存为JSON和Excel]
    V --> W[分析完成]
    
    T --> W
    
    %% 子流程：查找网络接口的详细步骤
    subgraph 查找网络接口详细流程
        F1[使用Resource Graph查询网络接口] --> F2[筛选包含目标IP的配置]
        F2 --> F3[提取子网ID和直接关联的NSG]
        F3 --> F4[使用az network vnet subnet show获取子网NSG]
    end
    
    %% 子流程：流日志配置获取的详细步骤
    subgraph 流日志获取详细流程
        H1[从获取的NSG IDs中提取资源信息] --> H2[使用Resource Graph查询流日志资源]
        H2 --> H3[筛选指定目标NSG的流日志]
        H3 --> H4[提取工作区ID和状态]
    end
    
    %% 子流程：KQL查询构建的详细步骤
    subgraph KQL查询构建详细流程
        O1[计算开始和结束时间] --> O2[创建基本查询]
        O2 --> O3[使用between设置时间范围]
        O3 --> O4[添加流状态过滤器(FlowStatus_s == "A")]
        O4 --> O5[添加IP过滤器(SrcIP_s或DestIP_s)]
        O5 --> O6[根据NSG名称添加NSG过滤器]
        O6 --> O7[添加结果投影和按时间排序]
    end
```
