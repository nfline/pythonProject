# NSGv2 - 优化版NSG流日志查询工具

这个工具是对原始`ip_nsg_finder`的优化版本，简化了查询Azure NSG流日志的流程。主要改进包括：

## 主要优化

1. **流程简化**：将原本多步骤操作合并为一个直接函数调用
2. **减少依赖**：直接从IP地址找到相关的工作区ID和订阅ID
3. **性能提升**：优化Azure Resource Graph查询，减少API调用次数
4. **结果集中**：将来自多个工作区的结果自动合并

## 使用方法

### 作为Python模块

```python
from azure.nsgv2 import query_ip_traffic

# 查询特定IP地址的流量（默认查询过去24小时）
results = query_ip_traffic("10.0.0.1")

# 指定时间范围（小时）
results = query_ip_traffic("10.0.0.1", time_range_hours=48)
```

### 通过命令行

```bash
# 安装依赖（如果需要）
pip install pandas openpyxl

# 查询特定IP地址的流量（默认24小时）
python -m azure.nsgv2.cli 10.0.0.1

# 指定时间范围（小时）
python -m azure.nsgv2.cli 10.0.0.1 --hours 48
```

## 返回结果

查询结果会：
1. 保存为JSON文件
2. 如果安装了pandas，也会保存为Excel文件
3. 返回包含每个工作区结果的字典对象

## 与原始版本的对比

原始的`ip_nsg_finder`需要多个步骤来查询流日志：
1. 查找与IP关联的NSG
2. 获取NSG的流日志配置
3. 从流日志配置中提取工作区ID
4. 生成KQL查询
5. 执行查询

而这个优化版只需要一步即可完成：
```python
results = query_ip_traffic("10.0.0.1")
```

## 关键依赖

1. Azure CLI：确保已登录Azure CLI并有权限访问相关资源
2. Python 3.6或更高版本
3. 可选：pandas和openpyxl（用于Excel导出）
