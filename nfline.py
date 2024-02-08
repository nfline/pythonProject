# 根据提供的excel表格验证url是否可达

import pandas as pd
import requests
# Excel文件路径
excel_path = 'test url.xlsx'

# 读取Excel文件
df = pd.read_excel(excel_path)

# 新增一列用于保存验证结果
df['Status'] = ''

# 遍历DataFrame中的每个URL
for index, row in df.iterrows():
    url = row['URL']
    try:
        response = requests.get(url, timeout=5)
        # 根据HTTP响应状态码判断URL有效性
        if response.status_code == 200:
            df.at[index, 'Status'] = 'Valid'
        else:
            df.at[index, 'Status'] = 'Invalid'
    except requests.RequestException:
        df.at[index, 'Status'] = 'Invalid'

# 将结果保存到新的Excel文件中
output_path = 'validated_urls.xlsx'
df.to_excel(output_path, index=False)
