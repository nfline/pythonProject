import subprocess
import requests
import json
import logging  # 修改点: 添加日志记录功能

# 配置日志  # 修改点: 添加日志配置
logging.basicConfig(filename='sync_users.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 修改点: 添加log_and_print函数，统一日志记录和终端输出
def log_and_print(message, level="info"):
    print(message)
    if level == "info":
        logging.info(message)
    elif level == "error":
        logging.error(message)
    elif level == "warning":
        logging.warning(message)
        
# Azure CLI命令获取用户EMAIL列表
def get_azure_users():
    command = 'az ad group member list --group "group" --query "[].mail" --output json'
    log_and_print("Running Azure CLI command to get user emails...")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"Azure CLI command failed: {result.stderr}")
    emails = [email.lower() for email in json.loads(result.stdout)]
    log_and_print(f"Azure users retrieved: {emails}")
    return emails

# 获取ThousandEyes现有用户EMAIL列表
def get_1000eyes_users(api_token):
    url = "https://api.thousandeyes.com/v6/users.json"
    headers = {"Authorization": f"Bearer {api_token}"}
    log_and_print("Fetching existing ThousandEyes users...")
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"ThousandEyes API request failed: {response.text}")
    users = response.json().get("users", [])
    emails = [user["email"].lower() for user in users if "email" in user]
    log_and_print(f"ThousandEyes users retrieved: {emails}")
    return emails

# 创建新用户到ThousandEyes
def create_1000eyes_user(api_token, email, login_account_group_id, account_group_id, role_ids):
    url = "https://api.thousandeyes.com/v6/users.json"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "name": email.split("@")[0],  # 使用邮箱前缀作为名字
        "email": email,
        "loginAccountGroupId": login_account_group_id,
        "accountGroupRoles": [
            {
                "accountGroupId": account_group_id,
                "roleIds": role_ids
            }
        ],
        "allAccountGroupRoleIds": role_ids
    }
    log_and_print(f"Creating user {email} in ThousandEyes...")
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code != 201:
        log_and_print(f"Failed to create user {email}: {response.text}")
    else:
        log_and_print(f"Successfully created user: {email}")

# 主逻辑
def sync_users(api_token, login_account_group_id, account_group_id, role_ids):
    azure_users = get_azure_users()
    te_users = get_1000eyes_users(api_token)
    
    new_users = set(azure_users) - set(te_users)
    log_and_print(f"New users to create: {new_users}")
    
    if new_users:
        log_and_print(f"Creating {len(new_users)} new users in ThousandEyes...")
        for email in new_users:
            create_1000eyes_user(api_token, email, login_account_group_id, account_group_id, role_ids)
    else:
        log_and_print("No new users to create.")

# 执行脚本
if __name__ == "__main__":
    THOUSAND_EYES_API_TOKEN = "your_api_token_here"  # 请替换为你的API Token
    LOGIN_ACCOUNT_GROUP_ID = "your_login_account_group_id_here"  # 替换为正确的 loginAccountGroupId
    ACCOUNT_GROUP_ID = "your_account_group_id_here"  # 替换为正确的 accountGroupId
    ROLE_IDS = [57, 1140]  # 替换为正确的角色ID
    sync_users(THOUSAND_EYES_API_TOKEN, LOGIN_ACCOUNT_GROUP_ID, ACCOUNT_GROUP_ID, ROLE_IDS)
