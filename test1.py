import subprocess
import requests
import json

# Azure CLI命令获取用户EMAIL列表
def get_azure_users():
    command = 'az ad group member list --group "group" --query "[].mail" --output json'
    print("Running Azure CLI command to get user emails...")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"Azure CLI command failed: {result.stderr}")
    emails = [email.lower() for email in json.loads(result.stdout)]
    print(f"Azure users retrieved: {emails}")
    return emails

# 获取ThousandEyes现有用户EMAIL列表
def get_1000eyes_users(api_token):
    url = "https://api.thousandeyes.com/v6/users.json"
    headers = {"Authorization": f"Bearer {api_token}"}
    print("Fetching existing ThousandEyes users...")
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"ThousandEyes API request failed: {response.text}")
    users = response.json().get("users", [])
    emails = [user["email"].lower() for user in users if "email" in user]
    print(f"ThousandEyes users retrieved: {emails}")
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
    print(f"Creating user {email} in ThousandEyes...")
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code != 201:
        print(f"Failed to create user {email}: {response.text}")
    else:
        print(f"Successfully created user: {email}")

# 主逻辑
def sync_users(api_token, login_account_group_id, account_group_id, role_ids):
    azure_users = get_azure_users()
    te_users = get_1000eyes_users(api_token)
    
    new_users = set(azure_users) - set(te_users)
    print(f"New users to create: {new_users}")
    
    if new_users:
        print(f"Creating {len(new_users)} new users in ThousandEyes...")
        for email in new_users:
            create_1000eyes_user(api_token, email, login_account_group_id, account_group_id, role_ids)
    else:
        print("No new users to create.")

# 执行脚本
if __name__ == "__main__":
    THOUSAND_EYES_API_TOKEN = "your_api_token_here"  # 请替换为你的API Token
    LOGIN_ACCOUNT_GROUP_ID = "your_login_account_group_id_here"  # 替换为正确的 loginAccountGroupId
    ACCOUNT_GROUP_ID = "your_account_group_id_here"  # 替换为正确的 accountGroupId
    ROLE_IDS = [57, 1140]  # 替换为正确的角色ID
    sync_users(THOUSAND_EYES_API_TOKEN, LOGIN_ACCOUNT_GROUP_ID, ACCOUNT_GROUP_ID, ROLE_IDS)
