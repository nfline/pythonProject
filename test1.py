import subprocess
import requests
import json

# Azure CLI命令获取用户EMAIL列表
def get_azure_users():
    command = "az ad user list --query '[].mail' --output json"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"Azure CLI command failed: {result.stderr}")
    return json.loads(result.stdout)

# 获取ThousandEyes现有用户EMAIL列表
def get_1000eyes_users(api_token):
    url = "https://api.thousandeyes.com/v6/users.json"
    headers = {"Authorization": f"Bearer {api_token}"}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"ThousandEyes API request failed: {response.text}")
    users = response.json().get("users", [])
    return [user["email"] for user in users if "email" in user]

# 创建新用户到ThousandEyes
def create_1000eyes_user(api_token, email):
    url = "https://api.thousandeyes.com/v6/users.json"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "firstName": email.split("@")[0],  # 使用邮箱前缀作为名字
        "lastName": "User",
        "email": email,
        "roleId": 2  # 角色ID，根据实际情况调整
    }
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code != 201:
        print(f"Failed to create user {email}: {response.text}")
    else:
        print(f"Successfully created user: {email}")

# 主逻辑
def sync_users(api_token):
    azure_users = get_azure_users()
    te_users = get_1000eyes_users(api_token)
    
    new_users = set(azure_users) - set(te_users)
    
    if new_users:
        print(f"Creating {len(new_users)} new users in ThousandEyes...")
        for email in new_users:
            create_1000eyes_user(api_token, email)
    else:
        print("No new users to create.")

# 执行脚本
if __name__ == "__main__":
    THOUSAND_EYES_API_TOKEN = "your_api_token_here"  # 请替换为你的API Token
    sync_users(THOUSAND_EYES_API_TOKEN)
