---

## 🚀 3DOS 自动注册脚本

使用 Python 脚本自动完成 [3DOS](https://dashboard.3dos.io/) 平台账号注册、邮箱验证、登录提取 API Key，全自动、支持代理、验证码识别、IMAP 邮箱解析。

---
注册成功后可以用华哥的脚本进行注册操作https://github.com/sdohuajia/3dos

### 📦 功能特点

* ✅ 支持 Gmail 邮箱 IMAP 自动提取验证链接
* ✅ 集成 YesCaptcha 自动识别验证码
* ✅ 使用代理注册（IPRoyal 代理支持）
* ✅ 自动登录提取 `access_token` 和 `api_key`
* ✅ 支持批量邮箱注册（从 `gmail.txt` 加载）
* ✅ 所有结果保存到 `results.csv`
* ✅ 稳定、高度自动化，适合批量账号管理

---

### 📁 文件结构说明

```bash
.
├── 3dosreg.py            # 主程序入口
├── gmail.txt             # 邮箱列表，每行一个 Gmail
├── results.csv           # 注册成功或失败的结果输出
└── README.md             # 使用说明
```

---

### ✅ 环境要求

* Python 3.8 及以上
* 系统需联网，支持代理访问
* Gmail 开启 IMAP 功能并配置 **应用专用密码**

---

### 🔧 安装依赖

先安装 Python 依赖：

```bash
pip install requests
```

如需支持 IMAP 及 HTML 邮件解析（建议）：

```bash
pip install email-validator
```

---

### 🔐 配置说明

编辑脚本开头的以下参数：

```python
PASSWORD = "密码"                # 注册时统一使用的密码
REFERRAL_CODE = "056418"             # 推荐码，可改为你自己的
COUNTRY_ID = "233"                   # 国家代码（233为中国）

GMAIL_APP_PASSWORD = "xxxx xxxx xxxx xxxx"  # Gmail 的应用专用密码
MONITOR_EMAIL = "your@gmail.com"            # 用于接收验证链接的邮箱
EMAIL_FILE = "gmail.txt"                    # 存放要注册的邮箱列表

# YesCaptcha 配置（用于自动识别验证码）（打码注册链接https://yescaptcha.com/i/7leVLd）
API_KEY = "你的YesCaptcha API Key"
SITEKEY = "你的"

# IPRoyal 代理配置（示例）（代理注册链接https://iproyal.cn/?r=398252）
PROXY_HOST = "geo.iproyal.com"
PROXY_PORT = 12321
PROXY_USER = "your_user"
PROXY_PASS = "your_pass"
```

---

### 📧 Gmail 设置指南

1. 登录 Gmail → 设置 → **转发和 POP/IMAP**
2. 启用 IMAP
3. 在 [https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords) 创建一个 **应用密码**，用于脚本登录（不是你的 Gmail 密码）
4. 保存该 16 位密码到 `GMAIL_APP_PASSWORD`

---

### 📨 添加邮箱列表

编辑 `gmail.txt` 文件，每行一个邮箱：

```
adfkasdasdf@gmail.com
adfakdfja@gmail.com
example123@gmail.com
...
```

---

### ▶️ 运行脚本

```bash
python3 3dosreg.py
```

脚本将依次：

1. 自动访问注册页 → 获取验证码并注册账户
2. 等待验证邮件 → 自动点击验证链接
3. 登录账号 → 获取 API Key
4. 将结果写入 `results.csv`

---

### 📁 输出文件：`results.csv`

成功和失败的邮箱都会写入：

| email | accessToken | apiKey | status | timestamp |
| ----- | ----------- | ------ | ------ | --------- |

---

### ❗ 常见问题

| 问题            | 解决方案                           |
| ------------- | ------------------------------ |
| Gmail 登录失败    | 检查是否启用 IMAP、是否使用应用密码           |
| 没收到验证邮件       | 等待时间不足，脚本默认等待 20 秒，可调整为 60 秒以上 |
| YesCaptcha 超时 | 检查 API Key 是否正确，额度是否足够         |
| 代理无效          | 替换为有效的代理账户（如 IPRoyal）          |

---

### 🤝 特别说明

* 本脚本仅供学习使用，请勿用于恶意用途


---


