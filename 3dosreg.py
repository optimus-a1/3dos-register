# -*- coding: utf-8 -*-
import time
import json
import requests
import re
import imaplib
import email
from email.header import decode_header
from typing import Optional, Dict, Any, List
import random
import ssl
import csv
import os

# ==== 配置信息 ====
PASSWORD = "改为你的登陆密码"
REFERRAL_CODE = "056418"
COUNTRY_ID = "233"

# ==== 代理配置 ====
PROXY_HOST = "geo.iproyal.com"
PROXY_PORT = 12321
PROXY_USER = "改为你的"
PROXY_PASS = "改为你的"

# ==== 文件配置 ====
EMAIL_FILE = "gmail.txt"
RESULT_FILE = "results.csv"
MONITOR_EMAIL = "改为你要接收验证链接的邮件"

# ==== Gmail IMAP 配置 ====
GMAIL_APP_PASSWORD = "改为你接收验证链接的邮箱的密码"

# ==== YesCaptcha 配置 ====
API_KEY = "改为你的"
SITEKEY = "改为你的"

# ==== 构建代理配置 ====
PROXIES = {
    'http': f'http://{PROXY_USER}:{PROXY_PASS}@{PROXY_HOST}:{PROXY_PORT}',
    'https': f'http://{PROXY_USER}:{PROXY_PASS}@{PROXY_HOST}:{PROXY_PORT}'
}

# ==== API URLs ====
LOGIN_URL = "https://api.dashboard.3dos.io/api/auth/login"
API_KEY_URL = "https://api.dashboard.3dos.io/api/profile/generate-api-key"

# ==== 请求头 ====
API_HEADERS = {
    "accept": "application/json, text/plain, */*",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
    "content-type": "application/json",
    "origin": "https://dashboard.3dos.io",
    "referer": "https://dashboard.3dos.io/",
    "sec-ch-ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
}

class ProxyManager:
    def __init__(self):
        self.proxies = PROXIES
        self.current_ip = None
    
    def get_new_proxy_ip(self) -> str:
        """获取新的代理IP地址"""
        try:
            time.sleep(random.uniform(2, 5))
            resp = requests.get('https://httpbin.org/ip', proxies=self.proxies, timeout=30)
            if resp.status_code == 200:
                ip = resp.json().get('origin', '未知')
                self.current_ip = ip
                print(f"🌐 获取新代理IP: {ip}")
                return ip
            else:
                print("❌ 获取代理IP失败")
                return "未知"
        except Exception as e:
            print(f"❌ 获取代理IP异常: {e}")
            return "未知"
    
    def refresh_proxy_session(self) -> dict:
        """刷新代理会话，返回新的代理配置"""
        try:
            print("🔄 刷新代理会话...")
            test_resp = requests.get(
                'https://httpbin.org/ip', 
                proxies=self.proxies, 
                timeout=30,
                params={'t': int(time.time()), 'r': random.randint(1000, 9999)}
            )
            
            if test_resp.status_code == 200:
                new_ip = test_resp.json().get('origin', '未知')
                if new_ip != self.current_ip:
                    print(f"✅ 代理IP已更新: {self.current_ip} -> {new_ip}")
                    self.current_ip = new_ip
                else:
                    print(f"⚠️ 代理IP未改变: {new_ip}")
                return self.proxies
            else:
                print("❌ 代理会话刷新失败")
                return self.proxies
        except Exception as e:
            print(f"❌ 刷新代理会话异常: {e}")
            return self.proxies

class IMAPEmailVerifier:
    def __init__(self, email_address: str, app_password: str):
        self.email_address = email_address
        self.app_password = app_password
        self.imap_server = None
        
        # 配置requests会话，添加用户代理和超时设置
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def connect(self) -> bool:
        """连接到Gmail IMAP服务器"""
        try:
            print(f"📧 连接到Gmail IMAP服务器...")
            print(f"📮 邮箱: {self.email_address}")
            
            context = ssl.create_default_context()
            self.imap_server = imaplib.IMAP4_SSL('imap.gmail.com', 993, ssl_context=context)
            result = self.imap_server.login(self.email_address, self.app_password)
            
            if result[0] == 'OK':
                print("✅ Gmail IMAP 连接成功")
                self.imap_server.select('INBOX')
                status, messages = self.imap_server.search(None, 'ALL')
                total_emails = len(messages[0].split()) if messages[0] else 0
                print(f"📊 收件箱总邮件数: {total_emails}")
                return True
            else:
                print(f"❌ 登录失败: {result}")
                return False
        except Exception as e:
            print(f"❌ Gmail IMAP 连接失败: {e}")
            return False
    
    def test_connection(self) -> bool:
        """测试IMAP连接"""
        print("🧪 测试IMAP连接...")
        success = self.connect()
        return success
    
    def get_latest_3dos_verification_link(self) -> Optional[str]:
        """获取最新的3DOS验证链接"""
        if not self.imap_server:
            if not self.connect():
                return None
        
        try:
            self.imap_server.select('INBOX')
            print("🔍 搜索最新的3DOS验证邮件...")
            search_criteria = 'FROM "noreply@3dos.io" SUBJECT "Please Verify Your Email"'
            status, message_ids = self.imap_server.search(None, search_criteria)
            
            if status != 'OK' or not message_ids[0]:
                print("❌ 未找到3DOS验证邮件")
                return None
            
            email_ids = message_ids[0].split()
            print(f"📬 找到 {len(email_ids)} 封验证邮件")
            
            if not email_ids:
                return None
            
            latest_email_id = email_ids[-1]
            print(f"📧 处理最新邮件 (ID: {latest_email_id.decode()})")
            status, email_data = self.imap_server.fetch(latest_email_id, '(RFC822)')
            
            if status != 'OK':
                print("❌ 获取邮件内容失败")
                return None
            
            email_message = email.message_from_bytes(email_data[0][1])
            subject = self._decode_header(email_message.get('Subject', ''))
            from_addr = self._decode_header(email_message.get('From', ''))
            
            print(f"📧 最新验证邮件信息:")
            print(f"   主题: {subject}")
            print(f"   发件人: {from_addr}")
            
            verify_link = self._extract_verification_link_from_email(email_message)
            return verify_link
        except Exception as e:
            print(f"❌ 处理邮件时出错: {e}")
            return None
    
    def _extract_verification_link_from_email(self, email_message) -> Optional[str]:
        """从邮件对象中提取验证链接"""
        try:
            email_content = ""
            
            if email_message.is_multipart():
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    if content_type in ["text/html", "text/plain"]:
                        payload = part.get_payload(decode=True)
                        if payload:
                            email_content += payload.decode('utf-8', errors='ignore')
            else:
                payload = email_message.get_payload(decode=True)
                if payload:
                    email_content = payload.decode('utf-8', errors='ignore')
            
            return self._extract_verification_link(email_content)
        except Exception as e:
            print(f"❌ 解析邮件失败: {e}")
            return None
    
    def _extract_verification_link(self, email_content: str) -> Optional[str]:
        """从邮件内容中提取验证链接"""
        try:
            patterns = [
                r'https://api\.dashboard\.3dos\.io/api/email/verify/\d+\?[^"\s<>]+',
                r'href=["\']([^"\']*api\.dashboard\.3dos\.io/api/email/verify/[^"\']*)["\']',
                r'https://mandrillapp\.com/track/click/[^/]+/api\.dashboard\.3dos\.io\?p=[^"\s<>]+',
                r'(https://[^"\s<>]*dashboard\.3dos\.io[^"\s<>]*verify[^"\s<>]*)'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, email_content, re.IGNORECASE)
                if matches:
                    link = matches[0]
                    if isinstance(link, tuple):
                        link = link[0] if link[0] else link[1]
                    
                    link = link.replace('&amp;', '&')
                    print(f"✅ 找到验证链接: {link}")
                    return link
            
            print("❌ 未能提取到验证链接")
            return None
        except Exception as e:
            print(f"❌ 提取验证链接失败: {e}")
            return None
    
    def verify_email_automatically(self, verify_link: str, max_retries: int = 2) -> bool:
        """自动执行邮箱验证（带重试机制）"""
        print(f"\n🔐 开始自动验证邮箱...")
        print(f"🔗 验证链接: {verify_link}")
        
        for attempt in range(max_retries + 1):
            if attempt > 0:
                print(f"\n🔄 重试第 {attempt} 次...")
                time.sleep(3)
            
            try:
                print("📡 发送验证请求...")
                response = self.session.get(verify_link, timeout=30, allow_redirects=True)
                
                print(f"📊 响应状态码: {response.status_code}")
                print(f"🔄 最终URL: {response.url}")
                
                if response.history:
                    print(f"🔄 发生了 {len(response.history)} 次重定向")
                
                if response.status_code == 200:
                    print("✅ HTTP请求成功 (200)")
                    
                    success_indicators = [
                        'verified successfully', 'verification successful', 'email verified',
                        'account activated', 'verification complete', 'success',
                        '"verified":true', '"status":"success"'
                    ]
                    
                    error_indicators = [
                        'verification failed', 'invalid token', 'expired', 'error',
                        'failed', 'invalid', '"verified":false', '"status":"error"'
                    ]
                    
                    content_lower = response.text.lower()
                    found_success = any(indicator in content_lower for indicator in success_indicators)
                    found_error = any(indicator in content_lower for indicator in error_indicators)
                    
                    if found_success and not found_error:
                        print("🎉 邮箱验证成功！")
                        return True
                    elif found_error:
                        if attempt < max_retries:
                            print(f"❌ 第 {attempt + 1} 次验证失败，准备重试...")
                            continue
                        else:
                            print("❌ 所有重试均失败")
                            return False
                    else:
                        if response.url != verify_link:
                            success_urls = ['success', 'verified', 'complete', 'dashboard']
                            if any(keyword in response.url.lower() for keyword in success_urls):
                                print("🎉 基于重定向URL判断验证成功")
                                return True
                        
                        if attempt < max_retries:
                            print(f"🔄 第 {attempt + 1} 次状态不明确，准备重试...")
                            continue
                        else:
                            print("❌ 所有重试后状态仍不明确")
                            return False
                
                elif response.status_code == 404:
                    print("❌ 验证链接无效或已过期 (404)")
                    return False
                    
                elif response.status_code >= 400:
                    if attempt < max_retries:
                        print(f"🔄 第 {attempt + 1} 次服务器错误，准备重试...")
                        continue
                    else:
                        print("❌ 所有重试均遇到服务器错误")
                        return False
                        
            except requests.exceptions.Timeout:
                if attempt < max_retries:
                    print(f"🔄 第 {attempt + 1} 次超时，准备重试...")
                    continue
                else:
                    print("❌ 所有重试均超时")
                    return False
                    
            except Exception as e:
                if attempt < max_retries:
                    print(f"🔄 第 {attempt + 1} 次异常，准备重试...")
                    continue
                else:
                    print("❌ 所有重试均异常")
                    return False
        
        return False
    
    def _decode_header(self, header_value: str) -> str:
        """解码邮件头"""
        if not header_value:
            return ""
        try:
            decoded_parts = decode_header(header_value)
            decoded_string = ""
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_string += part.decode(encoding, errors='ignore')
                    else:
                        decoded_string += part.decode('utf-8', errors='ignore')
                else:
                    decoded_string += str(part)
            return decoded_string.strip()
        except Exception:
            return str(header_value)
    
    def close(self):
        """关闭连接"""
        if self.imap_server:
            try:
                self.imap_server.close()
                self.imap_server.logout()
                print("📧 IMAP连接已关闭")
            except:
                pass
        self.session.close()

class Registration:
    def __init__(self, proxies: dict):
        self.session = requests.Session()
        self.session.proxies.update(proxies)
        self.setup_headers()
        
    def setup_headers(self):
        """设置基础请求头"""
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0"
        })
    
    def get_initial_session(self, referral_code: str) -> bool:
        """获取初始session"""
        try:
            print("🌐 建立初始session...")
            home_resp = self.session.get("https://dashboard.3dos.io/", timeout=30)
            register_url = f"https://dashboard.3dos.io/register?ref_code={referral_code}"
            register_resp = self.session.get(register_url, timeout=30)
            print(f"✅ Session建立成功")
            return True
        except Exception as e:
            print(f"❌ 建立session失败: {e}")
            return False
    
    def solve_captcha(self, referral_code: str) -> Optional[str]:
        """解决验证码"""
        website_url = f"https://dashboard.3dos.io/register?ref_code={referral_code}"
        task_data = {
            "clientKey": API_KEY,
            "task": {
                "type": "RecaptchaV2TaskProxyless",
                "websiteURL": website_url,
                "websiteKey": SITEKEY,
                "isInvisible": True,
                "userAgent": self.session.headers.get("User-Agent"),
                "pageAction": "register"
            }
        }
        
        try:
            print("🔄 创建验证码任务...")
            create_resp = requests.post("https://api.yescaptcha.com/createTask", json=task_data, timeout=30)
            create_result = create_resp.json()
            
            if not create_result.get("taskId"):
                print("❌ 创建任务失败:", create_result)
                return None
                
            task_id = create_result["taskId"]
            print(f"✅ 任务创建成功: {task_id}")
            
            for i in range(60):
                time.sleep(3)
                result_resp = requests.post("https://api.yescaptcha.com/getTaskResult", json={
                    "clientKey": API_KEY,
                    "taskId": task_id
                }, timeout=30)
                result = result_resp.json()
                
                if result.get("status") == "ready":
                    token = result["solution"]["gRecaptchaResponse"]
                    print(f"✅ 获取验证码成功!")
                    if len(token) > 50:
                        return token
                    else:
                        print("⚠️ 验证码token格式异常，重新获取...")
                        continue
                elif result.get("status") == "processing":
                    print(f"⌛ 等待中... ({i+1}/60)")
                else:
                    print(f"⚠️ 状态异常: {result}")
            
            print("❌ 验证码解决超时")
            return None
            
        except Exception as e:
            print(f"❌ 验证码解决异常: {e}")
            return None
    
    def register_account(self, email: str, password: str, country_id: str, 
                        referral_code: str, captcha_token: str) -> Optional[Dict[str, Any]]:
        """注册账户"""
        print("⏱️ 等待5秒确保验证码生效...")
        time.sleep(5)
        
        referer_url = f"https://dashboard.3dos.io/register?ref_code={referral_code}"
        self.session.headers.update({
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": "https://dashboard.3dos.io",
            "Referer": referer_url,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site"
        })
        
        payload = {
            "email": email,
            "password": password,
            "acceptTerms": True,
            "country_id": country_id,
            "referred_by": referral_code,
            "captcha_token": captcha_token
        }
        
        try:
            print("📝 发送注册请求...")
            resp = self.session.post(
                "https://api.dashboard.3dos.io/api/auth/register",
                json=payload,
                timeout=30
            )
            
            print(f"📡 状态码: {resp.status_code}")
            
            if resp.status_code == 200:
                result = resp.json()
                if result.get("flag") and result.get("status") == "Success":
                    print("🎉 注册成功！")
                    data = result['data']
                    print(f"📧 邮箱: {data['email']}")
                    print(f"🆔 用户ID: {data['id']}")
                    return data
                else:
                    print(f"❌ 注册失败: {result.get('message')}")
                    return None
            else:
                print(f"❌ HTTP错误: {resp.status_code}")
                print(f"响应内容: {resp.text}")
                return None
                
        except Exception as e:
            print(f"❌ 注册异常: {e}")
            return None

def login(email: str, proxies: dict = None) -> Optional[str]:
    """登录账户并返回access_token"""
    payload = {
        "email": email,
        "password": PASSWORD
    }

    try:
        time.sleep(random.uniform(1, 3))
        if proxies:
            resp = requests.post(LOGIN_URL, headers=API_HEADERS, json=payload, timeout=30, proxies=proxies)
        else:
            resp = requests.post(LOGIN_URL, headers=API_HEADERS, json=payload, timeout=30)

        print(f"[登录] {email} 状态码: {resp.status_code}")
        if resp.status_code == 200:
            result = resp.json()
            if (result.get('flag') is True and 
                result.get('status') == 'Success' and 
                result.get('data', {}).get('access_token')):
                access_token = result['data']['access_token']
                print(f"[✓] {email} 登录成功!")
                return access_token
            else:
                print(f"[!] {email} 登录失败：响应格式异常")
                print(f"响应内容: {resp.text}")
        else:
            print(f"[!] {email} 登录失败: HTTP {resp.status_code}")
            print(f"响应内容: {resp.text}")
    except requests.exceptions.Timeout:
        print(f"[!] {email} 登录请求超时")
    except requests.exceptions.ConnectionError:
        print(f"[!] {email} 连接错误")
    except Exception as e:
        print(f"[!] {email} 登录请求异常: {e}")

    return None

def get_api_key(token: str, email: str, proxies: dict = None) -> Optional[str]:
    """获取API密钥"""
    headers = API_HEADERS.copy()
    headers["authorization"] = f"Bearer {token}"

    for attempt in range(3):
        print(f"[*] {email} 第 {attempt+1} 次尝试获取 API Key...")
        try:
            time.sleep(random.uniform(1, 2))
            if proxies:
                resp = requests.post(API_KEY_URL, headers=headers, json={}, timeout=30, proxies=proxies)
            else:
                resp = requests.post(API_KEY_URL, headers=headers, json={}, timeout=30)

            print(f"[*] {email} API Key请求状态码: {resp.status_code}")
            if resp.status_code == 200:
                result = resp.json()
                print(f"[*] {email} API Key响应: {resp.text}")

                if isinstance(result.get("data"), dict) and "api_secret" in result["data"]:
                    api_secret = result["data"]["api_secret"]
                    print(f"[✓] {email} API Key获取成功: {api_secret}")
                    return api_secret
                else:
                    print(f"[-] {email} API Key 响应格式异常")
            else:
                print(f"[-] {email} API Key 获取失败: {resp.status_code}")
                print(f"响应内容: {resp.text}")
        except requests.exceptions.Timeout:
            print(f"[!] {email} API Key请求超时")
        except Exception as e:
            print(f"[!] {email} 获取 API Key 异常: {e}")

        if attempt < 2:
            print(f"[*] {email} 等待3秒后重试...")
            time.sleep(3)

    print(f"[!] {email} 所有API Key获取尝试都失败了")
    return None

def load_emails() -> List[str]:
    """从文件加载邮箱列表"""
    try:
        with open(EMAIL_FILE, 'r', encoding='utf-8') as f:
            emails = [line.strip() for line in f if line.strip()]
        print(f"📧 加载了 {len(emails)} 个邮箱")
        return emails
    except FileNotFoundError:
        print(f"❌ 文件 {EMAIL_FILE} 不存在")
        return []
    except Exception as e:
        print(f"❌ 读取邮箱文件失败: {e}")
        return []

def save_result(email: str, access_token: str, api_key: str, status: str):
    """保存结果到CSV文件"""
    try:
        file_exists = os.path.exists(RESULT_FILE)
        
        with open(RESULT_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            if not file_exists:
                writer.writerow(["email", "accessToken", "apiKey", "status", "timestamp"])
            
            writer.writerow([email, access_token, api_key, status, time.strftime("%Y-%m-%d %H:%M:%S")])
        
        print(f"💾 结果已保存: {email}")
        
    except Exception as e:
        print(f"❌ 保存结果失败: {e}")

def main():
    """主函数 - 集成邮箱验证功能"""
    print("🚀 开始批量注册3DOS账户 - 集成邮箱验证版")
    print("=" * 60)
    
    # 加载邮箱列表
    emails = load_emails()
    if not emails:
        print("❌ 没有可用的邮箱，程序退出")
        return
    
    # 初始化组件
    proxy_manager = ProxyManager()
    proxy_manager.get_new_proxy_ip()
    
    # 使用邮件验证器
    email_verifier = IMAPEmailVerifier(MONITOR_EMAIL, GMAIL_APP_PASSWORD)
    
    # 测试邮件验证器连接
    if not email_verifier.test_connection():
        print("❌ 无法连接到Gmail，程序退出")
        return
    
    success_count = 0
    total_count = len(emails)
    
    for i, email_addr in enumerate(emails, 1):
        print(f"\n{'='*60}")
        print(f"🔄 处理第 {i}/{total_count} 个邮箱: {email_addr}")
        print(f"{'='*60}")
        
        try:
            # 刷新代理
            if i > 1:
                proxy_manager.refresh_proxy_session()
                time.sleep(random.uniform(3, 7))
            
            # 初始化注册器
            registration = Registration(proxy_manager.proxies)
            
            # 建立初始会话
            if not registration.get_initial_session(REFERRAL_CODE):
                print("❌ 建立会话失败，跳过此邮箱")
                save_result(email_addr, "", "", "建立会话失败")
                continue
            
            # 解决验证码
            captcha_token = registration.solve_captcha(REFERRAL_CODE)
            if not captcha_token:
                print("❌ 验证码解决失败，跳过此邮箱")
                save_result(email_addr, "", "", "验证码解决失败")
                continue
            
            # 注册账户
            register_result = registration.register_account(
                email_addr, PASSWORD, COUNTRY_ID, REFERRAL_CODE, captcha_token
            )
            
            if not register_result:
                print("❌ 注册失败，跳过此邮箱")
                save_result(email_addr, "", "", "注册失败")
                continue
            
            # 等待邮件到达后直接提取最新验证链接
            print("⏱️ 等待20秒让邮件到达...")
            time.sleep(20)
            
            verification_link = email_verifier.get_latest_3dos_verification_link()
            
            if not verification_link:
                print("❌ 未找到验证邮件或无法提取验证链接，跳过此邮箱")
                save_result(email_addr, "", "", "验证邮件获取失败")
                continue
            
            # 使用集成的验证功能（带重试机制）
            verification_success = email_verifier.verify_email_automatically(verification_link, max_retries=2)
            
            if not verification_success:
                print("❌ 邮箱验证失败（已重试2次），跳过此邮箱")
                save_result(email_addr, "", "", "邮箱验证失败")
                continue
            
            # 短暂等待，确保验证生效
            print("⏱️ 等待3秒确保验证生效...")
            time.sleep(3)
            
            # 使用新的登录函数
            access_token = login(email_addr, proxy_manager.proxies)
            if not access_token:
                print("❌ 登录失败，跳过此邮箱")
                save_result(email_addr, "", "", "登录失败")
                continue
            
            # 等待60秒后获取API密钥
            print(f"[*] {email_addr} 登录成功，等待 60 秒...")
            time.sleep(60)
            
            # 使用新的API密钥获取函数
            api_key = get_api_key(access_token, email_addr, proxy_manager.proxies)
            if not api_key:
                print("❌ 获取API密钥失败，跳过此邮箱")
                save_result(email_addr, access_token, "", "API Key获取失败")
                continue
            
            # 保存成功结果
            save_result(email_addr, access_token, api_key, "成功")
            success_count += 1
            
            print(f"🎉 {email_addr} 处理完成！")
            print(f"✅ 成功: {success_count}/{total_count}")
            print(f"📊 当前成功率: {(success_count/i)*100:.1f}%")
            
            # 添加随机延迟，避免请求过快
            if i < total_count:
                delay = random.uniform(15, 25)
                print(f"⏱️ 等待 {delay:.1f} 秒后处理下一个...")
                time.sleep(delay)
            
        except Exception as e:
            print(f"❌ 处理 {email_addr} 时发生异常: {e}")
            save_result(email_addr, "", "", f"异常: {str(e)}")
            continue
    
    # 关闭邮件验证器连接
    email_verifier.close()
    
    print(f"\n{'='*60}")
    print(f"🏁 批量注册完成！")
    print(f"📊 总数: {total_count}, 成功: {success_count}, 失败: {total_count - success_count}")
    print(f"📁 结果已保存到: {RESULT_FILE}")
    print(f"🎯 最终成功率: {(success_count/total_count)*100:.1f}%")
    
    # 显示成功的账户信息
    if success_count > 0:
        print(f"\n📋 成功注册的账户:")
        try:
            with open(RESULT_FILE, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader, 1):
                    if row['status'] == '成功':
                        print(f"  {i}. {row['email']} - Token: {row['accessToken'][:20]}... - API Key: {row['apiKey']}")
        except Exception as e:
            print(f"❌ 读取结果文件失败: {e}")
    
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
