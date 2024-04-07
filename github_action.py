#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import os
import random
import re
import smtplib
import ssl
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests
from requests.utils import cookiejar_from_dict, dict_from_cookiejar

USER_AGENT = [
    "Mozilla/5.0 (Linux; U; Android 11; zh-cn; PDYM20 Build/RP1A.200720.011) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/70.0.3538.80 Mobile Safari/537.36 HeyTapBrowser/40.7.24.9"
    "Mozilla/5.0 (Linux; Android 12; Redmi K30 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36"
]


class Push_messages:
    class Server_chan:
        def __init__(self, send_key: str) -> None:
            self.send_key = send_key

        def send_message(self, content: str) -> bool:
            data = {"title": "联想签到", "desp": content}
            response = requests.post(
                f"https://sctapi.ftqq.com/{self.send_key}.send", data=data
            )
            res_data = response.json().get("data")
            pushid = res_data.get("pushid")
            readkey = res_data.get("readkey")
            result = requests.get(
                f"https://sctapi.ftqq.com/push?id={pushid}&readkey={readkey}"
            )
            return True if result.json().get("code") == 0 else False

def set_push_type():
    for type, key in config.get("message_push").items():
        key_list = key.values()
        if "".join(key_list):
            return getattr(Push_messages(), type)(*key_list).send_message
    else:
        return logger

def login(username, password):
    def get_cookie():
        session.headers = {
            "user-agent": ua,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }
        session.get(url="https://reg.lenovo.com.cn/auth/rebuildleid")
        session.get(
            url="https://reg.lenovo.com.cn/auth/v1/login?ticket=5e9b6d3d-4500-47fc-b32b-f2b4a1230fd3&ru=https%3A%2F%2Fmclub.lenovo.com.cn%2F"
        )
        data = f"account={username}&password={base64.b64encode(str(password).encode()).decode()}\
            &ps=1&ticket=5e9b6d3d-4500-47fc-b32b-f2b4a1230fd3&codeid=&code=&slide=v2&applicationPlatform=2&shopId=\
                1&os=web&deviceId=BIT%2F8ZTwWmvKpMsz3bQspIZRY9o9hK1Ce3zKIt5js7WSUgGQNnwvYmjcRjVHvJbQ00fe3T2wxgjZAVSd\
                    OYl8rrQ%3D%3D&t=1655187183738&websiteCode=10000001&websiteName=%25E5%2595%2586%25E5%259F%258E%25E\
                        7%25AB%2599&forwardPageUrl=https%253A%252F%252Fmclub.lenovo.com.cn%252F"
        login_response = session.post(
            url="https://reg.lenovo.com.cn/auth/v2/doLogin", data=data
        )
        if login_response.json().get("ret") == "1":  # 账号或密码错误
            return None
        ck_dict = dict_from_cookiejar(session.cookies)
        session.cookies = cookiejar_from_dict(ck_dict)
        return session

    session = requests.Session()
    session.headers = {
        "user-agent": ua,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }

    session = get_cookie()
    return session


def sign(session):
    res = session.get("https://mclub.lenovo.com.cn/sign")
    token = re.findall('token\s*=\s*"(.*?)"', res.text)[0]
    data = f"_token={token}&memberSource=1"
    headers = {
        "Host": "mclub.lenovo.com.cn",
        "pragma": "no-cache",
        "cache-control": "no-cache",
        "accept": "application/json, text/javascript, */*; q=0.01",
        "origin": "https://mclub.lenovo.com.cn",
        "x-requested-with": "XMLHttpRequest",
        "user-agent": ua
                      + "/lenovoofficialapp/16554342219868859_10128085590/newversion/versioncode-1000080/",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "referer": "https://mclub.lenovo.com.cn/signlist?pmf_group=in-push&pmf_medium=app&pmf_source=Z00025783T000",
        "accept-language": "zh-CN,en-US;q=0.8",
    }
    sign_response = session.post(
        "https://mclub.lenovo.com.cn/signadd", data=data, headers=headers
    )
    sign_days = (
        session.get(url="https://mclub.lenovo.com.cn/getsignincal")
        .json()
        .get("signinCal")
        .get("continueCount")
    )
    sign_user_info = session.get("https://mclub.lenovo.com.cn/signuserinfo")
    try:
        serviceAmount = sign_user_info.json().get("serviceAmount")
        ledou = sign_user_info.json().get("ledou")
    except Exception as e:
        serviceAmount, ledou = None, None
    session.close()
    if sign_response.json().get("success"):
        return f"\U00002705账号{username}签到成功, \U0001F4C6连续签到{sign_days}天, \U0001F954共有乐豆{ledou}个, \U0001F4C5共有延保{serviceAmount}天\n"
    else:
        return f"\U0001F6AB账号{username}今天已经签到, \U0001F4C6连续签到{sign_days}天, \U0001F954共有乐豆{ledou}个, \U0001F4C5共有延保{serviceAmount}天\n"


def main():
    global ua, username
    push = set_push_type()
    message = "联想签到: \n"
    if not (ua := os.environ.get('UA')):
        ua = random.choice(USER_AGENT)
    account_secret = os.environ.get("ACCOUNT")
    if account_secret:
        accounts = account_secret.split(",")
        for account in accounts:
            username, password = account.split(":")
            session = login(username, password)
            if not session:
                continue
            message += sign(session)
        push(message)


if __name__ == "__main__":
    main()
