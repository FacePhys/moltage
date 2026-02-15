#!/usr/bin/env python3
"""
微信公众号服务器推送模拟器
用于测试 Moltage WeChat Bridge 的消息接收与处理逻辑。

使用方式:
    python test_wechat_simulator.py                     # 交互式模式
    python test_wechat_simulator.py --text "你好"        # 发送文本消息
    python test_wechat_simulator.py --event subscribe    # 模拟关注事件
    python test_wechat_simulator.py --command help       # 发送指令
    python test_wechat_simulator.py --verify             # 验证服务器 URL (GET)
    python test_wechat_simulator.py --batch              # 批量测试所有场景

环境变量:
    BRIDGE_URL      Bridge 地址 (默认: http://localhost:3000)
    WECHAT_TOKEN    微信 Token (默认: test_token)
    FAKE_OPENID     模拟用户 OpenID (默认: 自动生成)
    FAKE_APPID      模拟公众号 AppID (默认: wx_test_appid)
"""

import hashlib
import time
import random
import string
import argparse
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("❌ 需要安装 requests 库: pip install requests")
    sys.exit(1)

# ============================================================
# 配置
# ============================================================

import os

BRIDGE_URL = os.environ.get("BRIDGE_URL", "http://localhost:3000")
WECHAT_TOKEN = os.environ.get("WECHAT_TOKEN", "test_token")
FAKE_OPENID = os.environ.get("FAKE_OPENID", "")
FAKE_APPID = os.environ.get("FAKE_APPID", "wx_test_appid")

# 如果没有设置 FAKE_OPENID，生成一个模拟的
if not FAKE_OPENID:
    FAKE_OPENID = "oTest" + "".join(random.choices(string.ascii_letters + string.digits, k=24))


# ============================================================
# 工具函数
# ============================================================

def generate_nonce(length=10):
    """生成随机字符串"""
    return "".join(random.choices(string.digits, k=length))


def generate_signature(token: str, timestamp: str, nonce: str) -> str:
    """
    生成微信签名
    与 Bridge 的 validateSignature 逻辑一致:
        sort([token, timestamp, nonce]) -> join -> sha1
    """
    arr = sorted([token, timestamp, nonce])
    raw = "".join(arr)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def generate_msg_id():
    """生成模拟的微信消息 ID"""
    return str(random.randint(10**18, 10**19 - 1))


def build_text_xml(from_user: str, to_user: str, content: str, msg_id: str = None) -> str:
    """构建文本消息 XML"""
    if not msg_id:
        msg_id = generate_msg_id()
    create_time = int(time.time())
    return f"""<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{create_time}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{content}]]></Content>
<MsgId>{msg_id}</MsgId>
</xml>"""


def build_event_xml(from_user: str, to_user: str, event: str, event_key: str = "") -> str:
    """构建事件消息 XML (subscribe/unsubscribe/CLICK 等)"""
    create_time = int(time.time())
    event_key_xml = f"\n<EventKey><![CDATA[{event_key}]]></EventKey>" if event_key else ""
    return f"""<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{create_time}</CreateTime>
<MsgType><![CDATA[event]]></MsgType>
<Event><![CDATA[{event}]]></Event>{event_key_xml}
</xml>"""


def build_image_xml(from_user: str, to_user: str, pic_url: str, media_id: str) -> str:
    """构建图片消息 XML"""
    create_time = int(time.time())
    msg_id = generate_msg_id()
    return f"""<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{create_time}</CreateTime>
<MsgType><![CDATA[image]]></MsgType>
<PicUrl><![CDATA[{pic_url}]]></PicUrl>
<MediaId><![CDATA[{media_id}]]></MediaId>
<MsgId>{msg_id}</MsgId>
</xml>"""


def build_location_xml(from_user: str, to_user: str, lat: float, lng: float, label: str) -> str:
    """构建位置消息 XML"""
    create_time = int(time.time())
    msg_id = generate_msg_id()
    return f"""<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{create_time}</CreateTime>
<MsgType><![CDATA[location]]></MsgType>
<Location_X>{lat}</Location_X>
<Location_Y>{lng}</Location_Y>
<Scale>15</Scale>
<Label><![CDATA[{label}]]></Label>
<MsgId>{msg_id}</MsgId>
</xml>"""


def parse_reply_xml(xml_text: str) -> dict:
    """解析 Bridge 返回的 XML 回复"""
    try:
        root = ET.fromstring(xml_text)
        result = {}
        for child in root:
            result[child.tag] = child.text
        return result
    except ET.ParseError:
        return {"raw": xml_text}


# ============================================================
# 请求发送
# ============================================================

def send_verify_request():
    """
    发送 GET /wechat 验证请求，模拟微信服务器验证 URL 配置。
    """
    timestamp = str(int(time.time()))
    nonce = generate_nonce()
    echostr = "test_echostr_" + generate_nonce(16)
    signature = generate_signature(WECHAT_TOKEN, timestamp, nonce)

    url = urljoin(BRIDGE_URL, "/wechat")
    params = {
        "signature": signature,
        "timestamp": timestamp,
        "nonce": nonce,
        "echostr": echostr,
    }

    print(f"\n{'='*60}")
    print("📡 GET /wechat — 服务器 URL 验证")
    print(f"{'='*60}")
    print(f"  URL:       {url}")
    print(f"  Token:     {WECHAT_TOKEN}")
    print(f"  Timestamp: {timestamp}")
    print(f"  Nonce:     {nonce}")
    print(f"  Signature: {signature}")
    print(f"  Echostr:   {echostr}")
    print()

    try:
        resp = requests.get(url, params=params, timeout=10)
        print(f"  状态码:    {resp.status_code}")
        print(f"  响应内容:  {resp.text}")
        if resp.status_code == 200 and resp.text == echostr:
            print("  ✅ 验证通过! Bridge 正常响应 echostr")
        else:
            print("  ❌ 验证失败!")
        return resp
    except requests.ConnectionError:
        print(f"  ❌ 无法连接到 {url}，请确认 Bridge 服务已启动")
        return None
    except Exception as e:
        print(f"  ❌ 请求异常: {e}")
        return None


def send_message(xml_body: str, description: str = ""):
    """
    发送 POST /wechat 消息，模拟微信服务器推送消息。
    """
    timestamp = str(int(time.time()))
    nonce = generate_nonce()
    signature = generate_signature(WECHAT_TOKEN, timestamp, nonce)

    url = urljoin(BRIDGE_URL, "/wechat")
    params = {
        "signature": signature,
        "timestamp": timestamp,
        "nonce": nonce,
    }

    print(f"\n{'='*60}")
    print(f"📨 POST /wechat — {description}")
    print(f"{'='*60}")
    print(f"  OpenID:    {FAKE_OPENID}")
    print(f"  Signature: {signature}")
    print()
    # 打印 XML (缩进)
    for line in xml_body.strip().split("\n"):
        print(f"  {line}")
    print()

    try:
        resp = requests.post(
            url,
            params=params,
            data=xml_body.encode("utf-8"),
            headers={"Content-Type": "text/xml"},
            timeout=30,
        )
        print(f"  状态码:    {resp.status_code}")
        print(f"  Content-Type: {resp.headers.get('content-type', 'N/A')}")
        print()

        if resp.headers.get("content-type", "").startswith("text/xml"):
            reply = parse_reply_xml(resp.text)
            if "Content" in reply:
                print(f"  🤖 Bot 回复:")
                for line in reply["Content"].split("\\n"):
                    print(f"     {line}")
            else:
                print(f"  📄 XML 回复: {reply}")
        elif resp.text:
            print(f"  📄 响应: {resp.text[:500]}")
        else:
            print(f"  📄 (空响应)")

        return resp
    except requests.ConnectionError:
        print(f"  ❌ 无法连接到 {url}，请确认 Bridge 服务已启动")
        return None
    except requests.Timeout:
        print(f"  ⏰ 请求超时 (30秒)")
        return None
    except Exception as e:
        print(f"  ❌ 请求异常: {e}")
        return None


# ============================================================
# 测试场景
# ============================================================

def test_verify():
    """测试服务器 URL 验证"""
    return send_verify_request()


def test_subscribe():
    """测试关注事件"""
    xml = build_event_xml(FAKE_OPENID, FAKE_APPID, "subscribe")
    return send_message(xml, "用户关注事件 (subscribe)")


def test_unsubscribe():
    """测试取消关注事件"""
    xml = build_event_xml(FAKE_OPENID, FAKE_APPID, "unsubscribe")
    return send_message(xml, "用户取消关注事件 (unsubscribe)")


def test_text_message(content: str):
    """测试文本消息"""
    xml = build_text_xml(FAKE_OPENID, FAKE_APPID, content)
    return send_message(xml, f"文本消息: \"{content}\"")


def test_command(command: str):
    """测试指令"""
    xml = build_text_xml(FAKE_OPENID, FAKE_APPID, command)
    return send_message(xml, f"指令: {command}")


def test_image():
    """测试图片消息"""
    xml = build_image_xml(
        FAKE_OPENID, FAKE_APPID,
        "https://example.com/test_image.jpg",
        "media_id_test_123456"
    )
    return send_message(xml, "图片消息")


def test_location():
    """测试位置消息"""
    xml = build_location_xml(
        FAKE_OPENID, FAKE_APPID,
        39.9042, 116.4074,
        "北京市东城区天安门"
    )
    return send_message(xml, "位置消息")


def test_invalid_signature():
    """测试错误签名"""
    timestamp = str(int(time.time()))
    nonce = generate_nonce()
    bad_signature = "0000000000000000000000000000000000000000"

    url = urljoin(BRIDGE_URL, "/wechat")
    params = {
        "signature": bad_signature,
        "timestamp": timestamp,
        "nonce": nonce,
    }

    xml = build_text_xml(FAKE_OPENID, FAKE_APPID, "test")

    print(f"\n{'='*60}")
    print("🔒 POST /wechat — 错误签名测试")
    print(f"{'='*60}")

    try:
        resp = requests.post(
            url, params=params,
            data=xml.encode("utf-8"),
            headers={"Content-Type": "text/xml"},
            timeout=10,
        )
        print(f"  状态码: {resp.status_code}")
        if resp.status_code == 403:
            print("  ✅ 正确拒绝了无效签名")
        else:
            print(f"  ⚠️ 预期 403，实际 {resp.status_code}")
        return resp
    except Exception as e:
        print(f"  ❌ 请求异常: {e}")
        return None


# ============================================================
# 批量测试
# ============================================================

def run_batch_tests():
    """运行所有测试场景"""
    print("\n" + "=" * 60)
    print("🧪 Moltage WeChat Bridge 批量测试")
    print("=" * 60)
    print(f"  Bridge URL:  {BRIDGE_URL}")
    print(f"  Token:       {WECHAT_TOKEN}")
    print(f"  Fake OpenID: {FAKE_OPENID}")
    print(f"  Fake AppID:  {FAKE_APPID}")

    results = []

    # Test 1: URL 验证
    r = test_verify()
    results.append(("URL 验证 (GET)", r and r.status_code == 200))

    # Test 2: 错误签名
    r = test_invalid_signature()
    results.append(("错误签名拒绝", r and r.status_code == 403))

    # Test 3: 关注事件
    r = test_subscribe()
    results.append(("关注事件", r and r.status_code == 200))

    time.sleep(1)

    # Test 4: help 指令
    r = test_command("help")
    results.append(("help 指令", r and r.status_code == 200))

    time.sleep(0.5)

    # Test 5: status 指令
    r = test_command("status")
    results.append(("status 指令", r and r.status_code == 200))

    time.sleep(0.5)

    # Test 6: 普通文本消息
    r = test_text_message("你好，这是一条测试消息")
    results.append(("文本消息", r and r.status_code == 200))

    time.sleep(0.5)

    # Test 7: 图片消息
    r = test_image()
    results.append(("图片消息", r and r.status_code == 200))

    time.sleep(0.5)

    # Test 8: 位置消息
    r = test_location()
    results.append(("位置消息", r and r.status_code == 200))

    # ========== 汇总 ==========
    print("\n" + "=" * 60)
    print("📊 测试结果汇总")
    print("=" * 60)

    passed = 0
    for name, ok in results:
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"  {status}  {name}")
        if ok:
            passed += 1

    total = len(results)
    print(f"\n  总计: {passed}/{total} 通过")
    print("=" * 60)


# ============================================================
# 交互式模式
# ============================================================

def interactive_mode():
    """交互式聊天模式"""
    print("\n" + "=" * 60)
    print("💬 微信模拟器 — 交互式模式")
    print("=" * 60)
    print(f"  Bridge URL:  {BRIDGE_URL}")
    print(f"  Token:       {WECHAT_TOKEN}")
    print(f"  Fake OpenID: {FAKE_OPENID}")
    print()
    print("  输入消息模拟微信用户发送，特殊指令:")
    print("    /verify      — 测试 URL 验证")
    print("    /subscribe   — 模拟关注事件")
    print("    /unsubscribe — 模拟取消关注")
    print("    /image       — 模拟图片消息")
    print("    /location    — 模拟位置消息")
    print("    /badsig      — 测试错误签名")
    print("    /quit        — 退出")
    print()

    while True:
        try:
            user_input = input("📱 微信用户> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n👋 再见!")
            break

        if not user_input:
            continue

        if user_input == "/quit":
            print("👋 再见!")
            break
        elif user_input == "/verify":
            test_verify()
        elif user_input == "/subscribe":
            test_subscribe()
        elif user_input == "/unsubscribe":
            test_unsubscribe()
        elif user_input == "/image":
            test_image()
        elif user_input == "/location":
            test_location()
        elif user_input == "/badsig":
            test_invalid_signature()
        else:
            test_text_message(user_input)


# ============================================================
# CLI 入口
# ============================================================

def main():
    global BRIDGE_URL, WECHAT_TOKEN, FAKE_OPENID

    parser = argparse.ArgumentParser(
        description="微信公众号服务器推送模拟器 — 测试 Moltage WeChat Bridge",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python test_wechat_simulator.py                          # 交互式模式
  python test_wechat_simulator.py --verify                 # 验证 URL 配置
  python test_wechat_simulator.py --text "你好"             # 发送文本
  python test_wechat_simulator.py --command help           # 发送指令
  python test_wechat_simulator.py --event subscribe        # 模拟关注
  python test_wechat_simulator.py --batch                  # 批量测试
  
  BRIDGE_URL=http://192.168.1.100:3000 python test_wechat_simulator.py --batch
        """,
    )

    parser.add_argument("--url", default=None, help="Bridge URL (默认: 环境变量或 http://localhost:3000)")
    parser.add_argument("--token", default=None, help="微信 Token (默认: 环境变量或 test_token)")
    parser.add_argument("--openid", default=None, help="模拟用户 OpenID")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--verify", action="store_true", help="测试 URL 验证 (GET)")
    group.add_argument("--text", metavar="MSG", help="发送文本消息")
    group.add_argument("--command", metavar="CMD", choices=["help", "status", "restart", "stop", "destroy"],
                       help="发送指令 (help/status/restart/stop/destroy)")
    group.add_argument("--event", metavar="EVT", choices=["subscribe", "unsubscribe"],
                       help="发送事件 (subscribe/unsubscribe)")
    group.add_argument("--batch", action="store_true", help="批量运行所有测试场景")
    group.add_argument("--interactive", action="store_true", help="交互式模式 (默认)")

    args = parser.parse_args()

    # 更新全局配置（仅在命令行指定时覆盖）
    if args.url:
        BRIDGE_URL = args.url
    if args.token:
        WECHAT_TOKEN = args.token
    if args.openid:
        FAKE_OPENID = args.openid

    if args.verify:
        test_verify()
    elif args.text:
        test_text_message(args.text)
    elif args.command:
        test_command(args.command)
    elif args.event:
        if args.event == "subscribe":
            test_subscribe()
        else:
            test_unsubscribe()
    elif args.batch:
        run_batch_tests()
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
