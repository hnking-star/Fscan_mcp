import asyncio
from typing import Any
import httpx
from mcp.server.fastmcp import FastMCP
import base64
import sys
from typing import List
import subprocess
import re
import os
import time
import json

# 初始化一个mcp服务
mcp = FastMCP("fscan")


# 清理所有缓存文件
def clean_cache_files():
    cache_files = ['result.txt']
    for file in cache_files:
        try:
            if os.path.exists(file):
                os.remove(file)
        except Exception as e:
            print(f"清理缓存文件 {file} 失败: {str(e)}")

# 将JSON格式转换为人类可读的格式
def format_scan_result(json_str):
    try:
        data = json.loads(json_str)
        result = []
        
        # 格式化时间
        time_str = data.get("time", "").split("T")[0] if "time" in data else ""
        
        # 根据不同类型格式化输出
        if data.get("type") == "PORT" and data.get("status") == "open":
            port = data.get("details", {}).get("port", "未知")
            result.append(f"发现开放端口: {port} (目标: {data.get('target', '未知')})")
        
        elif data.get("type") == "SERVICE" and data.get("status") == "identified":
            details = data.get("details", {})
            port = details.get("port", "未知")
            service = details.get("service", "未知")
            product = details.get("product", "")
            banner = details.get("banner", "")
            
            if "hostname" in details:
                hostname = details.get("hostname", "")
                ipv4 = ", ".join(details.get("ipv4", []))
                result.append(f"主机信息: {hostname}")
                result.append(f"IPv4地址: {ipv4}")
                if "ipv6" in details:
                    ipv6 = ", ".join(details.get("ipv6", []))
                    result.append(f"IPv6地址: {ipv6}")
            elif service == "http" and "title" in details:
                title = details.get("title", "")
                url = details.get("url", "").strip(" `")
                result.append(f"发现Web服务: {url} - {title}")
                if "server_info" in details and details["server_info"].get("status_code"):
                    status = details["server_info"].get("status_code")
                    result.append(f"  状态码: {status}")
            else:
                result.append(f"服务识别: 端口 {port} - {service} {product}")
                if banner:
                    result.append(f"  Banner: {banner}")
        
        return "\n".join(result) if result else f"未识别的数据: {json_str}"
    except json.JSONDecodeError:
        return f" {json_str}"
    except Exception as e:
        return f"处理错误: {str(e)}, 原始数据: {json_str}"

@mcp.tool()
async def fscan_scan(
    target: str = "192.168.93.1",
    mode: str = "All",
    ports: str = None,
    threads: int = 60,
    output_format: str = "json",
    timeout: int = 300,
    proxy: str = None,
    poc_name: str = None,
    no_scan: bool = False
) -> dict:
    """
    执行fscan安全扫描
    :param target: 扫描目标(IP/IP段/URL)
    :param mode: 扫描模式(All/Basic/Database/Vul等)
    :param ports: 指定扫描端口(示例: 80,443,1-1000)
    :param threads: 扫描线程数
    :param output_format: 输出格式(json/txt/csv)
    :param timeout: 超时时间(秒)
    :param proxy: 代理服务器地址
    :param poc_name: 指定POC名称
    :param no_scan: 仅探测存活不扫描
    """
    # 参数验证
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}(-\d+)?(,.*)?$|^http(s)?://', target):
        raise ValueError("目标格式错误，支持IP/IP段/URL")
    
    if ports and not re.match(r'^\d+(-\d+)?(,\d+(-\d+)?)*$', ports):
        raise ValueError("端口格式错误，示例: 80,443,1-1000")

   # 清理旧结果文件
    try:
        if os.path.exists('result.txt'):
            subprocess.run(['del', 'result.txt'], check=True, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"文件清理失败: {e}")
        return

    # 构建命令行参数
    # 获取当前脚本所在目录
    fscan_path = "F:\\ai\\mcp\\fscan\\fscan.exe"
    cmd = [fscan_path]
    
    # 添加目标参数
    cmd.extend(["-h", target])
    
    # 添加模式参数
    cmd.extend(["-m", mode])
    
    # 添加可选参数
    if ports:
        cmd.extend(["-p", ports])
    if threads:
        cmd.extend(["-t", str(threads)])
    if output_format:
        cmd.extend(["-f", output_format])
    if timeout:
        cmd.extend(["-time", str(timeout)])
    if proxy:
        cmd.extend(["-proxy", proxy])
    if poc_name:
        cmd.extend(["-poc", poc_name])
    if no_scan:
        cmd.append("-ns")
    print(' '.join(cmd))
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
            encoding='utf-8',
        )

        # 设置超时时间为10秒
        timeout_duration = 10
        start_time = time.time()
        
        # 循环检查进程状态
        while process.poll() is None:
            if time.time() - start_time > timeout_duration:
                print(f"已达到{timeout_duration}秒时间限制，正在终止进程...")
                process.terminate()
                process.wait()
                break
            time.sleep(0.5)
        
        # 读取 result.txt 文件内容
        json_results = []
        formatted_results = []
        try:
            with open('result.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():  # 跳过空行
                        json_results.append(line.strip())
                        # 将每个JSON对象转换为人类可读格式
                        human_readable = format_scan_result(line.strip())
                        if human_readable:
                            formatted_results.append(human_readable)
        except Exception as e:
            print(f"读取 result.txt 失败: {str(e)}")
            
        # 返回最终结果
        print(json_results)
        return {
            "status": "completed",
            "exit_code": process.returncode,
            "output": '\n\n'.join(formatted_results),  # 使用格式化后的结果
            "raw_output": '\n'.join(json_results),     # 保留原始JSON结果
            "error": process.stderr.read()
        }

    except Exception as e:
        print(f"执行错误: {str(e)}")
        return {"status": "error", "message": str(e)}


if __name__ == "__main__":
    print("MCP fscan服务正在启动...")
    # 清理进程和缓存
   
    clean_cache_files()
    # 运行扫描并获取结果
    result = asyncio.run(fscan_scan())
    # 打印扫描结果
    print("\n===== 扫描结果 =====")
    if result and "output" in result:
        print(result["output"])
    else:
        print("未获取到扫描结果或扫描出错")
        if result and "error" in result:
            print(f"错误信息: {result['error']}")
    
    # 启动 MCP 服务
    mcp.run(transport='stdio')
    print("MCP 服务已启动，等待连接...")