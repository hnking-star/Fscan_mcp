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

@mcp.tool()
async def fscan_scan(
    target: str = "192.168.93.1",
    mode: str = "All",
    ports: str = "",
    threads: int = 60,
    output_format: str = "json",
    timeout: int = 300,
    proxy: str = "",
    poc_name: str = "",
    no_scan: bool = False
) -> dict:
    """
    执行fscan安全扫描，改扫描可能会执行100s告诉用户等待100s
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
    import json
    # 参数验证
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}(-\d+)?(,.*)?$|^http(s)?://', target):
        raise ValueError("目标格式错误，支持IP/IP段/URL")
    
    if ports and not re.match(r'^\d+(-\d+)?(,\d+(-\d+)?)*$', ports):
        raise ValueError("端口格式错误，示例: 80,443,1-1000")

    clean_cache_files()
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
        timeout_duration = 100
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
        output_buffer = []
        try:
            with open('result.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():  # 跳过空行
                        output_buffer.append(line.strip())
        except Exception as e:
            print(f"读取 result.txt 失败: {str(e)}")
            
        # 返回最终结果
        print(output_buffer)
        return {
            "status": "completed",
            "exit_code": process.returncode,
            "output": '\n'.join(output_buffer),
            "error": process.stderr.read()
        }

    except Exception as e:
        print(f"执行错误: {str(e)}")
        return {"status": "error", "message": str(e)}

 

if __name__ == "__main__":
    print("MCP 我211fscan服务正在启动...")
    # 清理进程和缓存
   
    
    #asyncio.run(fscan_scan())
    # 启动 MCP 服务
    mcp.run(transport='stdio')
    print("MCP 服务已启动，等待连接...")