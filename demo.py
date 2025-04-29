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

mcp = FastMCP("fscan")


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



    fscan_path = "F:\\ai\\mcp\\fscan\\fscan.exe"
    cmd = [fscan_path]
    
    # 添加目标参数
    cmd.extend(["-h", target])
    
    # 添加模式参数
    cmd.extend(["-m", mode])
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

        # 设置超时时间为300秒
        timeout_duration = 30
        start_time = time.time()
        
        # 实时读取输出
        while True:
            # 检查是否超时
            if time.time() - start_time > timeout_duration:
                print(f"已达到{timeout_duration}秒的时间限制，正在终止进程...")
                process.terminate()
                process.wait()
                break
                
            # 检查进程是否已结束
            if process.poll() is not None:
                print(f"进程已结束，返回码: {process.returncode}")
                break
                
                 # 读取一行输出（非阻塞方式）
            output = process.stdout.readline()
            if output:
                print(output.strip())
                return {"status": "scanning", "output": output.strip()}
            else:
                # 短暂休眠，避免CPU占用过高
                time.sleep(0.1)
                
        # 确保进程已终止
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    except Exception as e:
        print(f"执行错误: {str(e)}")

 

if __name__ == "__main__":
   # print("MCP 1fscan服务正在启动...")
    #asyncio.run(fscan_scan())
    # 启动 MCP 服务
    mcp.run(transport='stdio')
    #print("MCP 服务已启动，等待连接...")