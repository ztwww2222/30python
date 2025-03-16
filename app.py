import os
import uuid as uuid_module
import base64
import socket
import threading
import time
from urllib.parse import urlparse, parse_qs
import websockets
import asyncio
from aiohttp import web
import ssl
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 环境变量配置
UUID = os.environ.get('UUID', '8c93ea6d-87a9-4565-b60d-fc1490950ad1').replace('-', '')
PORT = int(os.environ.get('PORT', 8080))
TIMEOUT = int(os.environ.get('TIMEOUT', 60000)) / 1000  # 转换为秒
KEEPALIVE = int(os.environ.get('KEEPALIVE', 30000)) / 1000  # 转换为秒
EARLY_DATA_SIZE = int(os.environ.get('EARLY_DATA_SIZE', 2560))
SERVER_NAME = os.environ.get('SERVER_NAME', "ws-vless")
SERVER_HOST = os.environ.get('SERVER_HOST', "")
TLS_FINGERPRINT = os.environ.get('TLS_FINGERPRINT', "chrome")

# 生成VLESS链接
def generate_vless_link(host, user_uuid):
    vless_link = f"vless://{user_uuid}@{host}:443?path=%2Fwsvl&security=tls&encryption=none&host={host}&fp={TLS_FINGERPRINT}&type=ws&sni={host}#{SERVER_NAME}"
    return vless_link

# 处理订阅请求的路由
async def handle_subscription(request):
    user_uuid = request.match_info.get('userUuid', '')
    
    # 格式化用户提供的UUID，去掉可能存在的连字符
    formatted_uuid = user_uuid.replace('-', '')
    
    # 验证UUID格式
    if not user_uuid:
        return web.Response(text='Invalid UUID format', status=400)
    
    # 验证UUID是否与配置的UUID匹配
    if formatted_uuid != UUID:
        return web.Response(text='Unauthorized', status=403)
    
    # 获取主机名
    host = SERVER_HOST
    if not host:
        host = request.headers.get('Host', 'localhost')
    
    # 生成VLESS链接
    vless_link = generate_vless_link(host, user_uuid)
    
    # 返回Base64编码的链接
    base64_link = base64.b64encode(vless_link.encode()).decode()
    
    # 设置响应头
    return web.Response(text=base64_link, content_type='text/plain')

# 主页路由
async def handle_home(request):
    return web.Response(text='hello world')

# 验证请求是否包含ed参数并处理Early Data
def validate_and_process_early_data(path, query_string):
    if not query_string:
        return False
    
    query_params = parse_qs(query_string)
    return 'ed' in query_params

# 处理WebSocket连接
async def handle_websocket(websocket, path):
    try:
        # 检查Early Data支持
        query_string = urlparse(websocket.path).query
        early_data_supported = validate_and_process_early_data(websocket.path, query_string)
        
        # 接收第一条消息
        msg = await websocket.recv()
        msg_bytes = msg if isinstance(msg, bytes) else msg.encode()
        
        # 解析VLESS协议内容
        VERSION = msg_bytes[0]
        id_bytes = msg_bytes[1:17]
        
        # 验证UUID
        uuid_valid = True
        for i, v in enumerate(id_bytes):
            if v != int(UUID[i*2:i*2+2], 16):
                uuid_valid = False
                break
        
        if not uuid_valid:
            logger.warning('UUID验证失败')
            await websocket.close()
            return
        
        # 解析目标主机和端口
        i = msg_bytes[17] + 19
        port = int.from_bytes(msg_bytes[i:i+2], byteorder='big')
        i += 2
        ATYP = msg_bytes[i]
        i += 1
        
        if ATYP == 1:  # IPv4
            host = '.'.join(str(b) for b in msg_bytes[i:i+4])
            i += 4
        elif ATYP == 2:  # 域名
            domain_len = msg_bytes[i]
            i += 1
            host = msg_bytes[i:i+domain_len].decode()
            i += domain_len
        elif ATYP == 3:  # IPv6
            # IPv6地址处理比较复杂，这里简化处理
            host_bytes = msg_bytes[i:i+16]
            i += 16
            host = ':'.join(f'{host_bytes[j]:02x}{host_bytes[j+1]:02x}' for j in range(0, 16, 2))
        else:
            logger.error(f"不支持的地址类型: {ATYP}")
            await websocket.close()
            return
        
        # 响应客户端
        await websocket.send(bytes([VERSION, 0]))
        
        # 创建到目标服务器的TCP连接
        reader, writer = await asyncio.open_connection(host, port)
        
        # 如果支持Early Data，优先处理
        if early_data_supported:
            writer.write(msg_bytes[i:])
            await writer.drain()
        else:
            writer.write(msg_bytes[i:])
            await writer.drain()
        
        # 设置双向数据转发
        async def forward_ws_to_tcp():
            try:
                while True:
                    data = await websocket.recv()
                    if not data:
                        break
                    writer.write(data if isinstance(data, bytes) else data.encode())
                    await writer.drain()
            except Exception as e:
                logger.error(f"WebSocket到TCP转发错误: {e}")
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
        
        async def forward_tcp_to_ws():
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    await websocket.send(data)
            except Exception as e:
                logger.error(f"TCP到WebSocket转发错误: {e}")
            finally:
                try:
                    await websocket.close()
                except:
                    pass
        
        # 创建双向数据流
        forward_ws_task = asyncio.create_task(forward_ws_to_tcp())
        forward_tcp_task = asyncio.create_task(forward_tcp_to_ws())
        
        # 等待任一任务完成
        done, pending = await asyncio.wait(
            [forward_ws_task, forward_tcp_task],
            return_when=asyncio.FIRST_COMPLETED
        )
        
        # 取消未完成的任务
        for task in pending:
            task.cancel()
        
    except Exception as e:
        logger.error(f"WebSocket处理错误: {e}")
        try:
            await websocket.close()
        except:
            pass

# 主应用服务器
async def run_app():
    # 创建HTTP应用
    app = web.Application()
    app.add_routes([
        web.get('/', handle_home),
        web.get('/sub-{userUuid}', handle_subscription)
    ])
    
    # 设置HTTP头中间件
    @web.middleware
    async def middleware(request, handler):
        response = await handler(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Cache-Control'] = 'no-cache'
        return response
    
    app.middlewares.append(middleware)
    
    # 启动HTTP服务器
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()
    logger.info(f"HTTP服务器启动在端口: {PORT}")
    
    # 启动WebSocket服务器
    websocket_server = await websockets.serve(
        handle_websocket, 
        '0.0.0.0', 
        PORT,
        process_request=lambda path, headers: None,  # 让HTTP服务器处理非WebSocket请求
        ping_interval=KEEPALIVE,
        ping_timeout=TIMEOUT,
        max_size=100 * 1024 * 1024,  # 100MB最大负载
        compression=None,
        path='/wsvl'
    )
    
    logger.info("WebSocket服务器已启动")
    logger.info(f"订阅链接路径: /sub-uuid")
    
    # 保持服务器运行
    await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(run_app())
    except KeyboardInterrupt:
        logger.info("服务已停止")
    except Exception as e:
        logger.error(f"未捕获的异常: {e}")
