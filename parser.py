import json
from datetime import datetime
import re
from urllib.parse import urlparse

input_file = "logs.json"
output_file = "parsed_logs.txt"

def extract_domain_port(message):
    # 第一优先：提取 “connected to” 或 “处理 TCP 出站连接” 后的 <域名:端口>
    match = re.search(r"(connected to|处理 TCP 出站连接)\s+([a-zA-Z0-9\-\.]+:\d+)", message)
    if match:
        return match.group(2)

    # 第二优先：从方括号中提取形如 [域名:端口-- 的格式
    prefix_match = re.search(r'\[([a-zA-Z0-9\-\.]+:\d+)--', message)
    if prefix_match:
        return prefix_match.group(1)

    # 第三优先：判断是否出现了 :443，作为无域名但尝试建立 TLS 连接的标志
    if ":443" in message:
        return ":443"

    return None

def timestamp_to_readable(ts):
    return datetime.utcfromtimestamp(ts / 1000).strftime('%Y-%m-%d %H:%M:%S')

def parse_logs(input_file, output_file):
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    invocations = data.get("result", {}).get("invocations", {})
    processed_ray_ids = set()

    with open(output_file, "w", encoding="utf-8") as f_out:
        for request_id, entries in invocations.items():
            ray_id = entries[0]["$metadata"].get("requestId", "N/A")
            if ray_id in processed_ray_ids:
                continue

            # 初始化字段
            cf_connecting_ip = "N/A"
            x_real_ip = "N/A"
            country = "N/A"
            region = "N/A"
            colo = "N/A"
            city = "N/A"
            connection = "N/A"
            user_agent = "N/A"
            domain_port = "N/A"
            timestamp = 0
            cpu_time = "N/A"
            wall_time = "N/A"
            cpu_exceeded = False
            fallback_worker_host = None

            for entry in entries:
                metadata = entry.get("$metadata", {})
                workers = entry.get("$workers", {})
                event = workers.get("event", {})
                request = event.get("request", {})
                headers = request.get("headers", {})
                cf_info = request.get("cf", {})

                cf_connecting_ip = headers.get("cf-connecting-ip", cf_connecting_ip)
                x_real_ip = headers.get("x-real-ip", x_real_ip)
                country = cf_info.get("country", country)
                region = cf_info.get("region", region)
                colo = cf_info.get("colo", colo)
                city = cf_info.get("city", city)
                connection = headers.get("connection", connection)
                user_agent = headers.get("user-agent", user_agent)
                cpu_time = workers.get("cpuTimeMs", cpu_time)
                wall_time = workers.get("wallTimeMs", wall_time)

                # 记录 Worker 绑定域名（用于排除）
                if not fallback_worker_host and "url" in request:
                    try:
                        fallback_worker_host = urlparse(request["url"]).hostname
                    except:
                        pass

                # 检查 CPU 超时
                if "Worker exceeded CPU time limit" in entry.get("source", {}).get("message", ""):
                    cpu_exceeded = True

                # 提取目标域名:端口
                message = entry.get("source", {}).get("message", "")
                extracted_domain = extract_domain_port(message)
                current_timestamp = entry.get("timestamp", 0)

                # 设置域名：优先最早出现的合法项，排除 worker 自身绑定域名
                if extracted_domain and extracted_domain != fallback_worker_host:
                    if domain_port == "N/A" or current_timestamp < timestamp:
                        domain_port = extracted_domain
                        timestamp = current_timestamp

            # CPU超时但还未找到域名，再次尝试提取
            if cpu_exceeded and domain_port == "N/A":
                for entry in entries:
                    message = entry.get("source", {}).get("message", "")
                    extracted_domain = extract_domain_port(message)
                    current_timestamp = entry.get("timestamp", 0)

                    if extracted_domain and extracted_domain != fallback_worker_host:
                        domain_port = extracted_domain
                        timestamp = current_timestamp
                        break

            # 写入日志
            log_entry = (
                f"rayId: {ray_id}\n"
                f"cf-connecting-ip: {cf_connecting_ip}\n"
                f"x-real-ip: {x_real_ip}\n"
                f"country: {country}\n"
                f"region: {region}\n"
                f"colo: {colo}\n"
                f"city: {city}\n"
                f"connection: {connection}\n"
                f"user-agent: {user_agent}\n"
                f"cpu_time(ms): {cpu_time}\n"
                f"wall_time(ms): {wall_time}\n"
                f"domains:\n"
                f"  - {domain_port if domain_port != 'N/A' else 'N/A'}\n"
                "----------------------------------------\n"
            )

            f_out.write(log_entry)
            processed_ray_ids.add(ray_id)

    print(f"日志解析完成，结果已保存至 {output_file}")

# 启动主函数
parse_logs(input_file, output_file)