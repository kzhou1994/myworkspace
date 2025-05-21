import asyncio
import time
import logging
import os
from typing import List, Dict, Optional,Union
import httpx
from fastapi import FastAPI, Query
from fastapi.responses import PlainTextResponse
from datetime import datetime


# 全局配置
MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", "200"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))
CACHE_TTL = int(os.getenv("CACHE_TTL", "10800"))  # 3小时=10800秒

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

app = FastAPI()
metrics_cache = {}
cache_lock = asyncio.Lock()

class IPMIClient:
    def __init__(self, ip: str, username: str, password: str):
        self.ip = ip
        self.username = username
        self.password = password
        self.base_url = f"https://{ip}/api"
        self.token = None
        self.cookie = None

    async def login(self, client: httpx.AsyncClient) -> bool:
        try:
            url = f"{self.base_url}/session"
            payload = {"username": self.username, "password": self.password}
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest"
            }
            resp = await client.post(url, data=payload, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                self.cookie = resp.headers.get("set-cookie")
                self.token = resp.json().get("CSRFToken")
                return bool(self.token)
            else:
                raise Exception(f"/session 返回非200: {resp.status_code}")
        except httpx.TimeoutException:
            raise Exception("/session 请求超时")
        except Exception as e:
            raise Exception(f"/session 异常: {str(e)}")

    async def get_bios_versions(self, client: httpx.AsyncClient) -> Optional[List[Dict]]:
        if not self.token:
            return None
        headers = {
            "Cookie": self.cookie,
            "X-CSRFTOKEN": self.token,
            "X-Requested-With": "XMLHttpRequest"
        }
        try:
            url = f"{self.base_url}/version_summary"
            resp = await client.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                return [
                    {"dev_name": item["dev_name"], "dev_version": item["dev_version"]}
                    for item in resp.json()
                    if item.get("dev_name") in ["BIOS", "BMC"]
                ]
            elif resp.status_code == 401:
                raise Exception("/version_summary 认证失败 (401)")
            else:
                raise Exception(f"/version_summary 返回非200: {resp.status_code}")
        except Exception as e:
            raise Exception(f"/version_summary 异常: {str(e)}")

    async def get_data(self, client: httpx.AsyncClient, endpoint: str) -> Optional[Dict]:
        if not self.token:
            return None
        headers = {
            "Cookie": self.cookie,
            "X-CSRFTOKEN": self.token,
            "X-Requested-With": "XMLHttpRequest"
        }
        try:
            url = f"{self.base_url}/{endpoint}"
            resp = await client.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 401:
                raise Exception(f"/{endpoint} 认证失败 (401)")
            else:
                raise Exception(f"/{endpoint} 返回非200: {resp.status_code}")
        except Exception as e:
            raise Exception(f"/{endpoint} 异常: {str(e)}")

    async def post_data(self,
                            client: httpx.AsyncClient,
                            endpoint: str,
                            data: Optional[Dict] = None) -> Optional[Union[List, Dict]]:
        """
        异步POST请求版本（需配合async/await使用）
        
        Args:
            client: 已初始化的httpx.AsyncClient
            endpoint: API端点路径
            data: 可选的要发送的JSON数据
        """
        if not self.cookie and not await self.login_async():
            return None
            
        url = f"{self.base_url}/{endpoint}"
        headers = {
            "Cookie": self.cookie,
            "X-CSRFTOKEN": self.token,
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json;charset=UTF-8"
        }
    
        try:
            resp = await client.post(
                url,
                json=data or {},
                headers=headers,
                timeout=10
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logging.error(f"异步POST请求失败: {str(e)}")
            return None

class CPUCollector:
    """CPU信息采集器"""
    def __init__(self, ipmi_client: IPMIClient):
        self.client = ipmi_client
    
    async def get_cpu_info(self, client: httpx.AsyncClient) -> Optional[List[Dict]]:
        """获取CPU信息"""
        raw_data = await self.client.get_data(client, "status/cpu_info")
        if not raw_data or "processors" not in raw_data:
            return None
            
        # 定义所有可能的字段
        possible_fields = [
            "proc_id", "proc_name", "proc_status", "status",
            "proc_speed", "proc_core_count", "proc_thread_count",
            "proc_l1cache_size", "proc_l2cache_size", "proc_l3cache_size",
            "proc_arch", "proc_vendor", "proc_socket", "proc_SN"
        ]
        
        # 只保留存在的字段
        processed_data = []
        for item in raw_data["processors"]:
            cpu_info = {}
            for field in possible_fields:
                if field in item:
                    cpu_info[field] = item[field]
            processed_data.append(cpu_info)
            
        return processed_data

    @staticmethod
    def format_cpu_info(cpus: List[Dict], ipmi_ip: str) -> str:
        """格式化CPU信息"""
        metrics = []
        for cpu in cpus:
            # 确保必须有status字段
            if "status" not in cpu:
                continue
                
            value = 1 if cpu["status"] == "OK" else 0
            labels = {'instance': f'"{ipmi_ip}"'}
            
            # 动态添加存在的字段
            for key in cpu:
                if key != "status":  # status已经用作值
                    labels[key] = f'"{cpu[key]}"'
            
            metrics.append(
                f'ipmi_cpu_status{{{",".join(f"{k}={v}" for k,v in labels.items())}}} {value}'
            )
        return "\n".join(metrics)

class UptimeCollector:
    """启动时间采集器"""
    def __init__(self, ipmi_client: IPMIClient):  # 修正参数名称
        self.client = ipmi_client
    
    async def get_uptime(self, client: httpx.AsyncClient) -> Optional[int]:
        """获取启动时间(秒)"""
        raw_data = await self.client.get_data(client, "status/uptime")
        if not raw_data or "poh_counter_reading" not in raw_data:
            return None
            
        return int(raw_data["poh_counter_reading"]) * 60 * 60  # 转换为秒数
    
    @staticmethod
    def format_uptime(uptime_seconds: int, ipmi_ip: str) -> str:
        """格式化启动时间信息"""
        labels = {
            'instance': f'"{ipmi_ip}"'
        }
        return f'ipmi_uptime_seconds{{{",".join(f"{k}={v}" for k,v in labels.items())}}} {uptime_seconds}'

class EventCollector:
    """事件采集器"""
    def __init__(self, ipmi_client: IPMIClient):
        self.client = ipmi_client
    
    async def get_recent_events(self, client: httpx.AsyncClient, limit: int = 10) -> Optional[List[Dict]]:
        """获取最近事件"""
        raw_data = await self.client.get_data(client, "logs/event")
        if not raw_data:
            return None
            
        # 只保留需要的字段
        return [
            {
                "id": item["id"],
                "timestamp": item["timestamp"],
                "sensor_name": item["sensor_name"],
                "severity": item["severity"]
            }
            for item in raw_data[:limit]
        ]

    @staticmethod
    def format_events(events: List[Dict], ipmi_ip: str) -> str:
        """格式化事件信息"""
        metrics = []
        for event in events:
            # 将时间戳转换为可读格式
            event_time = datetime.fromtimestamp(event["timestamp"]).strftime('%Y-%m-%d %H:%M:%S')
            labels = {
                'instance': f'"{ipmi_ip}"',
                'event_id': f'"{event["id"]}"',
                'sensor_name': f'"{event["sensor_name"]}"',
                'severity': f'"{event["severity"]}"',
                'timestamp': f'"{event_time}"'
            }
            metrics.append(
                f'ipmi_event_info{{{",".join(f"{k}={v}" for k,v in labels.items())}}} 1'
            )
        return "\n".join(metrics)


class MemoryCollector:
    """内存信息采集器"""
    def __init__(self,ipmi_client: IPMIClient):
        self.client = ipmi_client
    
    async def get_memory_info(self, client: httpx.AsyncClient) -> Optional[Dict]:
        """获取内存信息"""
        raw_data = await self.client.get_data(client, "status/memory_info")
        if not raw_data or "mem_modules" not in raw_data:
            return None
            
        # 定义所有可能的内存字段
        possible_fields = [
            "mem_mod_id", "mem_mod_slot", "mem_mod_status", "mem_mod_size",
            "mem_mod_type", "mem_mod_max_frequency", "mem_mod_cur_frequency",
            "mem_mod_vendor", "mem_mod_serial_num", "mem_mod_ranks",
            "mem_mod_data_width", "status", "mem_device_locator"
        ]
        
        # 处理内存模块信息
        processed_modules = []
        for item in raw_data["mem_modules"]:
            module_info = {}
            for field in possible_fields:
                if field in item:
                    module_info[field] = item[field]
            processed_modules.append(module_info)
        
        # 返回处理后的数据
        return {
            "total_memory_count": raw_data.get("total_memory_count", 0),
            "present_memory_count": raw_data.get("present_memory_count", 0),
            "mem_modules": processed_modules
        }

    @staticmethod
    def format_memory_info(memory: Dict, ipmi_ip: str) -> str:
        """格式化内存信息"""
        metrics = []
        
        # 添加总内存和已安装内存指标
        metrics.append(
            f'ipmi_memory_total_count{{instance="{ipmi_ip}"}} {memory.get("total_memory_count", 0)}'
        )
        metrics.append(
            f'ipmi_memory_present_count{{instance="{ipmi_ip}"}} {memory.get("present_memory_count", 0)}'
        )
        
        # 添加每个内存模块的指标
        for module in memory.get("mem_modules", []):
            if "status" not in module:
                continue
                
            value = 1 if module["status"] == "OK" else 0
            labels = {'instance': f'"{ipmi_ip}"'}
            
            # 动态添加存在的字段
            for key in module:
                if key != "status":
                    labels[key] = f'"{module[key]}"'
            
            metrics.append(
                f'ipmi_memory_module_status{{{",".join(f"{k}={v}" for k,v in labels.items())}}} {value}'
            )
        return "\n".join(metrics)

class DiskCollector:
    """硬盘信息采集器"""
    def __init__(self, ipmi_client: IPMIClient):
        self.client = ipmi_client
    
    async def get_disk_info(self, client: httpx.AsyncClient) -> Optional[List[Dict]]:
        """获取硬盘信息"""
        raw_data = await self.client.post_data(client, "raid/getctrlpdinfo")  # 添加 await 和 client 参数
        if not raw_data:
            return None
            
        # 定义所有可能的磁盘字段
        possible_fields = [
            "ctrlindex", "slotNum", "intfType", "vendSpec",
            "linkSpeed", "fwState", "rawSize", "mediaType",
            "model", "manu", "status"
        ]
        
        # 处理磁盘信息
        processed_disks = []
        for item in raw_data:
            disk_info = {}
            for field in possible_fields:
                if field in item:
                    disk_info[field] = item[field].strip() if isinstance(item[field], str) else item[field]
            processed_disks.append(disk_info)
            
        return processed_disks
    
    @staticmethod
    def format_disk_info(disks: List[Dict], ipmi_ip: str) -> str:
        """格式化硬盘信息"""
        metrics = []
        for disk in disks:
            if "status" not in disk:
                continue
                
            value = 1 if disk["status"] == "OK" else 0
            labels = {'instance': f'"{ipmi_ip}"'}
            
            # 动态添加存在的字段
            for key in disk:
                if key != "status":
                    labels[key] = f'"{disk[key]}"'
            
            metrics.append(
                f'ipmi_disk_status{{{",".join(f"{k}={v}" for k,v in labels.items())}}} {value}'
            )
        return "\n".join(metrics)


class RaidControllerCollector:
    """RAID控制器信息采集器"""
    def __init__(self, ipmi_client: IPMIClient):
        self.client = ipmi_client
    
    async def get_raid_info(self, client: httpx.AsyncClient) -> Optional[List[Dict]]:
        """获取RAID控制器信息"""
        raw_data = await self.client.get_data(client, "raid/ctrlinfo")
        if not raw_data:
            return None
            
        # 定义所有可能的RAID字段
        possible_fields = {
            "name": "name",
            "index": "index",
            "model": "PN",
            "serial": "SN",
            "vendor": "vendorId",
            "device_id": "devId",
            "memory_size": "memSz",
            "status": "status",
            "raid_state": "raid_state",
            "health": "raid_health"
        }
        
        # 处理RAID控制器信息
        processed_controllers = []
        for item in raw_data:
            controller_info = {}
            for new_field, orig_field in possible_fields.items():
                if orig_field in item:
                    value = item[orig_field]
                    if new_field == "memory_size":
                        value = f"{value}MB" if value else "0MB"
                    controller_info[new_field] = value
            processed_controllers.append(controller_info)
            
        return processed_controllers
    @staticmethod
    def format_raid_info(controllers: List[Dict], ipmi_ip: str) -> str:
        """格式化RAID控制器信息"""
        metrics = []
        for ctrl in controllers:
            # 状态指标
            if "status" in ctrl:
                status_value = 1 if ctrl["status"] == "OK" else 0
                status_labels = {'instance': f'"{ipmi_ip}"', 'component': '"controller_status"'}
                for key in ctrl:
                    if key not in ["status", "health"]:
                        status_labels[key] = f'"{ctrl[key]}"'
                metrics.append(
                    f'ipmi_raid_status{{{",".join(f"{k}={v}" for k,v in status_labels.items())}}} {status_value}'
                )
            
            # 健康指标
            if "health" in ctrl:
                health_value = 1 if ctrl["health"] == "OK" else 0
                health_labels = {'instance': f'"{ipmi_ip}"', 'component': '"controller_health"'}
                for key in ctrl:
                    if key not in ["status", "health"]:
                        health_labels[key] = f'"{ctrl[key]}"'
                metrics.append(
                    f'ipmi_raid_status{{{",".join(f"{k}={v}" for k,v in health_labels.items())}}} {health_value}'
                )
            
            # 内存大小指标
            if "memory_size" in ctrl:
                mem_labels = {'instance': f'"{ipmi_ip}"', 'component': '"controller_memory"'}
                for key in ctrl:
                    if key not in ["status", "health", "memory_size"]:
                        mem_labels[key] = f'"{ctrl[key]}"'
                mem_value = ctrl["memory_size"].replace("MB", "") if "MB" in ctrl["memory_size"] else ctrl["memory_size"]
                metrics.append(
                    f'ipmi_raid_memory{{{",".join(f"{k}={v}" for k,v in mem_labels.items())}}} {mem_value}'
                )
        
        return "\n".join(metrics)


class NICCollector:
    """网卡信息采集器"""
    def __init__(self, ipmi_client: IPMIClient):
        self.client = ipmi_client
  
    async def get_nic_info(self, client: httpx.AsyncClient) -> Optional[List[Dict]]:
        """获取网卡信息"""
        raw_data = await self.client.get_data(client, "status/adapter_info")
        if not raw_data or "sys_adapters" not in raw_data:
            return None
          
        # 定义所有可能的网卡字段
        possible_fields = [
            "pcie_slot_name", "id", "present", "slot",
            "port_num", "vendor", "model", "status",
            "card_model", "port_type"
        ]
        
        # 定义所有可能的端口字段
        possible_port_fields = ["id", "mac_addr"]
        
        # 处理网卡和端口信息
        nic_list = []
        for adapter in raw_data["sys_adapters"]:
            if "ports" not in adapter:
                continue
                
            adapter_info = {}
            for field in possible_fields:
                if field in adapter:
                    adapter_info[field] = adapter[field]
            
            for port in adapter["ports"]:
                port_info = {}
                for field in possible_port_fields:
                    if field in port:
                        port_info[f"port_{field}"] = port[field]
                
                nic_info = {**adapter_info, **port_info}
                nic_list.append(nic_info)
                
        return nic_list if nic_list else None
    @staticmethod
    def format_nic_info(nics: List[Dict], ipmi_ip: str) -> str:
        """格式化网卡信息"""
        metrics = []
        for nic in nics:
            if "status" not in nic:
                continue
                
            value = 1 if nic["status"] == "OK" else 0
            labels = {'instance': f'"{ipmi_ip}"'}
            
            # 动态添加存在的字段
            for key in nic:
                if key != "status":
                    labels[key] = f'"{nic[key]}"'
            
            metrics.append(
                f'ipmi_nic_status{{{",".join(f"{k}={v}" for k,v in labels.items())}}} {value}'
            )
        return "\n".join(metrics)

class HardwareCollector:
    """硬件型号采集器"""
    def __init__(self, ipmi_client: IPMIClient):
        self.client = ipmi_client
  
    async def get_hardware_info(self, client: httpx.AsyncClient) -> Optional[Dict]:
        """获取硬件型号信息"""
        raw_data = await self.client.get_data(client, "fru")
        if not raw_data or not isinstance(raw_data, list) or len(raw_data) == 0:
            return None
            
        # 获取第一个设备的product信息
        first_device = raw_data[0]
        if "product" not in first_device:
            return None
          
        # 定义所有可能的硬件字段
        possible_fields = {
            "manufacturer": "manufacturer",
            "product_name": "product_name",
            "product_version": "product_version",
            "serial_number": "serial_number"
        }
        
        # 处理硬件信息
        hardware_info = {}
        for new_field, orig_field in possible_fields.items():
            if orig_field in first_device["product"]:
                hardware_info[new_field] = first_device["product"][orig_field]
        
        return hardware_info if hardware_info else None
    @staticmethod
    def format_hardware_info(hardware: Dict, ipmi_ip: str) -> str:
        """格式化硬件型号信息"""
        labels = {'instance': f'"{ipmi_ip}"'}
        
        # 动态添加存在的字段
        for key in hardware:
            labels[key] = f'"{hardware[key]}"'
        
        return f'ipmi_hardware_info{{{",".join(f"{k}={v}" for k,v in labels.items())}}} 1'

class HealthCollector:
    """健康状态汇总采集器"""
    def __init__(self, ipmi_client: IPMIClient):
        self.client = ipmi_client
    
    async def get_health_summary(self, client: httpx.AsyncClient) -> Optional[Dict]:
        """获取健康状态汇总信息"""
        raw_data = await self.client.get_data(client, "status/health_summary")
        if not raw_data or not isinstance(raw_data, dict):
            return None
        
        # 动态处理所有状态字段
        metrics = {}
        for field_name, status in raw_data.items():
            if field_name.endswith("_status") or field_name.endswith("_redundancy"):
                metric_name = field_name.lower()
                metrics[metric_name] = 1 if status == "OK" else 0
        
        return metrics if metrics else None
    @staticmethod
    def format_health_summary(status: Dict, ipmi_ip: str) -> List[str]:
        """格式化健康状态汇总信息"""
        metrics = []
        for field_name, value in status.items():
            labels = {'instance': f'"{ipmi_ip}"', 'component': f'"{field_name}"'}
            metric_line = f'ipmi_status{{{",".join(f"{k}={v}" for k,v in labels.items())}}} {value}'
            metrics.append(metric_line)
        return metrics

class PowerSupplyCollector:
    """电源信息采集器"""
    def __init__(self, ipmi_client: IPMIClient):
        self.client = ipmi_client
    
    async def get_power_info(self, client: httpx.AsyncClient) -> Optional[Dict]:
        """获取电源信息"""
        raw_data = await self.client.get_data(client, "status/psu_info")
        if not raw_data:
            return None
        
        # 定义所有可能的电源字段
        possible_psu_fields = [
            "id", "status", "vendor_id", "model",
            "temperature", "ps_out_power_max", "input_type","serial_num"
        ]
        
        # 处理电源详情
        power_supplies = []
        for psu in raw_data.get("power_supplies", []):
            if psu.get("present", 0) == 1:
                psu_info = {}
                for field in possible_psu_fields:
                    if field in psu:
                        value = psu[field]
                        if field == "status":
                            value = 1 if value == "OK" else 0
                        psu_info[field.replace("vendor_id", "vendor").replace("ps_out_power_max", "max_power")] = value
                power_supplies.append(psu_info)
        
        # 处理电源汇总
        possible_summary_fields = [
            "present_power_reading", "rated_power", "power_supplies_redundant"
        ]
        
        power_summary = {}
        for field in possible_summary_fields:
            if field in raw_data:
                new_field = field.replace("present_power_reading", "present_power").replace("power_supplies_redundant", "redundant")
                power_summary[new_field] = raw_data[field]
        
        return {
            "power_supplies": power_supplies,
            "power_summary": power_summary
        }

    @staticmethod
    def format_power_info(power_data: Dict, ipmi_ip: str) -> List[str]:
        """格式化电源信息"""
        metrics = []
        base_labels = {'instance': f'"{ipmi_ip}"'}

        # 电源详情指标
        for psu in power_data.get("power_supplies", []):
            if "status" not in psu:
                continue
                
            labels = base_labels.copy()
            for key in psu:
                if key != "status":
                    labels[key] = f'"{psu[key]}"'
            
            metrics.append(
                f'ipmi_power_supply_status{{{",".join(f"{k}={v}" for k,v in labels.items())}}} {psu["status"]}'
            )

        # 电源汇总指标
        summary = power_data.get("power_summary", {})
        if "present_power" in summary:
            labels = base_labels.copy()
            for key in summary:
                if key != "present_power":
                    labels[key] = f'"{summary[key]}"'
            
            metrics.append(
                f'ipmi_power_reading{{{",".join(f"{k}={v}" for k,v in labels.items())}}} {summary["present_power"]}'
            )
        
        return metrics

def format_versions(versions: List[Dict], ip: str) -> str:
    metrics = []
    for version in versions:
        metrics.append(
            f'ipmi_bios_info{{instance="{ip}",dev_name="{version["dev_name"]}",version="{version["dev_version"]}"}} 1'
        )
    return "\n".join(metrics)

def format_error(ip: str, error_type: str, error_msg: str) -> str:
    return f'ipmi_error{{instance="{ip}",error_type="{error_type}",error_msg="{error_msg}"}} 1'

async def collect_metrics(ip: str, user: str, password: str) -> str:
    cache_key = f"{ip}-{user}"
    async with cache_lock:
        cached = metrics_cache.get(cache_key)
        if cached and (time.time() - cached["timestamp"] < CACHE_TTL):
            logging.info(f"[{ip}] 使用缓存数据")
            return cached["metrics"]

    async with httpx.AsyncClient(verify=False, timeout=REQUEST_TIMEOUT) as client:
        ipmi_client = IPMIClient(ip, user, password)
        try:
            token_ok = await ipmi_client.login(client)
        except Exception as e:
            return format_error(ip, "login_failed", str(e)) + "\n"

        all_metrics = []
        timestamp = int(time.time() * 1000)
        
        # 获取BIOS版本信息
        try:
            versions = await ipmi_client.get_bios_versions(client)
            if versions:
                all_metrics.append(format_versions(versions, ip))
            else:
                all_metrics.append(format_error(ip, "get_versions_failed", "返回空数据"))
        except Exception as e:
            all_metrics.append(format_error(ip, "get_versions_failed", str(e)))
        
        # 获取CPU信息
        try:
            cpu_collector = CPUCollector(ipmi_client)
            cpus = await cpu_collector.get_cpu_info(client)
            if cpus:
                all_metrics.append(cpu_collector.format_cpu_info(cpus, ip))
            else:
                all_metrics.append(format_error(ip, "get_cpu_info_failed", "返回空数据"))
        except Exception as e:
            all_metrics.append(format_error(ip, "get_cpu_info_failed", str(e)))

        # 获取内存信息
        try:
            memory_collector = MemoryCollector(ipmi_client)
            memory = await memory_collector.get_memory_info(client)
            if memory:
                all_metrics.append(memory_collector.format_memory_info(memory, ip))
            else:
                all_metrics.append(format_error(ip, "get_memory_info_failed", "返回空数据"))
        except Exception as e:
            all_metrics.append(format_error(ip, "get_memory_info_failed", str(e)))
        
        # 获取启动时间信息
        try:
            uptime_collector = UptimeCollector(ipmi_client)  # 正确初始化
            uptime = await uptime_collector.get_uptime(client)
            if uptime is not None:
                all_metrics.append(uptime_collector.format_uptime(uptime, ip))
            else:
                all_metrics.append(format_error(ip, "get_uptime_failed", "返回空数据"))
        except Exception as e:
            all_metrics.append(format_error(ip, "get_uptime_failed", str(e)))
        # 获取硬盘信息
        try:
            disk_collector = DiskCollector(ipmi_client)
            disk_info = await disk_collector.get_disk_info(client)  # 正确调用异步方法
            if disk_info:
                all_metrics.append(disk_collector.format_disk_info(disk_info, ip))
            else:
                all_metrics.append(format_error(ip, "get_disk_info_failed", "返回空数据"))
        except Exception as e:
            all_metrics.append(format_error(ip, "get_disk_info_failed", str(e)))


        # 获取RAID控制器信息
        try:
            raid_collector = RaidControllerCollector(ipmi_client)
            raid_info = await raid_collector.get_raid_info(client)
            if raid_info:
                all_metrics.append(raid_collector.format_raid_info(raid_info, ip))
            else:
                all_metrics.append(format_error(ip, "get_raid_info_failed", "返回空数据"))
        except Exception as e:
            all_metrics.append(format_error(ip, "get_raid_info_failed", str(e)))
        # 获取网卡信息
        try:
            nic_collector = NICCollector(ipmi_client)
            nic_info = await nic_collector.get_nic_info(client)
            if nic_info:
                all_metrics.append(nic_collector.format_nic_info(nic_info, ip))
            else:
                all_metrics.append(format_error(ip, "get_nic_info_failed", "返回空数据"))
        except Exception as e:
            all_metrics.append(format_error(ip, "get_nic_info_failed", str(e)))
        # 获取硬件型号信息
        try:
            hardware_collector = HardwareCollector(ipmi_client)
            hardware_info = await hardware_collector.get_hardware_info(client)
            if hardware_info:
                all_metrics.append(hardware_collector.format_hardware_info(hardware_info, ip))
            else:
                all_metrics.append(format_error(ip, "get_hardware_info_failed", "返回空数据"))
        except Exception as e:
            all_metrics.append(format_error(ip, "get_hardware_info_failed", str(e)))
        # 获取健康状态汇总信息
        try:
            health_collector = HealthCollector(ipmi_client)
            health_info = await health_collector.get_health_summary(client)
            if health_info:
                all_metrics.extend(health_collector.format_health_summary(health_info, ip))
            else:
                all_metrics.append(format_error(ip, "get_health_summary_failed", "返回空数据"))
        except Exception as e:
            all_metrics.append(format_error(ip, "get_health_summary_failed", str(e)))
        # 获取电源信息
        try:
            power_collector = PowerSupplyCollector(ipmi_client)
            power_info = await power_collector.get_power_info(client)
            if power_info:
                all_metrics.extend(power_collector.format_power_info(power_info, ip))
            else:
                all_metrics.append(format_error(ip, "get_power_info_failed", "返回空数据"))
        except Exception as e:
            all_metrics.append(format_error(ip, "get_power_info_failed", str(e)))

        # 获取事件日志信息
        try:
            event_collector = EventCollector(ipmi_client)
            events = await event_collector.get_recent_events(client)
            if events:
                all_metrics.append(event_collector.format_events(events, ip))
            else:
                all_metrics.append(format_error(ip, "get_events_failed", "返回空数据"))
        except Exception as e:
            all_metrics.append(format_error(ip, "get_events_failed", str(e)))






        final_metrics = "\n".join(all_metrics) + f"\n# Scrape timestamp: {timestamp}\n"

    async with cache_lock:
        metrics_cache[cache_key] = {
            "metrics": final_metrics,
            "timestamp": time.time()
        }

    return final_metrics

@app.get("/metrics", response_class=PlainTextResponse)
async def metrics(
    ip: str = Query(..., description="IPMI IP"),
    bmc_user: str = Query("admin", description="BMC 用户名"),
    bmc_password: str = Query(..., description="BMC 密码")
):
    try:
        return await asyncio.wait_for(collect_metrics(ip, bmc_user, bmc_password), timeout=REQUEST_TIMEOUT + 5)
    except asyncio.TimeoutError:
        return PlainTextResponse(f"{format_error(ip, 'request_timeout', '请求超时')}\n", status_code=504)
    except Exception as e:
        return PlainTextResponse(f"{format_error(ip, 'unknown_error', str(e))}\n", status_code=500)

@app.get("/health")
def health():
    return PlainTextResponse("OK")

@app.get("/")
def index():
    return PlainTextResponse("""
# IPMI Exporter (FastAPI Async Version)
# Prometheus scrape endpoint: /metrics?ip=IPMI_IP&bmc_password=PASSWORD
# Health: /health
""")
