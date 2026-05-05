const express = require('express');
const os = require('os');
const path = require('path');
const net = require('net');
const fs = require('fs');
const configPath = path.join(__dirname, 'config.json');


// 初始化排除 IP 列表
let excludeIPs = [];
let excludeCIDRs = []; // 存储 CIDR 格式，用于网段匹配

function initExcludeRules() {
  const configExcludes = config.getClientIp?.excludeIPs || [];
  excludeIPs = [...configExcludes];
  excludeCIDRs = [];
  
  // 自动检测局域网网段
  if (config.getClientIp?.autoDetectLAN !== false) {
    const interfaces = os.networkInterfaces();
    for (const [name, addrs] of Object.entries(interfaces)) {
      for (const addr of addrs) {
        if (addr.internal === false && addr.family === 'IPv4' && addr.netmask && !addr.address.startsWith('127.')) {
          // 计算 CIDR 网段
          try {
            const ipParts = addr.address.split('.').map(Number);
            const maskParts = addr.netmask.split('.').map(Number);
            const networkParts = ipParts.map((octet, i) => octet & maskParts[i]);
            const cidr = maskParts.reduce((bits, octet) => bits + octet.toString(2).split('1').length - 1, 0);
            const cidrNotation = `${networkParts.join('.')}/${cidr}`;
            if (!excludeCIDRs.includes(cidrNotation)) {
              excludeCIDRs.push(cidrNotation);
              console.log(`[IP排除] 检测到局域网网段: ${cidrNotation} (网卡: ${name})`);
            }
          } catch (e) {
            // 忽略这个地址
          }
        }
      }
    }
  }
  
  console.log(`[IP排除] 手动排除IP: ${excludeIPs.length > 0 ? excludeIPs.join(', ') : '无'}`);
  console.log(`[IP排除] 自动检测局域网网段: ${excludeCIDRs.length > 0 ? excludeCIDRs.join(', ') : '无'}`);
}

// 判断 IP 是否在排除列表中
function isIPExcluded(ip) {
  if (excludeIPs.includes(ip)) return true;
  
  // 回环 / 未指定 / 链路本地
  if (ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0' || ip === '::' || ip === '0:0:0:0:0:0:0:0') return true;
  if (ip.startsWith('fe80:')) return true; // IPv6 链路本地

  // CIDR 网段匹配（IPv4）
  for (const cidr of excludeCIDRs) {
    if (ip.includes('.') && ipInCIDR(ip, cidr)) return true;
  }
  
  return false;
}


// 简单的 CIDR 匹配
function ipInCIDR(ip, cidr) {
  const [network, bits] = cidr.split('/');
  const maskLen = parseInt(bits, 10);
  if (isNaN(maskLen)) return false;
  
  const ipParts = ip.split('.').map(Number);
  const netParts = network.split('.').map(Number);
  if (ipParts.length !== 4 || netParts.length !== 4) return false;
  
  const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
  const netInt = (netParts[0] << 24) | (netParts[1] << 16) | (netParts[2] << 8) | netParts[3];
  const mask = maskLen === 0 ? 0 : (~0 << (32 - maskLen));
  
  return (ipInt & mask) === (netInt & mask);
}

// 初始化



// 加载 pcap
let pcap = null;
try {
  pcap = require('pcap');
} catch (e) {
  console.warn('[警告] pcap 模块未安装或加载失败，将退回到 API 请求 IP 统计');
}

// 默认配置（用于在配置文件缺失时创建默认 config.json，以及自动补全的依据）
const defaultConfig = {
  autoCompleteConfig: true,
  // 全局默认值，各个模块可单独覆盖
  updateInterval: 10000,
  MaxHistoryLength: 60,
  server: {
    port: 50000,
    enableRateLimit: true,
    minSecondsAfterLastRequest: 10
  },
getClientIp: {
    // 从 X-Forwarded-For 获取真实 IP
    getIpByXFF: true,
    getIpByXFFFromStart: true,
    getIpByXFFCount: 1,
    // 全局抓包设置（默认关闭）
    packetCaptureEnabled: false,
    packetCaptureInterface: '',
    packetCaptureFilter: 'tcp',
    // Nginx 日志读取（默认开启）
    nginxAccessLogEnabled: true,
   "nginxAccessLogPath": [
  "/var/log/nginx/access.log",
  "/var/log/nginx/other.log"
],
    // IP 排名展示数量
    topIPCount: 20,
    // IP 计数清空间隔（分钟）
    ipRequestCountSaveMinutes: 60,
    // 排除规则（自动检测局域网网段 + 手动添加）
    excludeIPs: [],
    autoDetectLAN: true
},
  systemStatsCPU: {},
  systemStatsRAM: {},
  napcat: {
    url: 'http://127.0.0.1:3002/get_status/',
    token: '',
    eventsMax: 100
  }
};


// 深度合并默认配置，补全缺失的项（只添加，不覆盖已有值）
function deepMergeDefaults(defaults, target) {
  const result = {};
  // 按 defaultConfig 的键顺序遍历
  for (const key of Object.keys(defaults)) {
    if (key in target) {
      // 用户有配置
      if (
        typeof defaults[key] === 'object' &&
        defaults[key] !== null &&
        !Array.isArray(defaults[key]) &&
        typeof target[key] === 'object' &&
        target[key] !== null
      ) {
        // 双方都是普通对象，递归合并
        result[key] = deepMergeDefaults(defaults[key], target[key]);
      } else {
        // 保留用户值
        result[key] = target[key];
      }
    } else {
      // 用户没有，用默认值
      result[key] = defaults[key];
    }
  }
  // 保留用户有但默认配置里没有的键（理论上不会发生，但安全起见）
  for (const key of Object.keys(target)) {
    if (!(key in result)) {
      result[key] = target[key];
    }
  }
  return result;
}

// 尝试安全加载配置文件：若不存在则创建默认文件，若存在则根据 autoCompleteConfig 自动补全缺失项
let config = {};
let configLoaded = false;
let configNeedsWrite = false;

if (!fs.existsSync(configPath)) {
  try {
    fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 4), { flag: 'wx' });
    console.log(`[提示] 默认配置文件已创建：${configPath}。请根据需要修改后重启服务（不会自动重启）。`);
    config = defaultConfig;
    configLoaded = true;
  } catch (err) {
    console.warn(`[警告] 创建默认配置文件失败：${err.message}`);
    config = defaultConfig; // 退回到内存中的默认配置以继续运行
  }
} else {
  try {
    config = require(configPath) || {};
    configLoaded = true;
  } catch (err) {
    console.warn(`[警告] 无法加载配置文件 ${configPath}，将使用内置默认配置，错误信息：${err.message}`);
    config = defaultConfig;
  }

  // 自动补全逻辑
  if (configLoaded) {
    // 检查并补全 autoCompleteConfig 字段本身（缺失视为 true）
    if (config.autoCompleteConfig === undefined) {
      config.autoCompleteConfig = true;
      configNeedsWrite = true;
    }

    // 如果开启了自动补全，则用默认配置补全所有缺失项
    if (config.autoCompleteConfig) {
      const merged = deepMergeDefaults(defaultConfig, config);
      if (JSON.stringify(merged) !== JSON.stringify(config)) {
        config = merged;
        configNeedsWrite = true;
      }
    }

    // 写回文件（如有变更）
    if (configNeedsWrite) {
      try {
        fs.writeFileSync(configPath, JSON.stringify(config, null, 4));
        console.log('[配置] 缺失的配置项已自动补全并保存。');
      } catch (err) {
        console.warn(`[警告] 自动补全配置后写入文件失败：${err.message}`);
      }
    }
  }
}

const app = express();
app.set('trust proxy', true); // 如果服务器部署在反向代理后面，启用此设置以正确获取客户端IP地址
const port = process.env.PORT || safeGetConfigValue('server.port', 3000);

// 静态文件服务
app.use(express.static(path.join(__dirname, 'public')));

// 安全获取配置值的函数，支持全局默认值 + 模块覆盖
function safeGetConfigValue(arg1, arg2, defaultValue) {
  // 判断是模块覆盖模式（三个参数，且第二个参数不包含点号）
  if (arguments.length === 3 && typeof arg1 === 'string' && typeof arg2 === 'string' && !arg2.includes('.')) {
    const modulePath = arg1;
    const key = arg2;
    const module = config[modulePath];
    // 如果模块内有显式配置则优先使用（优先级:全局默认值<模块覆盖）
    if (module && typeof module === 'object' && key in module) {
      const val = parseInt(module[key], 10);
      if (!isNaN(val) && val >= 1) return val;
    }
    // 否则使用全局顶层配置
    if (key in config) {
      const val = parseInt(config[key], 10);
      if (!isNaN(val) && val >= 1) return val;
    }
    // 都无效则返回默认值
    return defaultValue;
  }
  
  // 原有逻辑：嵌套路径模式，如 'server.port'
  const path = arg1;
  const keys = path.split('.');
  let value = config;
  
  for (const key of keys) {
    if (value && typeof value === 'object' && key in value) {
      value = value[key];
    } else {
      console.warn(`[警告] 配置项 ${path} 不存在，使用默认值: ${defaultValue}`);
      return defaultValue;
    }
  }
  try {
    const parsedValue = parseInt(value, 10);
    if (isNaN(parsedValue) || parsedValue < 1) {
      throw new Error('Not a valid integer');
    }
    return parsedValue;
  } catch (error) {
    console.warn(`[警告] 配置项 ${path} 的值 "${value}" 无法转换为正整数，使用默认值: ${defaultValue}`);
    return defaultValue;
  }
}


// ========== 系统状态历史数据分离 ==========
// CPU 历史
const cpuHistory = {
  timestamp: [],
  values: []      // 使用率百分比数值
};
// RAM 历史
const ramHistory = {
  timestamp: [],
  values: []      // 使用率百分比数值
};

// CPU 统计相关
const CPU_INTERVAL = safeGetConfigValue('systemStatsCPU', 'updateInterval', 10000);
const CPU_HISTORY_MAX = safeGetConfigValue('systemStatsCPU', 'MaxHistoryLength', 60);

// RAM 统计相关
const RAM_INTERVAL = safeGetConfigValue('systemStatsRAM', 'updateInterval', 10000);
const RAM_HISTORY_MAX = safeGetConfigValue('systemStatsRAM', 'MaxHistoryLength', 60);

// IP请求计数存储（全局入站 IP 计数，来源可能是 pcap 或 API fallback）
const ipRequestCount = new Map();

// 是否使用 pcap 模式
let usingPcap = false;

//初始化ip地址排除规则
initExcludeRules();
let ipCollectionMode = 'api'; // api | nginx | pcap

if (config.getClientIp?.nginxAccessLogEnabled !== false) {
  let paths = config.getClientIp.nginxAccessLogPath || ['/var/log/nginx/access.log'];
  if (!Array.isArray(paths)) paths = [paths]; // 兼容字符串
  
  let anyOk = false;
  for (const p of paths) {
    if (startNginxLogMonitor(p)) anyOk = true;
  }
  if (anyOk) {
    ipCollectionMode = 'nginx';
    console.log('[IP统计] 模式: Nginx 日志（实时）');
  }
}
if (pcap && config.getClientIp && config.getClientIp.packetCaptureEnabled === true && ipCollectionMode === 'api') {
  try {
    // 显示所有可用网卡
    const allDevices = pcap.findalldevs();
    console.log('[抓包] 可用网卡列表:');
    allDevices.forEach((dev, i) => {
      console.log(`  [${i}] ${dev.name} - ${dev.addresses?.map(a => a.addr).join(', ') || '无地址'}`);
    });
    
    // 查找默认网卡（如果配置为空）
    let iface;
    if (config.getClientIp.packetCaptureInterface) {
      iface = config.getClientIp.packetCaptureInterface;
      console.log(`[抓包] 使用配置指定的网卡: ${iface}`);
    } else if (allDevices.length > 0) {
      iface = allDevices[0].name;
      console.log(`[抓包] 自动选择网卡: ${iface}`);
    } else {
      throw new Error('未找到可用网卡');
    }
    
    const filter = config.getClientIp.packetCaptureFilter || 'tcp';
    console.log(`[抓包] 过滤规则: ${filter}`);
    console.log(`[抓包] 正在创建抓包会话...`);
    
    const pcapSession = pcap.createSession(iface, filter);
    console.log(`[抓包] 会话创建成功，开始监听 ${iface}`);
    
    let packetCount = 0;
    
    pcapSession.on('packet', (rawPacket) => {
      packetCount++;
      try {
        const packet = pcap.decode.packet(rawPacket);
        
        // 调试：打印前5个包的结构
        if (packetCount <= 5) {
          console.log(`[抓包调试] 第${packetCount}个包结构:`, 
            JSON.stringify({
              hasPayload: !!packet.payload,
              payloadType: packet.payload?.constructor?.name,
              hasPayloadPayload: !!packet.payload?.payload,
              saddr: packet.payload?.payload?.saddr,
              daddr: packet.payload?.payload?.daddr
            }, null, 2));
        }
        
        // 提取源IP
        let ip = null;
        const saddr = packet.payload?.payload?.saddr 
                   || packet.payload?.saddr 
                   || packet.link?.ip?.saddr;
        
        if (saddr) {
          if (saddr.addr && Array.isArray(saddr.addr)) {
            if (saddr.addr.length === 4) {
              ip = saddr.addr.join('.');
            } else if (saddr.addr.length === 16) {
              const parts = [];
              for (let i = 0; i < 16; i += 2) {
                const hex = ((saddr.addr[i] << 8) | saddr.addr[i + 1]).toString(16);
                parts.push(hex);
              }
              ip = parts.join(':').replace(/(^|:)0(:0)*(:|$)/, '::');
            }
          } else if (typeof saddr === 'string') {
            ip = saddr;
          }
        }
        
        if (ip && !isIPExcluded(ip)) {
          const count = ipRequestCount.get(ip) || 0;
          ipRequestCount.set(ip, count + 1);
          
          if (packetCount % 100 === 0) {
            console.log(`[抓包] 已处理 ${packetCount} 个包，当前统计IP数: ${ipRequestCount.size}`);
          }
        }
      } catch (e) {
        if (packetCount <= 3) {
          console.error(`[抓包调试] 解析错误:`, e.message);
        }
      }
    });
    
    pcapSession.on('error', (err) => {
      console.error(`[抓包] 会话错误:`, err);
    });
    
    usingPcap = true;
    ipCollectionMode = 'pcap';
    console.log('[IP统计] 模式: pcap 抓包');
    
  } catch (err) {
    console.error(`[抓包] 启动失败: ${err.message}`);
    console.error(`[抓包] 错误堆栈:`, err.stack);
    console.error('[抓包] 可能原因：权限不足、网卡不存在或 pcap 模块问题');
  }
}



if (!usingPcap) {
  console.log('[IP统计] 使用 API 请求计数（降级模式）');
}

// 定时清空IP请求计数
const ipClearMinutes = (config.getClientIp && config.getClientIp.ipRequestCountSaveMinutes) || 60;
setInterval(() => {
  ipRequestCount.clear();
  console.log('IP请求计数已清空');
}, ipClearMinutes * 60 * 1000);


// 上一次CPU时间戳（用于计算CPU使用率）
let lastCpuInfo = null;
let lastCpuTimestamp = 0;

// 计算CPU使用率
function calculateCpuUsage() {
  const cpus = os.cpus();
  const now = Date.now();
  
  // 如果是第一次调用，返回N/A
  if (!lastCpuInfo) {
    lastCpuInfo = cpus;
    lastCpuTimestamp = now;
    return 'N/A';
  }
  
  // 计算时间差
  const timeDiff = now - lastCpuTimestamp;
  if (timeDiff === 0) {
    return 'N/A';
  }
  
  let totalIdle = 0;
  let totalTick = 0;
  
  // 计算所有CPU核心的总空闲时间和总时间
  for (let i = 0; i < cpus.length; i++) {
    const cpu = cpus[i];
    const lastCpu = lastCpuInfo[i];
    
    // 计算当前CPU的总时间
    let currentTick = 0;
    for (const type in cpu.times) {
      currentTick += cpu.times[type];
    }
    
    // 计算上次CPU的总时间
    let lastTick = 0;
    for (const type in lastCpu.times) {
      lastTick += lastCpu.times[type];
    }
    
    // 计算时间差
    const tickDiff = currentTick - lastTick;
    const idleDiff = cpu.times.idle - lastCpu.times.idle;
    
    totalIdle += idleDiff;
    totalTick += tickDiff;
  }
  
  // 计算CPU使用率
  if (totalTick > 0) {
    const usage = ((totalTick - totalIdle) / totalTick * 100).toFixed(2);
    
    // 更新上次CPU信息
    lastCpuInfo = cpus;
    lastCpuTimestamp = now;
    
    return usage + '%';
  }
  
  return 'N/A';
}

// 实际获取 CPU 即时信息 + 更新历史
function fetchCPUStats() {
  const cpus = os.cpus();
  const cpuCount = cpus.length;
  const cpuUsage = calculateCpuUsage();
  const cpuUsageValue = cpuUsage === 'N/A' ? 0 : parseFloat(cpuUsage.replace('%', '')) || 0;

  // 更新 CPU 历史
  const now = new Date();
  cpuHistory.timestamp.push(now.toISOString());
  cpuHistory.values.push(cpuUsageValue);
  // 保持长度
  while (cpuHistory.timestamp.length > CPU_HISTORY_MAX) {
    cpuHistory.timestamp.shift();
    cpuHistory.values.shift();
  }

  return {
    count: cpuCount,
    model: cpus[0].model,
    usage: cpuUsage,
    history: {
      timestamp: cpuHistory.timestamp,
      values: cpuHistory.values
    }
  };
}

// 实际获取 RAM 即时信息 + 更新历史
function fetchRAMStats() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memUsage = (usedMem / totalMem * 100).toFixed(2);

  const now = new Date();
  ramHistory.timestamp.push(now.toISOString());
  ramHistory.values.push(parseFloat(memUsage));
  // 保持长度
  while (ramHistory.timestamp.length > RAM_HISTORY_MAX) {
    ramHistory.timestamp.shift();
    ramHistory.values.shift();
  }

  return {
    total: (totalMem / 1024 / 1024 / 1024).toFixed(2) + ' GB',
    used: (usedMem / 1024 / 1024 / 1024).toFixed(2) + ' GB',
    free: (freeMem / 1024 / 1024 / 1024).toFixed(2) + ' GB',
    usage: memUsage + '%',
    history: {
      timestamp: ramHistory.timestamp,
      values: ramHistory.values
    }
  };
}

// 系统基础信息（不常变）
function getSystemInfo() {
  const uptime = os.uptime();
  return {
    uptime: Math.floor(uptime / 3600) + 'h ' + Math.floor((uptime % 3600) / 60) + 'm',
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch()
  };
}

// 缓存最近一次采集的结果，供 API 快速返回
let latestCPU = null;
let latestRAM = null;

function updateCPUAndCache() {
  latestCPU = fetchCPUStats();
}
function updateRAMAndCache() {
  latestRAM = fetchRAMStats();
}

// 立即执行一次并定时
updateCPUAndCache();
updateRAMAndCache();
setInterval(updateCPUAndCache, CPU_INTERVAL);
setInterval(updateRAMAndCache, RAM_INTERVAL);

// 获取系统资源使用情况（用于API，返回即时数据 + 历史）
function getSystemStats() {
  return {
    cpu: latestCPU || fetchCPUStats(),
    ram: latestRAM || fetchRAMStats(),
    system: getSystemInfo()
  };
}

// 获取请求数量前5的IP地址
function getTopIPs() {
  const topCount = (config.getClientIp && config.getClientIp.topIPCount) || 20;
  const sortedIPs = Array.from(ipRequestCount.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, topCount);
  
  return sortedIPs.map(([ip, count]) => ({ ip, count }));
}
// 频率限制存储
const rateLimitStore = new Map();

// 检查频率限制（稍作修改让他支持读取浮点数）
function checkRateLimit(ip) {
  // 本地请求不限制
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
    return true;
  }
  
  const now = Date.now();
  const lastRequest = rateLimitStore.get(ip);
  // 支持小数秒：直接 parseFloat，默认 10 秒
  const raw = config.server?.minSecondsAfterLastRequest;
  const seconds = parseFloat(raw);
  const limit = (isNaN(seconds) || seconds <= 0 ? 10 : seconds) * 1000;
  
  if (lastRequest && (now - lastRequest) < limit) {
    return false;
  }
  
  rateLimitStore.set(ip, now);
  return true;
}

// 获取客户端IP
function getClientIP(req) {
    const xForwardedFor = req.headers["x-forwarded-for"];
    if (config.getClientIp.getIpByXFF && xForwardedFor) {
      // x-forwarded-for 大多数情况下是 "client_ip, proxy_ip1, proxy_ip2"
      // 根据配置文件读取，默认从左侧读取第一个IP地址（即客户端IP）
      const ipList = xForwardedFor.split(",").map(ip => ip.trim()); // 可以先统一trim
      // 安全获取值
      let N = safeGetConfigValue('getClientIp.getIpByXFFCount', 1);
      
      // 确保N不超过数组边界
      if (N > ipList.length) {
          // 配置超出范围：记录警告，并回退到最后一个IP
          console.log(`[警告] getIpByXFFCount(${N}) 超出IP列表长度(${ipList.length})，将取最后一个IP`);
          N = ipList.length; // 取最后一个
      }
        
      if (config.getClientIp.getIpByXFFFromStart) {
          // 从开头数：索引 = N - 1
          return ipList[N - 1];
      } else {
         // 从末尾数：索引 = ipList.length - N
          return ipList[ipList.length - N];
      }
    }
    return (
      req.headers["x-real-ip"] ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
      req.ip
    );
  }



// Nginx 日志读取：实时监控 access.log，提取真实客户端 IP
function startNginxLogMonitor(logPath) {
  if (!fs.existsSync(logPath)) {
    console.warn(`[Nginx日志] 文件不存在: ${logPath}`);
    return false;
  }
  
  let lastSize = fs.statSync(logPath).size;
  console.log(`[Nginx日志] 开始监控 ${logPath}（初始大小 ${lastSize} 字节）`);
  
  fs.watch(logPath, (eventType) => {
    if (eventType === 'change') {
      try {
        const stats = fs.statSync(logPath);
        const newSize = stats.size;
        if (newSize < lastSize) lastSize = 0;
        if (newSize > lastSize) {
          const buffer = Buffer.alloc(newSize - lastSize);
          const fd = fs.openSync(logPath, 'r');
          fs.readSync(fd, buffer, 0, buffer.length, lastSize);
          fs.closeSync(fd);
          const newLines = buffer.toString().split('\n').filter(line => line.trim());

          for (const line of newLines) {
            // 提取行首第一个空格前的字符串作为 IP
            const firstSpace = line.indexOf(' ');
            if (firstSpace === -1) continue;
            const ip = line.substring(0, firstSpace).trim();

            // 简单校验：至少包含 . 或 :
            if (ip && ip !== '-' && (ip.includes('.') || ip.includes(':')) && !isIPExcluded(ip)) {
              const count = ipRequestCount.get(ip) || 0;
              ipRequestCount.set(ip, count + 1);
            }
          }
          lastSize = newSize;
        }
      } catch (e) {
        // 忽略读取错误
      }
    }
  });

  return true;
}







// ========== NapCat 状态检测 ==========
// 从配置文件读取 NapCat 相关设置
const NAPCAT_URL = (config.napcat && config.napcat.url) || 'http://127.0.0.1:3002/get_status/';
const NAPCAT_TOKEN = (config.napcat && config.napcat.token) || '';
const NAPCAT_CHECK_INTERVAL = safeGetConfigValue('napcat', 'updateInterval', 10000);

// NapCat 异常事件记录
const napcatEvents = [];
const NAPCAT_EVENTS_MAX = safeGetConfigValue('napcat.eventsMax', 100);

// NapCat 历史数据（独立）
const napcatHistory = {
  timestamp: [],
  delay: [],
  status: []   // 1=normal, 0=offline, -1=error, -2=not_running
};

// 当前NapCat状态缓存
let napcatStatusCache = {
  status: 'checking',      // checking | normal | offline | error | not_running
  delay: -1,
  lastCheck: null,
  rawResponse: null
};

// 用于追踪异常时间段
let currentAnomaly = null; // { type: 'offline'|'error'|'not_running', startTime, endTime, reason }

function addNapcatEvent(event) {
  napcatEvents.unshift(event);
  if (napcatEvents.length > NAPCAT_EVENTS_MAX) {
    napcatEvents.pop();
  }
}

async function checkNapcatStatus() {
  const startTime = Date.now();
  let delay = -1;
  let napcatData = null;
  let errorMsg = null;
  
  try {
    const response = await fetch(NAPCAT_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${NAPCAT_TOKEN}`
      },
      body: JSON.stringify({}),
      signal: AbortSignal.timeout(5000)
    });
    
    delay = Date.now() - startTime;
    
    if (!response.ok) {
      napcatStatusCache = {
        status: 'error',
        delay: delay,
        lastCheck: new Date().toISOString(),
        rawResponse: `HTTP ${response.status}`
      };
      handleNapcatAnomaly('error', `HTTP状态码异常: ${response.status}`);
      
      // 推入历史
      napcatHistory.timestamp.push(new Date().toISOString());
      napcatHistory.delay.push(delay);
      napcatHistory.status.push(-1);
      trimNapcatHistory();
      
      return napcatStatusCache;
    }
    
    napcatData = await response.json();
    
  } catch (err) {
    delay = Date.now() - startTime;
    errorMsg = err.message;
    
    if (err.message.includes('fetch failed') || err.message.includes('ECONNREFUSED') || err.message.includes('timeout')) {
      napcatStatusCache = {
        status: 'not_running',
        delay: delay,
        lastCheck: new Date().toISOString(),
        rawResponse: errorMsg
      };
      handleNapcatAnomaly('not_running', `NapCat未启动或配置文件出现了问题: ${errorMsg}`);
      
      napcatHistory.timestamp.push(new Date().toISOString());
      napcatHistory.delay.push(delay);
      napcatHistory.status.push(-2);
      trimNapcatHistory();
      
      return napcatStatusCache;
    }
    
    napcatStatusCache = {
      status: 'error',
      delay: delay,
      lastCheck: new Date().toISOString(),
      rawResponse: errorMsg
    };
    handleNapcatAnomaly('error', `请求异常: ${errorMsg}`);
    
    napcatHistory.timestamp.push(new Date().toISOString());
    napcatHistory.delay.push(delay);
    napcatHistory.status.push(-1);
    trimNapcatHistory();
    
    return napcatStatusCache;
  }
  
  // 解析响应
  const statusOk = napcatData?.status === 'ok';
  const online = napcatData?.data?.online === true;
  
  if (!statusOk) {
    napcatStatusCache = {
      status: 'error',
      delay: delay,
      lastCheck: new Date().toISOString(),
      rawResponse: napcatData
    };
    handleNapcatAnomaly('error', `NapCat状态异常: status=${napcatData?.status}`);
    
    napcatHistory.timestamp.push(new Date().toISOString());
    napcatHistory.delay.push(delay);
    napcatHistory.status.push(-1);
    trimNapcatHistory();
    
  } else if (!online) {
    napcatStatusCache = {
      status: 'offline',
      delay: delay,
      lastCheck: new Date().toISOString(),
      rawResponse: napcatData
    };
    handleNapcatAnomaly('offline', 'QQ已下线');
    
    napcatHistory.timestamp.push(new Date().toISOString());
    napcatHistory.delay.push(delay);
    napcatHistory.status.push(0);
    trimNapcatHistory();
    
  } else {
    napcatStatusCache = {
      status: 'normal',
      delay: delay,
      lastCheck: new Date().toISOString(),
      rawResponse: napcatData
    };
    resolveAnomaly();
    
    napcatHistory.timestamp.push(new Date().toISOString());
    napcatHistory.delay.push(delay);
    napcatHistory.status.push(1);
    trimNapcatHistory();
  }
  
  return napcatStatusCache;
}

// 保持历史数据长度
function trimNapcatHistory() {
  const maxLength = safeGetConfigValue('napcat', 'MaxHistoryLength', 60);
  if (napcatHistory.timestamp.length > maxLength) {
    napcatHistory.timestamp.shift();
    napcatHistory.delay.shift();
    napcatHistory.status.shift();
  }
}

function handleNapcatAnomaly(type, reason) {
  const now = new Date().toISOString();
  
  // 如果已经有同类型的异常在持续中，不重复记录
  if (currentAnomaly && currentAnomaly.type === type && !currentAnomaly.endTime) {
    return;
  }
  
  // 如果之前有不同类型的异常，先结束它
  if (currentAnomaly && !currentAnomaly.endTime) {
    currentAnomaly.endTime = now;
    addNapcatEvent({ ...currentAnomaly });
  }
  
  // 创建新的异常记录
  currentAnomaly = {
    type: type,
    startTime: now,
    endTime: null,
    reason: reason
  };
}

function resolveAnomaly() {
  if (currentAnomaly && !currentAnomaly.endTime) {
    currentAnomaly.endTime = new Date().toISOString();
    addNapcatEvent({ ...currentAnomaly });
    currentAnomaly = null;
  }
}

// 定时检查
setInterval(checkNapcatStatus, NAPCAT_CHECK_INTERVAL);

// 初始化时立即检查一次
checkNapcatStatus();

// 状态API路由
app.get('/api/status/', async (req, res) => {
  const clientIP = getClientIP(req);
  
  // 如果未使用 pcap，则回退到 API 请求计数
if (!usingPcap && !isIPExcluded(clientIP)) {
  const currentCount = ipRequestCount.get(clientIP) || 0;
  ipRequestCount.set(clientIP, currentCount + 1);
}
  
  if (config.server.enableRateLimit && !checkRateLimit(clientIP)) {
    console.log(`[状态API] IP ${clientIP} 请求过于频繁，请稍后再试`);
    return res.status(429).json({ success: false, message: '请求过于频繁，请稍后再试' });
  }
  
  try {
    const systemStats = getSystemStats();
    const topIPs = getTopIPs();
    
    // NapCat 独立历史
    const napcatHistoryData = {
      timestamp: napcatHistory.timestamp,
      delay: napcatHistory.delay,
      status: napcatHistory.status
    };
    
res.json({
  success: true,
  system: systemStats,
  topIPs: topIPs,
  topIPCount: (config.getClientIp && config.getClientIp.topIPCount) || 20,
  ipRequestCountSaveMinutes: (config.getClientIp && config.getClientIp.ipRequestCountSaveMinutes) || 60,
  napcat: {
    status: napcatStatusCache.status,
    delay: napcatStatusCache.delay,
    lastCheck: napcatStatusCache.lastCheck,
    rawResponse: napcatStatusCache.rawResponse,
    currentAnomaly: currentAnomaly || null,
    recentEvents: napcatEvents.slice(0, 20),
    history: napcatHistoryData
  },
  timestamp: new Date().toISOString()
});
  } catch (error) {
    console.error(`[状态API] 获取状态失败: ${error.message}`);
    res.status(500).json({ success: false, message: '获取状态失败' });
  }
});

// 启动服务器
app.listen(port, () => {
  if(!config) {
    console.warn(`[警告] 配置文件加载失败，路径：${configPath} ，将使用默认配置`);
  } else {
    console.log('[配置] 配置文件加载成功');
  }
  if (usingPcap) {
    console.log('[抓包] 全局入站 IP 统计已启用');
  }
  console.log(`服务器运行在 http://localhost:${port}`);
});