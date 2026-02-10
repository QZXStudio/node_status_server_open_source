const express = require('express');
const os = require('os');
const path = require('path');
const net = require('net');
const fs = require('fs');
const configPath = path.join(__dirname, 'config.json');

// 默认配置（用于在配置文件缺失时创建默认 config.json）
const defaultConfig = {
  server: {
    port: 3000,
    enableRateLimit: true,
    minSecondsAfterLastRequest: 10
  },
  getClientIp: {
    getIpByXFF: true,
    getIpByXFFFromStart: true,
    getIpByXFFCount: 1
  },
  systemStats: {
    updateInterval: 10000,
    ipRequestCountSaveMinutes: 60,
    MaxHistoryLength: 60
  }
};

// 尝试安全加载配置文件：若不存在则创建默认文件并提示用户重启（不自动重启）
let config = {};
let configLoaded = false;
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
}

const app = express();
app.set('trust proxy', true); // 如果服务器部署在反向代理后面，启用此设置以正确获取客户端IP地址
const port = process.env.PORT || safeGetConfigValue('server.port', 3000);

// 静态文件服务
app.use(express.static(path.join(__dirname, 'public')));

// 资源使用历史数据（10分钟，每10秒一条）
const resourceHistory = {
  cpu: [],
  memory: [],
  timestamp: []
};

// 安全获取配置值的函数，支持嵌套路径
function safeGetConfigValue(path, defaultValue) {
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


// 系统状态缓存
let systemStatsCache = null;
let lastCacheUpdate = 0;
const CACHE_INTERVAL = safeGetConfigValue('systemStats.updateInterval', 10000); // 默认10秒

// IP请求计数存储
const ipRequestCount = new Map();

// 定时清空IP请求计数（默认每小时）
setInterval(() => {
  ipRequestCount.clear();
  console.log('IP请求计数已清空');
}, safeGetConfigValue('systemStats.ipRequestCountSaveMinutes', 60) * 60 * 1000);

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

// 实际获取系统资源使用情况的函数
function fetchSystemStats() {
  try {
    // 内存使用情况
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const memUsage = (usedMem / totalMem * 100).toFixed(2);
    
    // CPU使用情况
    const cpus = os.cpus();
    const cpuCount = cpus.length;
    
    // 计算CPU使用率
    const cpuUsage = calculateCpuUsage();
    
    // 系统信息
    const uptime = os.uptime();
    const hostname = os.hostname();
    const platform = os.platform();
    const arch = os.arch();
    
    // 更新资源历史数据
    const now = new Date();
    resourceHistory.timestamp.push(now.toISOString());
    resourceHistory.memory.push(parseFloat(memUsage));
    // 解析CPU使用率，移除'%'符号
    const cpuUsageValue = cpuUsage === 'N/A' ? 0 : parseFloat(cpuUsage.replace('%', '')) || 0;
    resourceHistory.cpu.push(cpuUsageValue);

    // 安全获取值
    // MaxHistoryLength: 保留的历史数据点数量。
    // 例: 当 systemStats.updateInterval = 10000 ms（10s）且 MaxHistoryLength = 60 时，
    // 保留时间为 60 * 10s = 600s = 10 分钟。
    let MaxLength = safeGetConfigValue('systemStats.MaxHistoryLength', 60);

    // 保持历史数据长度
    const maxDataPoints = MaxLength;
    if (resourceHistory.timestamp.length > maxDataPoints) {
      resourceHistory.timestamp.shift();
      resourceHistory.memory.shift();
      resourceHistory.cpu.shift();
    }
    
    const stats = {
      memory: {
        total: (totalMem / 1024 / 1024 / 1024).toFixed(2) + ' GB',
        used: (usedMem / 1024 / 1024 / 1024).toFixed(2) + ' GB',
        free: (freeMem / 1024 / 1024 / 1024).toFixed(2) + ' GB',
        usage: memUsage + '%'
      },
      cpu: {
        count: cpuCount,
        model: cpus[0].model,
        usage: cpuUsage
      },
      system: {
        uptime: Math.floor(uptime / 3600) + 'h ' + Math.floor((uptime % 3600) / 60) + 'm',
        hostname,
        platform,
        arch
      },
      history: {
        timestamp: resourceHistory.timestamp,
        memory: resourceHistory.memory,
        cpu: resourceHistory.cpu
      }
    };
    
    // 更新缓存
    systemStatsCache = stats;
    lastCacheUpdate = Date.now();
    
    return stats;
  } catch (error) {
    console.error('[系统信息] 获取系统信息失败:', error.message);
    return {
      memory: {
        total: 'N/A',
        used: 'N/A',
        free: 'N/A',
        usage: 'N/A'
      },
      cpu: {
        count: 'N/A',
        model: 'N/A',
        usage: 'N/A'
      },
      system: {
        uptime: 'N/A',
        hostname: 'N/A',
        platform: 'N/A',
        arch: 'N/A'
      },
      history: {
        timestamp: [],
        memory: [],
        cpu: []
      }
    };
  }
}

// 获取系统资源使用情况（使用缓存）
function getSystemStats() {
  const now = Date.now();
  
  // 检查缓存是否有效
  if (systemStatsCache && (now - lastCacheUpdate) < CACHE_INTERVAL) {
    return systemStatsCache;
  }
  
  // 缓存无效，重新获取
  return fetchSystemStats();
}

// 获取请求数量前5的IP地址
function getTopIPs() {
  // 将Map转换为数组并排序
  const sortedIPs = Array.from(ipRequestCount.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  
  return sortedIPs.map(([ip, count]) => ({ ip, count }));
}

// 频率限制存储
const rateLimitStore = new Map();

// 检查频率限制
function checkRateLimit(ip) {
  // 本地请求不限制
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
    return true;
  }
  
  const now = Date.now();
  const lastRequest = rateLimitStore.get(ip);
  const limit = safeGetConfigValue('server.minSecondsAfterLastRequest', 10) * 1000; // 默认10秒
  
  if (lastRequest && (now - lastRequest) < limit) { // 限制时间
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

// 状态API路由
app.get('/api/status', (req, res) => {
  const clientIP = getClientIP(req);
  
  // 增加IP请求计数
  const currentCount = ipRequestCount.get(clientIP) || 0;
  ipRequestCount.set(clientIP, currentCount + 1);
  
  // 检查频率限制
  if (config.server.enableRateLimit && !checkRateLimit(clientIP)) {
    console.log(`[状态API] IP ${clientIP} 请求过于频繁，请稍后再试`);
    return res.status(429).json({ success: false, message: '请求过于频繁，请稍后再试' });
  }
  
  try {
    // 获取系统资源使用情况
    const systemStats = getSystemStats();
    // 获取请求数量前5的IP地址
    const topIPs = getTopIPs();
    
    // 返回状态信息
    res.json({
      success: true,      
      system: systemStats,
      topIPs: topIPs,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error(`[状态API] 获取状态失败: ${error.message}`);
    res.status(500).json({ success: false, message: '获取状态失败' });
  }
});

// 定时更新系统状态缓存
setInterval(fetchSystemStats, CACHE_INTERVAL);

// 启动服务器
app.listen(port, () => {
  if(!config) {
    console.warn(`[警告] 配置文件加载失败，路径：${configPath} ，将使用默认配置`);
  } else {
    console.log('[配置] 配置文件加载成功');
  }

  console.log(`服务器运行在 http://localhost:${port}`);
  // 初始获取系统状态
  fetchSystemStats();
});
