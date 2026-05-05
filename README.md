# 服务器状态监控服务

一个轻量级的服务器状态实时监控系统，基于 Node.js 和 Express，提供简洁美观的Web界面。

## 功能特性

- 📊 **实时监控** - 实时显示CPU、内存等系统资源使用情况
- 📈 **历史数据** - 保存最近10分钟的资源使用历史（每10秒记录一次）
- 🌐 **Web界面** - 响应式设计，支持PC和移动设备访问
- 📊 **图表展示** - 使用Chart.js绘制动态实时图表
- 🖥️ **系统信息** - 显示服务器操作系统、CPU核心数、内存大小等基本信息
- 🔍 **IP统计** - 支持多种IP收集模式：API请求计数、Nginx日志监控、pcap抓包
- 🛡️ **IP排除规则** - 自动检测局域网网段并排除内部IP
- 🤖 **NapCat状态监控** - 集成NapCat机器人状态检测和异常事件记录
- ⚙️ **智能配置** - 自动配置补全和模块化配置管理

## 快速开始

### 前置要求

- Node.js >= 12.0
- npm 或 yarn

### 安装

```bash
# 克隆项目
git clone https://github.com/xfy2412/node_status_server_open_source.git
cd node_status_server_open_source

# 安装依赖
npm install
```

### 运行

```bash
# 开发模式
npm run dev

# 或使用 start 命令
npm start
```

服务器将在 `http://localhost:3000` 启动，打开浏览器访问即可。

## 项目结构

```
node_status_server_open_source/
├── server.js           # Express服务器主文件
├── package.json        # 项目配置和依赖
├── README.md          # 项目文档
├── config.json        # 配置文件
└── public/            # 前端静态文件目录
    └── index.html     # Web页面
```

### 依赖说明

**核心依赖：**
- `express` - Web服务器框架
- `os` - 系统信息获取

**可选依赖（用于增强功能）：**
- `pcap` - 网络抓包功能（`npm install pcap`）
- `fs` - 文件系统操作（内置）
- `net` - 网络操作（内置）
- `path` - 路径处理（内置）

### 配置说明

配置文件位于 [config.json](config.json)。以下是当前可用的主要配置选项及其默认值：

#### 服务器基础配置
- **`server.port`**: 服务器监听端口，默认 `3000`。
- **`server.enableRateLimit`**: 是否启用简单频率限制（对非本地IP），默认 `true`。
- **`server.minSecondsAfterLastRequest`**: 两次请求之间允许的最小秒数（当启用频率限制时），默认 `10`（支持小数秒）。

#### IP获取与统计配置
- **`getClientIp.getIpByXFF`**: 是否从 `X-Forwarded-For` 头中解析客户端 IP，默认 `true`。
- **`getClientIp.getIpByXFFFromStart`**: 从 `X-Forwarded-For` 的开头取第 N 个 IP（`true`）还是从末尾取（`false`），默认 `true`。
- **`getClientIp.getIpByXFFCount`**: 取 `X-Forwarded-For` 中的第 N 个 IP（与上项配合），默认 `1`。
- **`getClientIp.packetCaptureEnabled`**: 是否启用 pcap 模式统计入站请求（可能会看到一些CDN的回源ip，需要自行配置getClientIp.excludeIPs排除规则） 默认 `false`。
- **`getClientIp.packetCaptureInterface`**: 抓包使用的网卡接口，为空时自动选择第一个可用网卡。
- **`getClientIp.packetCaptureFilter`**: 抓包过滤规则，默认 `tcp`。
- **`getClientIp.nginxAccessLogEnabled`**: 是否启用 Nginx 日志监控，默认 `true`。
- **`getClientIp.nginxAccessLogPath`**: Nginx 访问日志路径，支持数组格式，默认 `["/var/log/nginx/access.log"]`。
- **`getClientIp.topIPCount`**: 显示排名前多少的IP地址，默认 `20`。
- **`getClientIp.ipRequestCountSaveMinutes`**: 清空 IP 请求计数的间隔（分钟），默认 `60`。
- **`getClientIp.excludeIPs`**: 手动排除的IP列表，默认 `[]`。
- **`getClientIp.autoDetectLAN`**: 是否自动检测局域网网段并排除，默认 `true`。

#### 系统统计配置
- **`systemStatsCPU.updateInterval`**: CPU 统计更新间隔（毫秒），默认 `10000`。
- **`systemStatsCPU.MaxHistoryLength`**: CPU 历史数据保留长度，默认 `60`。
- **`systemStatsRAM.updateInterval`**: 内存统计更新间隔（毫秒），默认 `10000`。
- **`systemStatsRAM.MaxHistoryLength`**: 内存历史数据保留长度，默认 `60`。

#### NapCat 配置
- **`napcat.url`**: NapCat 状态检测接口 URL，默认 `http://127.0.0.1:3002/get_status/`。
- **`napcat.token`**: NapCat 认证令牌，默认空。
- **`napcat.updateInterval`**: NapCat 状态检查间隔（毫秒），默认 `10000`。
- **`napcat.eventsMax`**: NapCat 异常事件最大记录数，默认 `100`。

#### 全局配置
- **`autoCompleteConfig`**: 是否自动补全缺失的配置项，默认 `true`。
- **`updateInterval`**: 全局更新间隔（毫秒），默认 `10000`。
- **`MaxHistoryLength`**: 全局历史数据保留长度，默认 `60`。

修改 `config.json` 后需重启服务以使配置生效。配置支持自动补全功能，缺失的配置项会自动使用默认值。

## 新功能使用说明

### IP统计模式
服务器支持三种IP统计模式，按优先级顺序自动选择：

1. **Nginx日志模式**（推荐）
   - 实时监控Nginx访问日志文件
   - 自动提取客户端IP地址
   - 配置：`getClientIp.nginxAccessLogEnabled = true`

2. **pcap抓包模式**
   - 使用pcap库进行网络抓包
   - 需要安装pcap依赖：`npm install pcap`
   - 需要root权限或CAP_NET_RAW能力
   -（可能会看到一些CDN的回源ip，需要自行配置getClientIp.excludeIPs排除规则）
   - 配置：`getClientIp.packetCaptureEnabled = true`

3. **API请求计数模式**（降级模式）
   - 通过API请求计数统计IP
   - 在前两种模式不可用时自动启用
- 使用 CDN 时获取真实客户端 IP：若服务前面部署了 CDN（如 Cloudflare），Nginx 日志中记录的可能是 CDN 回源 IP，而非真实客户端 IP。可通过 Nginx 的 `ngx_http_realip_module` 模块将真实 IP 传递给日志。在 Nginx 配置中添加以下内容：
  \```nginx
  set_real_ip_from 回源IP/网段;
  real_ip_header X-Forwarded-For;
  \```
  其中 `回源IP/网段` 需替换为 CDN 提供的回源 IP 列表或网段。配置后 Nginx 日志会正确记录 `X-Forwarded-For` 头中的客户端 IP，本监控系统即可从日志中提取真实 IP
  
### IP排除规则
系统自动检测局域网网段并排除内部IP，避免统计内部流量：
- 自动检测所有非回环网卡的IP段
- 支持手动添加排除IP列表
- 默认排除回环地址、链路本地地址等

### NapCat状态监控
集成NapCat机器人状态检测功能：
- 定时检测NapCat服务状态
- 记录异常事件和时间段
- 支持认证令牌配置
- 提供延迟和状态历史数据

### 智能配置管理
- **自动配置补全**：缺失的配置项会自动使用默认值
- **模块化配置**：支持CPU、RAM、NapCat等模块独立配置
- **配置验证**：自动验证配置值的有效性

## API接口

### 获取系统状态

**请求：**
```
GET /api/status
```

**响应示例：**
```json
{
    "success": true,
    "system": {
        "memory": {
            "total": "31.82 GB",
            "used": "28.20 GB",
            "free": "3.62 GB",
            "usage": "88.62%"
        },
        "cpu": {
            "count": 20,
            "model": "Intel(R) Core(TM) i5-14600KF",
            "usage": "12.05%"
        },
        "system": {
            "uptime": "9h 47m",
            "hostname": "xfy-Colorful",
            "platform": "win32",
            "arch": "x64"
        },
        "history": {
            "timestamp": [
                "2026-02-07T21:03:35.997Z",
                "2026-02-07T21:03:45.996Z"
            ],
            "memory": [
                88.84,
                88.62
            ],
            "cpu": [
                0,
                12.05
            ]
        }
    },
    "topIPs": [
        {
            "ip": "::1",
            "count": 1
        }
    ],
    "timestamp": "2026-02-07T21:03:47.055Z"
}
```

## 页面功能

- **系统信息卡片** - 显示操作系统、CPU核心数、总内存等信息
- **实时数据展示** - 以百分比形式实时显示CPU和内存使用率
- **实时图表** - 动态更新的折线图，展示最近10分钟的数据趋势
- **IP访问统计** - 列表显示各IP地址的请求次数

## 技术栈

- **后端框架** - Express.js
- **前端图表库** - Chart.js
- **系统信息获取** - Node.js os 模块

## 依赖

- [express](https://expressjs.com/) - Web应用框架

## 自定义配置

### 环境变量覆盖

你可以使用环境变量覆盖配置中的端口（常见于容器/云部署）：

```bash
# 使用环境变量覆盖端口
PORT=8080 npm start
```

建议在生产环境中通过 `process manager`（如 `pm2`）或 `systemd` 启动并管理进程。

### 示例配置片段（config.json）

```json
{
    "server": {
        "port": 3000,
        "enableRateLimit": true,
        "minSecondsAfterLastRequest": 10
    },
    "getClientIp": {
        "getIpByXFF": true,
        "getIpByXFFFromStart": true,
        "getIpByXFFCount": 1
    },
    "systemStats": {
        "updateInterval": 10000,
        "ipRequestCountSaveMinutes": 60,
        "MaxHistoryLength": 60
    }
}
```

修改 `config.json` 后需重启服务以使配置生效。

## 使用场景

- 🖥️ VPS/云服务器监控
- 📊 学习 Node.js 和 Express 的示例项目
- 🔧 内网服务器状态展示板
- 📈 简单的系统资源监控工具

## 注意事项

- 历史数据默认保留最近10分钟的数据
- 开启服务器后每小时清空IP统计
- 建议在局域网或受信网络内使用

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License

## 作者

xfy2412

---

**更新日期**: 2026年2月

如有问题或建议，欢迎提出 Issue！
