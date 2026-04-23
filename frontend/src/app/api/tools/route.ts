import { NextRequest, NextResponse } from "next/server";
import path from "path";
import fs from "fs/promises";

const PROJECT_ROOT = path.resolve(process.cwd(), "..");
const MCP_CONFIG_PATH = path.join(PROJECT_ROOT, "data", "mcp_tools.json");

interface MCPTool {
  id: string;
  name: string;
  description: string;
  serverUrl: string;
  enabled: boolean;
  addedAt: string;
}

// 内置渗透测试工具列表（从 Docker 容器中获取）
const BUILTIN_TOOLS = [
  {
    name: "nmap",
    description: "网络发现和安全审计工具，支持端口扫描、服务识别、操作系统检测",
    category: "网络扫描",
    usage: "nmap -sV -sC <target>",
    installed: true,
  },
  {
    name: "sqlmap",
    description: "自动化 SQL 注入检测和利用工具，支持多种数据库",
    category: "Web 漏洞",
    usage: "sqlmap -u <url> --dbs",
    installed: true,
  },
  {
    name: "nuclei",
    description: "基于模板的快速漏洞扫描器，支持自定义 PoC",
    category: "漏洞扫描",
    usage: "nuclei -u <url> -t <templates>",
    installed: true,
  },
  {
    name: "nikto",
    description: "Web 服务器漏洞扫描器，检测危险文件、过时软件等",
    category: "Web 扫描",
    usage: "nikto -h <target>",
    installed: true,
  },
  {
    name: "gobuster",
    description: "目录和文件暴力枚举工具，支持 DNS 子域名枚举",
    category: "目录扫描",
    usage: "gobuster dir -u <url> -w <wordlist>",
    installed: true,
  },
  {
    name: "ffuf",
    description: "高速 Web Fuzzer，支持目录、参数、虚拟主机枚举",
    category: "Fuzzing",
    usage: "ffuf -u <url>/FUZZ -w <wordlist>",
    installed: true,
  },
  {
    name: "hydra",
    description: "网络登录破解工具，支持多种协议的暴力破解",
    category: "密码破解",
    usage: "hydra -l <user> -P <passlist> <target> <protocol>",
    installed: true,
  },
  {
    name: "metasploit",
    description: "渗透测试框架，提供漏洞利用、Payload 生成等功能",
    category: "漏洞利用",
    usage: "msfconsole",
    installed: true,
  },
  {
    name: "burpsuite",
    description: "Web 应用安全测试平台，支持代理、扫描、入侵等",
    category: "Web 测试",
    usage: "burpsuite",
    installed: true,
  },
  {
    name: "zaproxy",
    description: "OWASP ZAP - 开源 Web 应用安全扫描器",
    category: "Web 扫描",
    usage: "zaproxy",
    installed: true,
  },
  {
    name: "whatweb",
    description: "Web 指纹识别工具，识别 CMS、框架、服务器等",
    category: "信息收集",
    usage: "whatweb <url>",
    installed: true,
  },
  {
    name: "wpscan",
    description: "WordPress 安全扫描器，检测插件、主题漏洞",
    category: "CMS 扫描",
    usage: "wpscan --url <url>",
    installed: true,
  },
  {
    name: "commix",
    description: "自动化命令注入检测和利用工具",
    category: "Web 漏洞",
    usage: "commix -u <url>",
    installed: true,
  },
  {
    name: "xsser",
    description: "自动化 XSS 漏洞检测和利用框架",
    category: "Web 漏洞",
    usage: "xsser -u <url>",
    installed: true,
  },
  {
    name: "sslscan",
    description: "SSL/TLS 配置扫描工具，检测弱加密和证书问题",
    category: "SSL 测试",
    usage: "sslscan <target>",
    installed: true,
  },
  {
    name: "amass",
    description: "子域名枚举和网络映射工具",
    category: "信息收集",
    usage: "amass enum -d <domain>",
    installed: true,
  },
  {
    name: "subfinder",
    description: "被动子域名发现工具，使用多种在线源",
    category: "信息收集",
    usage: "subfinder -d <domain>",
    installed: true,
  },
  {
    name: "httpx",
    description: "快速 HTTP 探测工具，支持批量 URL 检测",
    category: "HTTP 工具",
    usage: "httpx -l <urls.txt>",
    installed: true,
  },
  {
    name: "katana",
    description: "下一代爬虫框架，支持 JavaScript 渲染",
    category: "爬虫",
    usage: "katana -u <url>",
    installed: true,
  },
  {
    name: "masscan",
    description: "高速端口扫描器，可扫描整个互联网",
    category: "网络扫描",
    usage: "masscan -p<ports> <target>",
    installed: true,
  },
];

async function loadMCPTools(): Promise<MCPTool[]> {
  try {
    const content = await fs.readFile(MCP_CONFIG_PATH, "utf-8");
    return JSON.parse(content);
  } catch {
    return [];
  }
}

async function saveMCPTools(tools: MCPTool[]) {
  const dir = path.dirname(MCP_CONFIG_PATH);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(MCP_CONFIG_PATH, JSON.stringify(tools, null, 2), "utf-8");
}

/**
 * GET /api/tools - 获取所有工具
 */
export async function GET() {
  try {
    const mcpTools = await loadMCPTools();

    return NextResponse.json({
      success: true,
      builtinTools: BUILTIN_TOOLS,
      mcpTools,
      categories: [...new Set(BUILTIN_TOOLS.map((t) => t.category))],
    });
  } catch (error) {
    console.error("Failed to get tools:", error);
    return NextResponse.json(
      { success: false, error: "获取工具列表失败" },
      { status: 500 }
    );
  }
}

/**
 * POST /api/tools - MCP 工具操作
 */
export async function POST(request: NextRequest) {
  try {
    const { action, tool } = await request.json();

    if (action === "add") {
      // 添加 MCP 工具
      const mcpTools = await loadMCPTools();
      const newTool: MCPTool = {
        id: `mcp_${Date.now()}`,
        name: tool.name,
        description: tool.description,
        serverUrl: tool.serverUrl,
        enabled: true,
        addedAt: new Date().toISOString(),
      };
      mcpTools.push(newTool);
      await saveMCPTools(mcpTools);

      return NextResponse.json({
        success: true,
        message: "MCP 工具添加成功",
        tool: newTool,
      });
    }

    if (action === "remove") {
      // 删除 MCP 工具
      const mcpTools = await loadMCPTools();
      const filtered = mcpTools.filter((t) => t.id !== tool.id);
      await saveMCPTools(filtered);

      return NextResponse.json({ success: true, message: "MCP 工具已删除" });
    }

    if (action === "toggle") {
      // 切换 MCP 工具状态
      const mcpTools = await loadMCPTools();
      const updated = mcpTools.map((t) =>
        t.id === tool.id ? { ...t, enabled: !t.enabled } : t
      );
      await saveMCPTools(updated);

      return NextResponse.json({ success: true, message: "状态已更新" });
    }

    return NextResponse.json(
      { success: false, error: "未知操作" },
      { status: 400 }
    );
  } catch (error) {
    console.error("Tool operation failed:", error);
    return NextResponse.json(
      { success: false, error: "操作失败" },
      { status: 500 }
    );
  }
}
