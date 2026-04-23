import { NextRequest, NextResponse } from "next/server";
import { spawn, execSync } from "child_process";
import path from "path";
import fs from "fs/promises";
import { existsSync } from "fs";

const PROJECT_ROOT = path.resolve(process.cwd(), "..");
const SKILLS_DIR = path.join(PROJECT_ROOT, "shell_agent", "skills");
const DOCKER_SKILLS_PATH = "/opt/custom-skills";

// 从环境变量或默认值获取容器名
function getContainerName(): string {
  // 尝试读取 .env 文件
  try {
    const envPath = path.join(PROJECT_ROOT, ".env");
    if (existsSync(envPath)) {
      const envContent = require("fs").readFileSync(envPath, "utf-8");
      const match = envContent.match(/DOCKER_CONTAINER_NAME=(.+)/);
      if (match) return match[1].trim();
    }
  } catch {}
  return "kali-pentest";
}

interface SkillMeta {
  key: string;
  name: string;
  source: string;
  path: string;
  keywords: string[];
  description: string;
  files: SkillFile[];
  hasScripts: boolean;
  syncedToDocker: boolean;
}

interface SkillFile {
  name: string;
  type: "markdown" | "python" | "shell" | "other";
  size: number;
  executable: boolean;
}

async function extractFrontmatter(content: string): Promise<{ name: string; description: string }> {
  if (!content.startsWith("---")) {
    return { name: "", description: "" };
  }
  const endIdx = content.indexOf("\n---", 3);
  if (endIdx === -1) {
    return { name: "", description: "" };
  }
  const fm = content.slice(3, endIdx);
  const nameMatch = fm.match(/^name:\s*(.+)$/m);
  const descMatch = fm.match(/^description:\s*(.+)$/m);
  return {
    name: nameMatch ? nameMatch[1].trim() : "",
    description: descMatch ? descMatch[1].trim() : "",
  };
}

function getFileType(filename: string): SkillFile["type"] {
  const ext = path.extname(filename).toLowerCase();
  if (ext === ".md") return "markdown";
  if (ext === ".py") return "python";
  if (ext === ".sh" || ext === ".bash") return "shell";
  return "other";
}

function isExecutable(filename: string): boolean {
  const ext = path.extname(filename).toLowerCase();
  return [".py", ".sh", ".bash", ".pl", ".rb"].includes(ext);
}

async function scanSkillFiles(skillDir: string): Promise<SkillFile[]> {
  const files: SkillFile[] = [];
  try {
    const entries = await fs.readdir(skillDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      if (entry.name.startsWith(".")) continue;

      const filePath = path.join(skillDir, entry.name);
      const stat = await fs.stat(filePath);

      files.push({
        name: entry.name,
        type: getFileType(entry.name),
        size: stat.size,
        executable: isExecutable(entry.name),
      });
    }
  } catch {}
  return files;
}

async function scanSkillsDirectory(): Promise<SkillMeta[]> {
  const skills: SkillMeta[] = [];

  try {
    const entries = await fs.readdir(SKILLS_DIR, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith(".") || entry.name.startsWith("__")) continue;

      const skillDir = path.join(SKILLS_DIR, entry.name);
      const skillPath = path.join(skillDir, "SKILL.md");

      try {
        const content = await fs.readFile(skillPath, "utf-8");
        const { name, description } = await extractFrontmatter(content);
        const files = await scanSkillFiles(skillDir);
        const hasScripts = files.some((f) => f.executable);

        skills.push({
          key: entry.name,
          name: name || entry.name,
          source: "builtin",
          path: skillPath,
          keywords: entry.name.split("-"),
          description: description || `${entry.name} 渗透测试技能模块`,
          files,
          hasScripts,
          syncedToDocker: false, // 稍后检查
        });
      } catch {
        // SKILL.md 不存在，跳过
      }
    }
  } catch (error) {
    console.error("Failed to scan skills directory:", error);
  }

  return skills;
}

// 检查 Docker 容器是否运行
function isDockerRunning(): boolean {
  try {
    const containerName = getContainerName();
    const result = execSync(`docker inspect -f "{{.State.Running}}" ${containerName} 2>/dev/null`, {
      encoding: "utf-8",
    });
    return result.trim() === "true";
  } catch {
    return false;
  }
}

// 同步技能脚本到 Docker 容器
async function syncSkillToDocker(skillKey: string): Promise<{ success: boolean; message: string }> {
  const containerName = getContainerName();
  const skillDir = path.join(SKILLS_DIR, skillKey);

  if (!isDockerRunning()) {
    return { success: false, message: "Docker 容器未运行" };
  }

  try {
    // 1. 在容器中创建目标目录
    const targetDir = `${DOCKER_SKILLS_PATH}/${skillKey}`;
    execSync(`docker exec ${containerName} mkdir -p ${targetDir}`, { encoding: "utf-8" });

    // 2. 复制所有文件到容器
    const files = await fs.readdir(skillDir);
    for (const file of files) {
      const srcPath = path.join(skillDir, file);
      const stat = await fs.stat(srcPath);
      if (!stat.isFile()) continue;

      // 使用 docker cp 复制文件
      execSync(`docker cp "${srcPath}" ${containerName}:${targetDir}/${file}`, { encoding: "utf-8" });

      // 如果是可执行脚本，设置执行权限
      if (isExecutable(file)) {
        execSync(`docker exec ${containerName} chmod +x ${targetDir}/${file}`, { encoding: "utf-8" });
      }
    }

    // 3. 如果有 requirements.txt，安装依赖
    const reqPath = path.join(skillDir, "requirements.txt");
    if (existsSync(reqPath)) {
      try {
        execSync(
          `docker exec ${containerName} pip3 install -r ${targetDir}/requirements.txt --break-system-packages -q`,
          { encoding: "utf-8", timeout: 60000 }
        );
      } catch (e) {
        console.warn("Failed to install requirements:", e);
      }
    }

    return { success: true, message: `技能已同步到容器 ${targetDir}` };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return { success: false, message: `同步失败: ${msg}` };
  }
}

// 从 Docker 容器删除技能
async function removeSkillFromDocker(skillKey: string): Promise<{ success: boolean; message: string }> {
  const containerName = getContainerName();

  if (!isDockerRunning()) {
    return { success: false, message: "Docker 容器未运行" };
  }

  try {
    const targetDir = `${DOCKER_SKILLS_PATH}/${skillKey}`;
    execSync(`docker exec ${containerName} rm -rf ${targetDir}`, { encoding: "utf-8" });
    return { success: true, message: "技能已从容器中删除" };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return { success: false, message: `删除失败: ${msg}` };
  }
}

// 生成 SKILL.md 模板
function generateSkillTemplate(name: string, description: string, scripts: string[]): string {
  const scriptSection = scripts.length > 0
    ? `
## 包含脚本

${scripts.map((s) => `- \`${s}\``).join("\n")}

## 使用方法

\`\`\`bash
# 脚本位于容器内 ${DOCKER_SKILLS_PATH}/<skill-key>/
cd ${DOCKER_SKILLS_PATH}/<skill-key>

# 执行脚本示例
${scripts.map((s) => {
  if (s.endsWith(".py")) return `python3 ${s} --help`;
  if (s.endsWith(".sh")) return `./${s}`;
  return `# ${s}`;
}).join("\n")}
\`\`\`
`
    : "";

  return `---
name: ${name}
description: ${description}
---

# ${name}

${description}
${scriptSection}
## 注意事项

- 请确保目标在授权范围内
- 使用前请阅读脚本源码了解其功能
`;
}

/**
 * GET /api/skills - 获取所有技能列表
 */
export async function GET() {
  try {
    const skills = await scanSkillsDirectory();
    const dockerRunning = isDockerRunning();

    return NextResponse.json({
      success: true,
      skills,
      total: skills.length,
      dockerRunning,
      dockerSkillsPath: DOCKER_SKILLS_PATH,
    });
  } catch (error) {
    console.error("Failed to get skills:", error);
    return NextResponse.json(
      { success: false, error: "获取技能列表失败" },
      { status: 500 }
    );
  }
}

/**
 * POST /api/skills - 技能操作
 */
export async function POST(request: NextRequest) {
  try {
    const contentType = request.headers.get("content-type") || "";

    // 处理 multipart/form-data（文件上传）
    if (contentType.includes("multipart/form-data")) {
      const formData = await request.formData();
      const action = formData.get("action") as string;

      if (action === "create" || action === "upload") {
        const key = (formData.get("key") as string)?.toLowerCase().replace(/\s+/g, "-");
        const name = formData.get("name") as string || key;
        const description = formData.get("description") as string || "自定义技能模块";
        const skillContent = formData.get("content") as string || "";

        if (!key) {
          return NextResponse.json({ success: false, error: "技能标识不能为空" }, { status: 400 });
        }

        // 创建技能目录
        const skillDir = path.join(SKILLS_DIR, key);
        await fs.mkdir(skillDir, { recursive: true });

        // 收集上传的脚本文件
        const uploadedScripts: string[] = [];
        const files = formData.getAll("files") as File[];

        for (const file of files) {
          if (file && file.size > 0) {
            const buffer = Buffer.from(await file.arrayBuffer());
            const filePath = path.join(skillDir, file.name);
            await fs.writeFile(filePath, buffer);

            if (isExecutable(file.name)) {
              uploadedScripts.push(file.name);
            }
          }
        }

        // 生成或使用提供的 SKILL.md
        let finalContent = skillContent;
        if (!finalContent || finalContent.trim() === "") {
          finalContent = generateSkillTemplate(name, description, uploadedScripts);
        } else {
          // 添加 frontmatter
          if (!finalContent.startsWith("---")) {
            finalContent = `---
name: ${name}
description: ${description}
---

${finalContent}`;
          }
        }

        await fs.writeFile(path.join(skillDir, "SKILL.md"), finalContent, "utf-8");

        // 如果有脚本，自动同步到 Docker
        let syncResult = { success: true, message: "" };
        if (uploadedScripts.length > 0 && isDockerRunning()) {
          syncResult = await syncSkillToDocker(key);
        }

        return NextResponse.json({
          success: true,
          message: "技能创建成功",
          key,
          scripts: uploadedScripts,
          synced: syncResult.success,
          syncMessage: syncResult.message,
        });
      }

      return NextResponse.json({ success: false, error: "未知操作" }, { status: 400 });
    }

    // 处理 JSON 请求
    const { action, key, content, name, description } = await request.json();

    if (action === "get") {
      const skillPath = path.join(SKILLS_DIR, key, "SKILL.md");
      const skillContent = await fs.readFile(skillPath, "utf-8");
      const files = await scanSkillFiles(path.join(SKILLS_DIR, key));
      return NextResponse.json({ success: true, content: skillContent, files });
    }

    if (action === "create") {
      const skillDir = path.join(SKILLS_DIR, key);
      await fs.mkdir(skillDir, { recursive: true });

      const frontmatter = `---
name: ${name || key}
description: ${description || "自定义技能模块"}
---

${content || "# " + (name || key) + "\n\n请在此编写技能内容..."}`;

      await fs.writeFile(path.join(skillDir, "SKILL.md"), frontmatter, "utf-8");
      return NextResponse.json({ success: true, message: "技能创建成功" });
    }

    if (action === "update") {
      const skillPath = path.join(SKILLS_DIR, key, "SKILL.md");
      await fs.writeFile(skillPath, content, "utf-8");
      return NextResponse.json({ success: true, message: "技能更新成功" });
    }

    if (action === "delete") {
      // 先从 Docker 删除
      await removeSkillFromDocker(key);
      // 再删除本地文件
      const skillDir = path.join(SKILLS_DIR, key);
      await fs.rm(skillDir, { recursive: true, force: true });
      return NextResponse.json({ success: true, message: "技能删除成功" });
    }

    if (action === "sync") {
      // 手动同步到 Docker
      const result = await syncSkillToDocker(key);
      return NextResponse.json({ success: result.success, message: result.message });
    }

    if (action === "sync-all") {
      // 同步所有带脚本的技能
      const skills = await scanSkillsDirectory();
      const results: { key: string; success: boolean; message: string }[] = [];

      for (const skill of skills) {
        if (skill.hasScripts) {
          const result = await syncSkillToDocker(skill.key);
          results.push({ key: skill.key, ...result });
        }
      }

      return NextResponse.json({ success: true, results });
    }

    return NextResponse.json({ success: false, error: "未知操作" }, { status: 400 });
  } catch (error) {
    console.error("Skill operation failed:", error);
    const msg = error instanceof Error ? error.message : "操作失败";
    return NextResponse.json({ success: false, error: msg }, { status: 500 });
  }
}
