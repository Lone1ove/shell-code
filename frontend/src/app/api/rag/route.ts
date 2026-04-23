import { NextRequest, NextResponse } from "next/server";
import path from "path";
import fs from "fs/promises";

const PROJECT_ROOT = path.resolve(process.cwd(), "..");
const RAG_DIR = path.join(PROJECT_ROOT, "data", "rag");
const RAG_CONFIG_PATH = path.join(RAG_DIR, "config.json");
const RAG_DOCS_DIR = path.join(RAG_DIR, "documents");

interface RAGDocument {
  id: string;
  name: string;
  type: string;
  size: number;
  uploadedAt: string;
  chunks?: number;
}

interface RAGConfig {
  enabled: boolean;
  documentsCount: number;
  totalChunks: number;
  lastUpdated?: string;
  documents: RAGDocument[];
}

async function ensureRAGDir() {
  await fs.mkdir(RAG_DIR, { recursive: true });
  await fs.mkdir(RAG_DOCS_DIR, { recursive: true });
}

async function loadRAGConfig(): Promise<RAGConfig> {
  try {
    const content = await fs.readFile(RAG_CONFIG_PATH, "utf-8");
    return JSON.parse(content);
  } catch {
    return {
      enabled: false,
      documentsCount: 0,
      totalChunks: 0,
      documents: [],
    };
  }
}

async function saveRAGConfig(config: RAGConfig) {
  await ensureRAGDir();
  await fs.writeFile(RAG_CONFIG_PATH, JSON.stringify(config, null, 2), "utf-8");
}

/**
 * GET /api/rag - 获取 RAG 配置和文档列表
 */
export async function GET() {
  try {
    await ensureRAGDir();
    const config = await loadRAGConfig();

    // 扫描文档目录
    const files = await fs.readdir(RAG_DOCS_DIR).catch(() => []);
    const documents: RAGDocument[] = [];

    for (const file of files) {
      const filePath = path.join(RAG_DOCS_DIR, file);
      const stat = await fs.stat(filePath);
      if (stat.isFile()) {
        const ext = path.extname(file).toLowerCase();
        documents.push({
          id: Buffer.from(file).toString("base64"),
          name: file,
          type: ext.replace(".", "") || "unknown",
          size: stat.size,
          uploadedAt: stat.mtime.toISOString(),
        });
      }
    }

    return NextResponse.json({
      success: true,
      config: {
        enabled: config.enabled,
        documentsCount: documents.length,
        totalChunks: config.totalChunks,
        lastUpdated: config.lastUpdated,
      },
      documents,
    });
  } catch (error) {
    console.error("Failed to get RAG config:", error);
    return NextResponse.json(
      { success: false, error: "获取 RAG 配置失败" },
      { status: 500 }
    );
  }
}

/**
 * POST /api/rag - RAG 操作
 */
export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const action = formData.get("action") as string;

    if (action === "upload") {
      // 上传文档
      const file = formData.get("file") as File;
      if (!file) {
        return NextResponse.json(
          { success: false, error: "未提供文件" },
          { status: 400 }
        );
      }

      await ensureRAGDir();
      const buffer = Buffer.from(await file.arrayBuffer());
      const filePath = path.join(RAG_DOCS_DIR, file.name);
      await fs.writeFile(filePath, buffer);

      // 更新配置
      const config = await loadRAGConfig();
      config.lastUpdated = new Date().toISOString();
      config.documentsCount += 1;
      await saveRAGConfig(config);

      return NextResponse.json({
        success: true,
        message: "文档上传成功",
        document: {
          id: Buffer.from(file.name).toString("base64"),
          name: file.name,
          type: path.extname(file.name).replace(".", ""),
          size: file.size,
          uploadedAt: new Date().toISOString(),
        },
      });
    }

    if (action === "delete") {
      // 删除文档
      const docId = formData.get("id") as string;
      const fileName = Buffer.from(docId, "base64").toString("utf-8");
      const filePath = path.join(RAG_DOCS_DIR, fileName);

      await fs.unlink(filePath);

      const config = await loadRAGConfig();
      config.lastUpdated = new Date().toISOString();
      config.documentsCount = Math.max(0, config.documentsCount - 1);
      await saveRAGConfig(config);

      return NextResponse.json({ success: true, message: "文档删除成功" });
    }

    if (action === "reset") {
      // 重置知识库
      await ensureRAGDir();
      const files = await fs.readdir(RAG_DOCS_DIR);
      for (const file of files) {
        await fs.unlink(path.join(RAG_DOCS_DIR, file));
      }

      await saveRAGConfig({
        enabled: false,
        documentsCount: 0,
        totalChunks: 0,
        lastUpdated: new Date().toISOString(),
        documents: [],
      });

      return NextResponse.json({ success: true, message: "知识库已重置" });
    }

    if (action === "toggle") {
      // 切换启用状态
      const config = await loadRAGConfig();
      config.enabled = !config.enabled;
      config.lastUpdated = new Date().toISOString();
      await saveRAGConfig(config);

      return NextResponse.json({
        success: true,
        enabled: config.enabled,
        message: config.enabled ? "RAG 已启用" : "RAG 已禁用",
      });
    }

    return NextResponse.json(
      { success: false, error: "未知操作" },
      { status: 400 }
    );
  } catch (error) {
    console.error("RAG operation failed:", error);
    return NextResponse.json(
      { success: false, error: "操作失败" },
      { status: 500 }
    );
  }
}
