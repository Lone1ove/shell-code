import { NextRequest, NextResponse } from "next/server";
import path from "path";
import fs from "fs/promises";

const PROJECT_ROOT = path.resolve(process.cwd(), "..");
const CVE_INTEL_PATH = path.join(PROJECT_ROOT, "data", "cve_intel", "cve_intel.json");
const CUSTOM_CVE_PATH = path.join(PROJECT_ROOT, "data", "cve_intel", "custom_cve.json");

interface CVERecord {
  cve_id: string;
  source: string;
  description: string;
  severity: string;
  cvss?: number;
  product_family: string;
  protocols: string[];
  prerequisites: string[];
  poc_available: boolean;
  references: string[];
  updated_at: string;
}

async function loadCVEIntel(): Promise<CVERecord[]> {
  try {
    const content = await fs.readFile(CVE_INTEL_PATH, "utf-8");
    const data = JSON.parse(content);
    return data.records || [];
  } catch {
    return [];
  }
}

async function loadCustomCVE(): Promise<CVERecord[]> {
  try {
    const content = await fs.readFile(CUSTOM_CVE_PATH, "utf-8");
    return JSON.parse(content);
  } catch {
    return [];
  }
}

async function saveCustomCVE(records: CVERecord[]) {
  const dir = path.dirname(CUSTOM_CVE_PATH);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(CUSTOM_CVE_PATH, JSON.stringify(records, null, 2), "utf-8");
}

/**
 * GET /api/cve - 获取所有 CVE 记录
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get("page") || "1");
    const pageSize = parseInt(searchParams.get("pageSize") || "50");
    const search = searchParams.get("search") || "";
    const severity = searchParams.get("severity") || "";
    const family = searchParams.get("family") || "";

    // 加载所有 CVE
    const intelRecords = await loadCVEIntel();
    const customRecords = await loadCustomCVE();

    // 合并并去重
    const allRecords = [...customRecords, ...intelRecords];
    const seen = new Set<string>();
    const uniqueRecords = allRecords.filter((r) => {
      if (seen.has(r.cve_id)) return false;
      seen.add(r.cve_id);
      return true;
    });

    // 过滤
    let filtered = uniqueRecords;
    if (search) {
      const searchLower = search.toLowerCase();
      filtered = filtered.filter(
        (r) =>
          r.cve_id.toLowerCase().includes(searchLower) ||
          r.description.toLowerCase().includes(searchLower) ||
          r.product_family.toLowerCase().includes(searchLower)
      );
    }
    if (severity) {
      filtered = filtered.filter(
        (r) => r.severity.toLowerCase() === severity.toLowerCase()
      );
    }
    if (family) {
      filtered = filtered.filter(
        (r) => r.product_family.toLowerCase() === family.toLowerCase()
      );
    }

    // 分页
    const total = filtered.length;
    const start = (page - 1) * pageSize;
    const end = start + pageSize;
    const records = filtered.slice(start, end);

    // 统计信息
    const severityCounts: Record<string, number> = {};
    const familyCounts: Record<string, number> = {};
    uniqueRecords.forEach((r) => {
      severityCounts[r.severity] = (severityCounts[r.severity] || 0) + 1;
      familyCounts[r.product_family] = (familyCounts[r.product_family] || 0) + 1;
    });

    return NextResponse.json({
      success: true,
      records,
      pagination: {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
      },
      stats: {
        total: uniqueRecords.length,
        severityCounts,
        familyCounts,
        pocAvailable: uniqueRecords.filter((r) => r.poc_available).length,
      },
    });
  } catch (error) {
    console.error("Failed to get CVE records:", error);
    return NextResponse.json(
      { success: false, error: "获取 CVE 列表失败" },
      { status: 500 }
    );
  }
}

/**
 * POST /api/cve - CVE 操作
 */
export async function POST(request: NextRequest) {
  try {
    const { action, cve } = await request.json();

    if (action === "add") {
      // 添加自定义 CVE
      const customRecords = await loadCustomCVE();

      // 检查是否已存在
      if (customRecords.some((r) => r.cve_id === cve.cve_id)) {
        return NextResponse.json(
          { success: false, error: "CVE ID 已存在" },
          { status: 400 }
        );
      }

      const newCVE: CVERecord = {
        cve_id: cve.cve_id.toUpperCase(),
        source: "custom",
        description: cve.description || "",
        severity: cve.severity || "unknown",
        cvss: cve.cvss,
        product_family: cve.product_family || "unknown",
        protocols: cve.protocols || ["unknown"],
        prerequisites: cve.prerequisites || ["unknown"],
        poc_available: cve.poc_available || false,
        references: cve.references || [],
        updated_at: new Date().toISOString(),
      };

      customRecords.push(newCVE);
      await saveCustomCVE(customRecords);

      return NextResponse.json({
        success: true,
        message: "CVE 添加成功",
        cve: newCVE,
      });
    }

    if (action === "update") {
      // 更新自定义 CVE
      const customRecords = await loadCustomCVE();
      const index = customRecords.findIndex((r) => r.cve_id === cve.cve_id);

      if (index === -1) {
        return NextResponse.json(
          { success: false, error: "CVE 不存在或非自定义 CVE" },
          { status: 404 }
        );
      }

      customRecords[index] = {
        ...customRecords[index],
        ...cve,
        updated_at: new Date().toISOString(),
      };
      await saveCustomCVE(customRecords);

      return NextResponse.json({ success: true, message: "CVE 更新成功" });
    }

    if (action === "delete") {
      // 删除自定义 CVE
      const customRecords = await loadCustomCVE();
      const filtered = customRecords.filter((r) => r.cve_id !== cve.cve_id);

      if (filtered.length === customRecords.length) {
        return NextResponse.json(
          { success: false, error: "CVE 不存在或非自定义 CVE" },
          { status: 404 }
        );
      }

      await saveCustomCVE(filtered);
      return NextResponse.json({ success: true, message: "CVE 删除成功" });
    }

    return NextResponse.json(
      { success: false, error: "未知操作" },
      { status: 400 }
    );
  } catch (error) {
    console.error("CVE operation failed:", error);
    return NextResponse.json(
      { success: false, error: "操作失败" },
      { status: 500 }
    );
  }
}
