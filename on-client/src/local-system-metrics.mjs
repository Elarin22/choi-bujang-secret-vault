import { cpus, freemem, totalmem } from 'node:os';
import { statfs } from 'node:fs/promises';
import { parse } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const CPU_SAMPLE_INTERVAL_MS = 1000;
const execFileAsync = promisify(execFile);
const windowsStatusScript = fileURLToPath(new URL('../tools/read-local-windows-status.ps1', import.meta.url));

function timestamp() {
  return new Date().toISOString();
}

function unknown(reason, measuredAt = timestamp()) {
  return { status: 'unknown', reason, measuredAt };
}

function cpuTimes() {
  const rows = cpus();
  if (!rows.length) return null;
  return rows.reduce((total, cpu) => {
    for (const [name, value] of Object.entries(cpu.times)) total[name] = (total[name] || 0) + value;
    return total;
  }, {});
}

async function readCpu() {
  try {
    const before = cpuTimes();
    if (!before || !Number.isFinite(before.idle)) return unknown('운영체제가 CPU 사용량을 제공하지 않습니다.');
    await new Promise((resolve) => setTimeout(resolve, CPU_SAMPLE_INTERVAL_MS));
    const after = cpuTimes();
    const measuredAt = timestamp();
    if (!after || !Number.isFinite(after.idle)) return unknown('운영체제가 CPU 사용량을 제공하지 않습니다.', measuredAt);
    const totalDelta = Object.keys(after).reduce((sum, name) => sum + (after[name] - before[name]), 0);
    const idleDelta = after.idle - before.idle;
    if (!(totalDelta > 0) || idleDelta < 0 || idleDelta > totalDelta) return unknown('CPU 표본을 계산할 수 없습니다.', measuredAt);
    return {
      status: 'ok',
      percent: Math.max(0, Math.min(100, ((totalDelta - idleDelta) / totalDelta) * 100)),
      unit: '%',
      sampleIntervalMs: CPU_SAMPLE_INTERVAL_MS,
      measuredAt,
    };
  } catch {
    return unknown('CPU 사용량을 읽지 못했습니다.');
  }
}

function readMemory() {
  const measuredAt = timestamp();
  try {
    const totalBytes = totalmem();
    const availableBytes = freemem();
    if (!Number.isSafeInteger(totalBytes) || totalBytes <= 0 || !Number.isSafeInteger(availableBytes) || availableBytes < 0 || availableBytes > totalBytes) {
      return unknown('운영체제가 메모리 값을 확인할 수 있는 형식으로 제공하지 않았습니다.', measuredAt);
    }
    const usedBytes = totalBytes - availableBytes;
    return {
      status: 'ok',
      usedBytes,
      availableBytes,
      totalBytes,
      usedPercent: (usedBytes / totalBytes) * 100,
      unit: 'bytes',
      measuredAt,
    };
  } catch {
    return unknown('물리 메모리 정보를 읽지 못했습니다.', measuredAt);
  }
}

function systemVolume() {
  if (process.platform === 'win32') {
    const configured = process.env.SystemDrive;
    if (typeof configured === 'string' && /^[A-Za-z]:$/.test(configured)) return { root: `${configured.toUpperCase()}\\`, label: configured.toUpperCase() };
  }
  const root = parse(process.execPath).root || parse(process.cwd()).root;
  if (!root) return null;
  return { root, label: process.platform === 'win32' ? root.slice(0, 2).toUpperCase() : root };
}

async function readDisk() {
  const measuredAt = timestamp();
  const volume = systemVolume();
  if (!volume) return unknown('시스템 드라이브를 확인할 수 없습니다.', measuredAt);
  try {
    const stats = await statfs(volume.root);
    const availableBytes = stats.bavail * stats.bsize;
    const totalBytes = stats.blocks * stats.bsize;
    if (!Number.isSafeInteger(availableBytes) || !Number.isSafeInteger(totalBytes) || totalBytes <= 0 || availableBytes < 0 || availableBytes > totalBytes) {
      return unknown(`${volume.label}의 디스크 공간을 확인할 수 있는 형식으로 읽지 못했습니다.`, measuredAt);
    }
    return { status: 'ok', volume: volume.label, availableBytes, totalBytes, unit: 'bytes', measuredAt };
  } catch (error) {
    const reason = error?.code === 'EACCES'
      ? `${volume.label}의 디스크 공간을 읽을 권한이 없습니다.`
      : error?.code === 'ENOENT' || error?.code === 'ENODEV'
        ? `시스템 드라이브 ${volume.label}을(를) 찾을 수 없습니다.`
        : `${volume.label}의 디스크 공간을 읽지 못했습니다.`;
    return unknown(reason, measuredAt);
  }
}

function unknownWindowsStatus(reasonCode, checkedAt = timestamp()) {
  return {
    network: { status: 'unknown', checkedAt, reasonCode },
    firewall: { status: 'unknown', checkedAt, reasonCode },
    events: {
      windowHours: 24,
      windowStart: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      windowEnd: checkedAt,
      system: { status: 'unknown', checkedAt, reasonCode },
      application: { status: 'unknown', checkedAt, reasonCode },
    },
  };
}

async function readWindowsStatus() {
  const checkedAt = timestamp();
  if (process.platform !== 'win32') return unknownWindowsStatus('WINDOWS_ONLY', checkedAt);
  try {
    const { stdout } = await execFileAsync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', windowsStatusScript,
    ], { encoding: 'utf8', timeout: 6000, windowsHide: true, maxBuffer: 512 * 1024 });
    const encoded = stdout.trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) return unknownWindowsStatus('WINDOWS_STATUS_INVALID', timestamp());
    const result = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
    if (!result || typeof result !== 'object' || !['network', 'firewall', 'events'].every((key) => Object.hasOwn(result, key))) {
      return unknownWindowsStatus('WINDOWS_STATUS_INVALID', timestamp());
    }
    return result;
  } catch (error) {
    const reasonCode = error?.code === 'ETIMEDOUT' || error?.killed ? 'WINDOWS_STATUS_TIMEOUT'
      : error?.code === 'ENOENT' ? 'POWERSHELL_UNAVAILABLE' : 'WINDOWS_STATUS_QUERY_FAILED';
    return unknownWindowsStatus(reasonCode, timestamp());
  }
}

export async function readLocalSystemMetrics() {
  const [cpu, memory, disk, windows] = await Promise.all([readCpu(), Promise.resolve(readMemory()), readDisk(), readWindowsStatus()]);
  return { cpu, memory, disk, ...windows };
}
