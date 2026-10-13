// An authorized host can install a reviewer using setJevReviewer.
// No endpoint or credential is assumed; offline replay uses alert fallback.
let reviewer;
export function setJevReviewer(next) { reviewer = typeof next === 'function' ? next : undefined; }
export async function reviewAmbiguous({ pattern, level, count }) {
  if (!reviewer) return null;
  let timer;
  try {
    const response = await Promise.race([
      Promise.resolve().then(() => reviewer({ pattern, level, count })),
      new Promise(resolve => { timer = setTimeout(() => resolve(null), 1000); }),
    ]);
    const confidence = response?.confidence;
    return typeof confidence === 'number' && Number.isFinite(confidence) && confidence >= 0 && confidence <= 1
      ? confidence : null;
  } catch { return null; }
  finally { clearTimeout(timer); }
}
export function decision(confidence, reason) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
export async function ambiguous(pattern, level, count) {
  const confidence = await reviewAmbiguous({ pattern, level, count });
  return decision(confidence ?? 0.5, `${pattern}: ${confidence === null ? 'Jev unavailable; alert fallback' : 'Jev confidence'}`);
}
