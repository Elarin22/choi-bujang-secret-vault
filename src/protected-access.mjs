// Server-only integration seam. No header, cookie or body grants device approval.
// The official adapter must verify the current user/device AND this exact request.
// Until that adapter is supplied, protected APIs fail closed before storage access.
export async function verifyApprovedRequest() {
  throw new Error('official_adapter_not_provided');
}

export async function requireApprovedRequest(verifier, req, user, res) {
  try {
    if (await verifier(req, user) === true) return true;
    res.status(403).json({ error: 'device_approval_required' });
  } catch {
    res.status(503).json({ error: 'device_verification_unavailable' });
  }
  return false;
}
