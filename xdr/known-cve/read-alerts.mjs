import { projectAlert, readFixture } from '../read-alerts.mjs';
export async function readAlerts(path = new URL('../fixtures/known-cve.json', import.meta.url)) {
  return (await readFixture(path, 'known-cve')).alerts.map(projectAlert);
}
