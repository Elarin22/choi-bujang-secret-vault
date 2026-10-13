import { projectAlert, readFixture } from '../read-alerts.mjs';
export async function readAlerts(path = new URL('../fixtures/brute-force.json', import.meta.url)) {
  return (await readFixture(path, 'brute-force')).alerts.map(projectAlert);
}
