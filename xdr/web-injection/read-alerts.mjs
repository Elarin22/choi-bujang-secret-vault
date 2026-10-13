import { projectAlert, readFixture } from '../read-alerts.mjs';
export async function readAlerts(path = new URL('../fixtures/web-injection.json', import.meta.url)) {
  return (await readFixture(path, 'web-injection')).alerts.map(projectAlert);
}
