import { restore } from '../../lib/restore.mjs';
import { getDeps } from '../../lib/server.mjs';

export default (req, res) => restore(req, res, getDeps);
