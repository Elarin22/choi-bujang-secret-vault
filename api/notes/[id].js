import { item } from '../../lib/notes.mjs';
import { getDeps } from '../../lib/server.mjs';

export default (req, res) => item(req, res, getDeps);
