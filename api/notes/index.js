import { collection } from '../../lib/notes.mjs';
import { getDeps } from '../../lib/server.mjs';

export default (req, res) => collection(req, res, getDeps);
