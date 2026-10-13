import { myCollection } from '../../lib/notes.mjs';
import { getDeps } from '../../lib/server.mjs';

export default (req, res) => myCollection(req, res, getDeps);