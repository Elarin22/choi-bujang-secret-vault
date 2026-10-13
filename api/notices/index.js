import { noticeCollection } from '../../lib/notices.mjs';
import { getDeps } from '../../lib/server.mjs';

export default (req, res) => noticeCollection(req, res, getDeps);
