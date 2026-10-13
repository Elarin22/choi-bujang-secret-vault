import { noticeItem } from '../../lib/notices.mjs';
import { getDeps } from '../../lib/server.mjs';

export default (req, res) => noticeItem(req, res, getDeps);
