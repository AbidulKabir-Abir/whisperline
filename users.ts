import { Router } from 'express';
import { z } from 'zod';
import { query, queryOne } from '../config/database';
import { requireAuth, AuthRequest } from '../middleware/auth';

const router = Router();

// ── Get own profile ───────────────────────────────────────────────────────
router.get('/me', requireAuth, async (req: AuthRequest, res) => {
  const user = await queryOne<{
    id: string; user_tag: string; display_name: string;
    otpk_count: number; last_seen: string; created_at: string;
  }>(
    'SELECT id, user_tag, display_name, otpk_count, last_seen, created_at FROM users WHERE id = $1',
    [req.userId]
  );
  if (!user) { res.status(404).json({ error: 'not_found' }); return; }
  res.json(user);
});

// ── Update display name ───────────────────────────────────────────────────
router.patch('/me', requireAuth, async (req: AuthRequest, res) => {
  const { displayName } = z.object({
    displayName: z.string().min(1).max(64),
  }).parse(req.body);

  await query(
    'UPDATE users SET display_name = $2 WHERE id = $1',
    [req.userId, displayName]
  );
  res.json({ updated: true });
});

// ── Look up user by tag ───────────────────────────────────────────────────
router.get('/lookup/:userTag', requireAuth, async (_req: AuthRequest, res) => {
  const { userTag } = _req.params;
  const user = await queryOne<{
    id: string; user_tag: string; display_name: string; last_seen: string;
  }>(
    'SELECT id, user_tag, display_name, last_seen FROM users WHERE user_tag = $1',
    [userTag]
  );
  if (!user) { res.status(404).json({ error: 'not_found' }); return; }
  res.json(user);
});

export default router;
