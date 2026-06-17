import { Router } from 'express';
import crypto from 'crypto';
import { requireAuth, AuthRequest } from '../middleware/auth';

const router = Router();

// ── Generate TURN credentials (time-limited HMAC) ────────────────────────
router.get('/turn-credentials', requireAuth, async (req: AuthRequest, res) => {
  try {
    const ttl = 3600; // 1 hour
    const timestamp = Math.floor(Date.now() / 1000) + ttl;
    const username = `${timestamp}:${req.userId}`;
    const secret = process.env.TURN_SECRET!;

    const credential = crypto
      .createHmac('sha1', secret)
      .update(username)
      .digest('base64');

    res.json({
      urls: [
        `stun:${process.env.STUN_HOST || 'stun.l.google.com'}:19302`,
        `turn:${process.env.TURN_HOST || 'localhost'}:3478`,
      ],
      username,
      credential,
      ttl,
    });
  } catch (err) {
    res.status(500).json({ error: 'credentials_failed' });
  }
});

export default router;
