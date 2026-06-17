import { Router } from 'express';
import { z } from 'zod';
import { query, queryOne } from '../config/database';
import { requireAuth, AuthRequest } from '../middleware/auth';
import { cacheKeyBundle, getCachedKeyBundle } from '../config/redis';

const router = Router();

// ── Get key bundle for X3DH (anyone can fetch another user's public keys) ─
router.get('/bundle/:userTag', requireAuth, async (req: AuthRequest, res) => {
  try {
    const { userTag } = req.params;

    // Try cache first
    const cached = await getCachedKeyBundle(userTag);
    if (cached) { res.json(cached); return; }

    const user = await queryOne<{
      id: string; user_tag: string; display_name: string;
      ik_pub: Buffer; spk_pub: Buffer; spk_sig: Buffer; spk_id: number;
    }>(
      `SELECT id, user_tag, display_name,
              encode(ik_pub,'base64') as ik_pub,
              encode(spk_pub,'base64') as spk_pub,
              encode(spk_sig,'base64') as spk_sig,
              spk_id
       FROM users WHERE user_tag = $1`,
      [userTag]
    );

    if (!user) { res.status(404).json({ error: 'user_not_found' }); return; }

    // Fetch and consume one one-time prekey
    const otpk = await queryOne<{ id: string; key_id: number; pub_key: Buffer }>(
      `UPDATE one_time_prekeys SET used = true
       WHERE id = (
         SELECT id FROM one_time_prekeys
         WHERE user_id = $1 AND used = false
         ORDER BY created_at ASC
         LIMIT 1
       )
       RETURNING id, key_id, encode(pub_key,'base64') as pub_key`,
      [user.id]
    );

    // Update OTPKs count
    await query(
      'UPDATE users SET otpk_count = otpk_count - 1 WHERE id = $1 AND otpk_count > 0',
      [user.id]
    );

    const bundle = {
      userId: user.id,
      userTag: user.user_tag,
      displayName: user.display_name,
      identityKey: user.ik_pub,        // IK_pub (Ed25519)
      signedPrekey: {
        keyId: user.spk_id,
        publicKey: user.spk_pub,       // SPK_pub (Curve25519)
        signature: user.spk_sig,       // Sign(IK_priv, SPK_pub)
      },
      oneTimePrekey: otpk ? {
        keyId: otpk.key_id,
        publicKey: otpk.pub_key,
      } : null,
    };

    await cacheKeyBundle(userTag, bundle);
    res.json(bundle);
  } catch (err) {
    console.error('[Keys] Bundle error:', err);
    res.status(500).json({ error: 'fetch_failed' });
  }
});

// ── Upload new one-time prekeys (client replenishes pool) ────────────────
const OTPKSchema = z.object({
  oneTimePrekeys: z.array(z.object({
    keyId: z.number(),
    pubKey: z.string(),
  })).min(1).max(100),
});

router.post('/prekeys', requireAuth, async (req: AuthRequest, res) => {
  try {
    const { oneTimePrekeys } = OTPKSchema.parse(req.body);
    for (const otpk of oneTimePrekeys) {
      await query(
        `INSERT INTO one_time_prekeys (user_id, key_id, pub_key)
         VALUES ($1, $2, decode($3,'base64'))
         ON CONFLICT (user_id, key_id) DO NOTHING`,
        [req.userId, otpk.keyId, otpk.pubKey]
      );
    }
    await query(
      'UPDATE users SET otpk_count = otpk_count + $2 WHERE id = $1',
      [req.userId, oneTimePrekeys.length]
    );
    res.json({ uploaded: oneTimePrekeys.length });
  } catch (err) {
    res.status(500).json({ error: 'upload_failed' });
  }
});

// ── Rotate signed prekey ──────────────────────────────────────────────────
const SPKSchema = z.object({
  keyId: z.number(),
  publicKey: z.string(),
  signature: z.string(),
});

router.put('/signed-prekey', requireAuth, async (req: AuthRequest, res) => {
  try {
    const { keyId, publicKey, signature } = SPKSchema.parse(req.body);
    await query(
      `UPDATE users SET
        spk_pub = decode($2,'base64'),
        spk_sig = decode($3,'base64'),
        spk_id  = $4
       WHERE id = $1`,
      [req.userId, publicKey, signature, keyId]
    );
    res.json({ rotated: true });
  } catch (err) {
    res.status(500).json({ error: 'rotation_failed' });
  }
});

export default router;
