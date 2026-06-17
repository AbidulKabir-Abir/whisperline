import { Router } from 'express';
import { z } from 'zod';
import { query, queryOne } from '../config/database';
import { requireAuth, AuthRequest } from '../middleware/auth';

const router = Router();

// ── Get conversation messages (encrypted ciphertexts only) ───────────────
router.get('/conversation/:conversationId', requireAuth, async (req: AuthRequest, res) => {
  try {
    const { conversationId } = req.params;
    const limit = Math.min(parseInt(req.query.limit as string || '50'), 100);
    const before = req.query.before as string | undefined;

    // Verify membership
    const member = await queryOne(
      `SELECT 1 FROM conversation_members
       WHERE conversation_id = $1 AND user_id = $2`,
      [conversationId, req.userId]
    );
    if (!member) { res.status(403).json({ error: 'forbidden' }); return; }

    const rows = await query<{
      id: string; sender_id: string; encrypted_for: Record<string, string>;
      dh_pub: string; prev_chain_len: number; msg_index: number;
      delivered_at: string; read_at: string; created_at: string;
    }>(
      `SELECT id, sender_id, encrypted_for,
              encode(dh_pub,'base64') as dh_pub,
              prev_chain_len, msg_index,
              delivered_at, read_at, created_at
       FROM messages
       WHERE conversation_id = $1
         AND deleted_at IS NULL
         ${before ? 'AND created_at < $3' : ''}
       ORDER BY created_at DESC
       LIMIT $2`,
      before
        ? [conversationId, limit, before]
        : [conversationId, limit]
    );

    // Return only the ciphertext for this recipient
    const userId = req.userId!;
    const messages = rows.map(row => ({
      id: row.id,
      senderId: row.sender_id,
      // Server returns ciphertext — only the recipient can decrypt this
      ciphertext: row.encrypted_for[userId] ?? null,
      dhPub: row.dh_pub,
      prevChainLen: row.prev_chain_len,
      msgIndex: row.msg_index,
      deliveredAt: row.delivered_at,
      readAt: row.read_at,
      createdAt: row.created_at,
    }));

    res.json({ messages: messages.reverse() });
  } catch (err) {
    res.status(500).json({ error: 'fetch_failed' });
  }
});

// ── Create/send message (server stores encrypted blob, never sees plaintext) ─
const SendMessageSchema = z.object({
  conversationId: z.string().uuid(),
  // Map of userId -> base64(nonce + ciphertext) — one entry per recipient
  encryptedFor: z.record(z.string(), z.string()),
  dhPub: z.string().optional(),       // Ratchet public key for this step
  prevChainLen: z.number().optional(),
  msgIndex: z.number().optional(),
});

router.post('/send', requireAuth, async (req: AuthRequest, res) => {
  try {
    const body = SendMessageSchema.parse(req.body);

    // Verify sender is member
    const member = await queryOne(
      `SELECT 1 FROM conversation_members
       WHERE conversation_id = $1 AND user_id = $2`,
      [body.conversationId, req.userId]
    );
    if (!member) { res.status(403).json({ error: 'forbidden' }); return; }

    const [msg] = await query<{ id: string; created_at: string }>(
      `INSERT INTO messages
         (conversation_id, sender_id, encrypted_for, dh_pub, prev_chain_len, msg_index)
       VALUES ($1, $2, $3::jsonb, decode($4,'base64'), $5, $6)
       RETURNING id, created_at`,
      [
        body.conversationId,
        req.userId,
        JSON.stringify(body.encryptedFor),
        body.dhPub ?? null,
        body.prevChainLen ?? null,
        body.msgIndex ?? null,
      ]
    );

    res.status(201).json({ messageId: msg.id, createdAt: msg.created_at });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'validation_error' }); return;
    }
    res.status(500).json({ error: 'send_failed' });
  }
});

// ── Create conversation ───────────────────────────────────────────────────
router.post('/conversations', requireAuth, async (req: AuthRequest, res) => {
  try {
    const { recipientId } = req.body as { recipientId: string };

    // Check existing conversation between these two users
    const existing = await queryOne<{ id: string }>(
      `SELECT c.id FROM conversations c
       JOIN conversation_members m1 ON m1.conversation_id = c.id AND m1.user_id = $1
       JOIN conversation_members m2 ON m2.conversation_id = c.id AND m2.user_id = $2`,
      [req.userId, recipientId]
    );

    if (existing) { res.json({ conversationId: existing.id, existing: true }); return; }

    const [conv] = await query<{ id: string }>(
      'INSERT INTO conversations DEFAULT VALUES RETURNING id'
    );

    await query(
      `INSERT INTO conversation_members (conversation_id, user_id)
       VALUES ($1, $2), ($1, $3)`,
      [conv.id, req.userId, recipientId]
    );

    res.status(201).json({ conversationId: conv.id, existing: false });
  } catch (err) {
    res.status(500).json({ error: 'create_failed' });
  }
});

// ── List conversations ────────────────────────────────────────────────────
router.get('/conversations', requireAuth, async (req: AuthRequest, res) => {
  try {
    const rows = await query<{
      id: string; created_at: string;
      other_user_id: string; other_user_tag: string; other_display_name: string;
    }>(
      `SELECT c.id, c.created_at,
              u.id as other_user_id,
              u.user_tag as other_user_tag,
              u.display_name as other_display_name
       FROM conversations c
       JOIN conversation_members cm ON cm.conversation_id = c.id AND cm.user_id = $1
       JOIN conversation_members cm2 ON cm2.conversation_id = c.id AND cm2.user_id != $1
       JOIN users u ON u.id = cm2.user_id
       ORDER BY c.created_at DESC`,
      [req.userId]
    );
    res.json({ conversations: rows });
  } catch (err) {
    res.status(500).json({ error: 'fetch_failed' });
  }
});

// ── Mark delivered ────────────────────────────────────────────────────────
router.post('/delivered/:messageId', requireAuth, async (req: AuthRequest, res) => {
  try {
    await query(
      `UPDATE messages SET delivered_at = NOW()
       WHERE id = $1 AND delivered_at IS NULL`,
      [req.params.messageId]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'update_failed' });
  }
});

export default router;
