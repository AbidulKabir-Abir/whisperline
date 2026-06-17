import { Router } from 'express';
import { rateLimit } from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { query, queryOne } from '../config/database';
import { signToken } from '../middleware/auth';
import { generateUserTag } from '../services/userTag';

const router = Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
});

// ── Register (standard — no email/phone, keys only) ──────────────────────
const RegisterSchema = z.object({
  displayName: z.string().min(1).max(64).optional(),
  // Public key bundle (client-generated, never private keys)
  ikPub: z.string(),     // base64 Ed25519 identity key
  spkPub: z.string(),    // base64 Curve25519 signed prekey
  spkSig: z.string(),    // base64 signature of spkPub
  oneTimePrekeys: z.array(z.object({
    keyId: z.number(),
    pubKey: z.string(),
  })).min(10).max(100),
});

router.post('/register', authLimiter, async (req, res) => {
  try {
    const body = RegisterSchema.parse(req.body);
    const userTag = await generateUserTag();

    const [user] = await query<{ id: string; user_tag: string }>(
      `INSERT INTO users (user_tag, display_name, ik_pub, spk_pub, spk_sig, otpk_count)
       VALUES ($1, $2, decode($3,'base64'), decode($4,'base64'), decode($5,'base64'), $6)
       RETURNING id, user_tag`,
      [
        userTag,
        body.displayName ?? null,
        body.ikPub,
        body.spkPub,
        body.spkSig,
        body.oneTimePrekeys.length,
      ]
    );

    // Insert one-time prekeys
    for (const otpk of body.oneTimePrekeys) {
      await query(
        `INSERT INTO one_time_prekeys (user_id, key_id, pub_key)
         VALUES ($1, $2, decode($3,'base64'))`,
        [user.id, otpk.keyId, otpk.pubKey]
      );
    }

    const token = signToken(user.id, user.user_tag);
    res.status(201).json({ userId: user.id, userTag: user.user_tag, token });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'validation_error', details: err.errors });
      return;
    }
    console.error('[Auth] Register error:', err);
    res.status(500).json({ error: 'registration_failed' });
  }
});

// ── WebAuthn: Start registration ──────────────────────────────────────────
router.post('/webauthn/register/start', authLimiter, async (req, res) => {
  try {
    const { userId } = req.body as { userId: string };
    const user = await queryOne<{ id: string; user_tag: string; display_name: string }>(
      'SELECT id, user_tag, display_name FROM users WHERE id = $1',
      [userId]
    );
    if (!user) { res.status(404).json({ error: 'user_not_found' }); return; }

    const options = await generateRegistrationOptions({
      rpName: 'WhisperLine',
      rpID: process.env.RP_ID || 'localhost',
      userID: Buffer.from(user.id),
      userName: user.user_tag,
      userDisplayName: user.display_name || user.user_tag,
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'required',
      },
    });

    // Store challenge in DB temporarily
    await query(
      `UPDATE users SET webauthn_cred = jsonb_set(COALESCE(webauthn_cred, '{}'), '{challenge}', $2)
       WHERE id = $1`,
      [userId, JSON.stringify(options.challenge)]
    );

    res.json(options);
  } catch (err) {
    res.status(500).json({ error: 'webauthn_start_failed' });
  }
});

// ── WebAuthn: Complete registration ──────────────────────────────────────
router.post('/webauthn/register/finish', authLimiter, async (req, res) => {
  try {
    const { userId, credential } = req.body as { userId: string; credential: unknown };
    const user = await queryOne<{ id: string; user_tag: string; webauthn_cred: { challenge: string } }>(
      'SELECT id, user_tag, webauthn_cred FROM users WHERE id = $1',
      [userId]
    );
    if (!user || !user.webauthn_cred?.challenge) {
      res.status(400).json({ error: 'invalid_state' }); return;
    }

    const verification = await verifyRegistrationResponse({
      response: credential as Parameters<typeof verifyRegistrationResponse>[0]['response'],
      expectedChallenge: user.webauthn_cred.challenge,
      expectedOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173',
      expectedRPID: process.env.RP_ID || 'localhost',
    });

    if (!verification.verified || !verification.registrationInfo) {
      res.status(400).json({ error: 'verification_failed' }); return;
    }

    await query(
      `UPDATE users SET
        webauthn_id = decode($2, 'base64'),
        webauthn_cred = $3::jsonb
       WHERE id = $1`,
      [
        userId,
        Buffer.from(verification.registrationInfo.credential.id).toString('base64'),
        JSON.stringify(verification.registrationInfo.credential),
      ]
    );

    res.json({ verified: true });
  } catch (err) {
    res.status(500).json({ error: 'webauthn_finish_failed' });
  }
});

// ── WebAuthn: Start authentication ───────────────────────────────────────
router.post('/webauthn/auth/start', authLimiter, async (req, res) => {
  try {
    const { userTag } = req.body as { userTag: string };
    const user = await queryOne<{ id: string; webauthn_cred: { id: string } }>(
      'SELECT id, webauthn_cred FROM users WHERE user_tag = $1',
      [userTag]
    );
    if (!user?.webauthn_cred) {
      res.status(404).json({ error: 'user_not_found' }); return;
    }

    const options = await generateAuthenticationOptions({
      rpID: process.env.RP_ID || 'localhost',
      userVerification: 'required',
      allowCredentials: [{ id: user.webauthn_cred.id, type: 'public-key' }],
    });

    await query(
      `UPDATE users SET webauthn_cred = jsonb_set(webauthn_cred, '{authChallenge}', $2)
       WHERE id = $1`,
      [user.id, JSON.stringify(options.challenge)]
    );

    res.json({ options, userId: user.id });
  } catch (err) {
    res.status(500).json({ error: 'webauthn_auth_start_failed' });
  }
});

// ── WebAuthn: Complete authentication ────────────────────────────────────
router.post('/webauthn/auth/finish', authLimiter, async (req, res) => {
  try {
    const { userId, credential } = req.body as { userId: string; credential: unknown };
    const user = await queryOne<{
      id: string; user_tag: string;
      webauthn_cred: { id: string; publicKey: string; counter: number; authChallenge: string };
    }>(
      'SELECT id, user_tag, webauthn_cred FROM users WHERE id = $1',
      [userId]
    );
    if (!user?.webauthn_cred?.authChallenge) {
      res.status(400).json({ error: 'invalid_state' }); return;
    }

    const verification = await verifyAuthenticationResponse({
      response: credential as Parameters<typeof verifyAuthenticationResponse>[0]['response'],
      expectedChallenge: user.webauthn_cred.authChallenge,
      expectedOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173',
      expectedRPID: process.env.RP_ID || 'localhost',
      credential: {
        id: user.webauthn_cred.id,
        publicKey: Buffer.from(user.webauthn_cred.publicKey, 'base64'),
        counter: user.webauthn_cred.counter || 0,
      },
    });

    if (!verification.verified) {
      res.status(401).json({ error: 'auth_failed' }); return;
    }

    // Update counter to prevent replay attacks
    await query(
      `UPDATE users SET webauthn_cred = jsonb_set(webauthn_cred, '{counter}', $2::jsonb)
       WHERE id = $1`,
      [userId, JSON.stringify(verification.authenticationInfo.newCounter)]
    );

    await query('UPDATE users SET last_seen = NOW() WHERE id = $1', [userId]);

    const token = signToken(user.id, user.user_tag);
    res.json({ token, userId: user.id, userTag: user.user_tag });
  } catch (err) {
    res.status(500).json({ error: 'webauthn_auth_finish_failed' });
  }
});

export default router;
