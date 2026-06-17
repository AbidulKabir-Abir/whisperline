import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { query, queryOne } from '../config/database';
import { requireAuth, AuthRequest } from '../middleware/auth';
import { putEncryptedFile, presignGetUrl, deleteFile } from '../config/minio';

const router = Router();

// ── Upload encrypted file ─────────────────────────────────────────────────
// Client must encrypt the file before sending; server stores opaque blob
router.post('/upload', requireAuth, async (req: AuthRequest, res) => {
  try {
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLength > 50 * 1024 * 1024) {
      res.status(413).json({ error: 'file_too_large' }); return;
    }

    const fileId = uuidv4();
    const minioKey = `files/${req.userId}/${fileId}`;

    // Stream encrypted body directly to MinIO
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      if (chunks.reduce((a, c) => a + c.length, 0) > 50 * 1024 * 1024) {
        res.status(413).json({ error: 'file_too_large' }); return;
      }
    }
    const data = Buffer.concat(chunks);

    await putEncryptedFile(minioKey, data, {
      'x-uploader': req.userId!,
    });

    // Store reference — encrypted metadata comes from client
    const encryptedMeta = req.headers['x-encrypted-meta'] as string || '';
    const [fileRef] = await query<{ id: string }>(
      `INSERT INTO file_refs (uploader_id, minio_key, encrypted_meta, size_bytes)
       VALUES ($1, $2, decode($3,'base64'), $4)
       RETURNING id`,
      [req.userId, minioKey, encryptedMeta, data.length]
    );

    res.status(201).json({ fileRefId: fileRef.id });
  } catch (err) {
    console.error('[Files] Upload error:', err);
    res.status(500).json({ error: 'upload_failed' });
  }
});

// ── Download encrypted file ───────────────────────────────────────────────
router.get('/download/:fileRefId', requireAuth, async (req: AuthRequest, res) => {
  try {
    const file = await queryOne<{
      minio_key: string; uploader_id: string; encrypted_meta: string;
    }>(
      'SELECT minio_key, uploader_id, encode(encrypted_meta,\'base64\') as encrypted_meta FROM file_refs WHERE id = $1',
      [req.params.fileRefId]
    );

    if (!file) { res.status(404).json({ error: 'not_found' }); return; }

    // Generate short-lived presigned URL
    const url = await presignGetUrl(file.minio_key, 300);
    res.json({
      url,
      encryptedMeta: file.encrypted_meta,
      ttl: 300,
    });
  } catch (err) {
    res.status(500).json({ error: 'download_failed' });
  }
});

export default router;
