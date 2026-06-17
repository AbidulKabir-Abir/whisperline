import * as Minio from 'minio';

let client: Minio.Client;
const BUCKET = process.env.MINIO_BUCKET || 'whisperline-files';

export async function initMinio(): Promise<void> {
  client = new Minio.Client({
    endPoint: process.env.MINIO_ENDPOINT || 'minio',
    port: parseInt(process.env.MINIO_PORT || '9000', 10),
    useSSL: process.env.MINIO_USE_SSL === 'true',
    accessKey: process.env.MINIO_ACCESS_KEY!,
    secretKey: process.env.MINIO_SECRET_KEY!,
  });

  const exists = await client.bucketExists(BUCKET);
  if (!exists) {
    await client.makeBucket(BUCKET, 'us-east-1');
    // Block public access
    await client.setBucketPolicy(BUCKET, JSON.stringify({
      Version: '2012-10-17',
      Statement: [{
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: `arn:aws:s3:::${BUCKET}/*`,
        Condition: {
          StringNotEquals: {
            'aws:PrincipalAccount': [process.env.MINIO_ACCESS_KEY!]
          }
        }
      }]
    }));
  }

  console.log('[MinIO] Connected, bucket:', BUCKET);
}

export function getMinio(): Minio.Client {
  if (!client) throw new Error('MinIO not initialized');
  return client;
}

export async function putEncryptedFile(
  key: string,
  data: Buffer,
  metadata: Record<string, string>
): Promise<void> {
  await getMinio().putObject(BUCKET, key, data, data.length, {
    'Content-Type': 'application/octet-stream',
    'X-Amz-Meta-Encrypted': 'true',
    ...metadata,
  });
}

export async function getEncryptedFile(key: string): Promise<Buffer> {
  const stream = await getMinio().getObject(BUCKET, key);
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

export async function deleteFile(key: string): Promise<void> {
  await getMinio().removeObject(BUCKET, key);
}

export async function presignGetUrl(key: string, ttlSeconds = 300): Promise<string> {
  return getMinio().presignedGetObject(BUCKET, key, ttlSeconds);
}
