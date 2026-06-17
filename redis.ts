import Redis from 'ioredis';

let redis: Redis;

export async function initRedis(): Promise<void> {
  redis = new Redis(process.env.REDIS_URL!, {
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    lazyConnect: true,
  });

  await redis.connect();
  await redis.ping();
  console.log('[Redis] Connected');
}

export function getRedis(): Redis {
  if (!redis) throw new Error('Redis not initialized');
  return redis;
}

// Session helpers
export const SESSION_TTL = 30 * 24 * 60 * 60; // 30 days

export async function setSession(
  userId: string,
  socketId: string
): Promise<void> {
  await getRedis().hset(`user:online:${userId}`, 'socketId', socketId, 'ts', Date.now());
  await getRedis().expire(`user:online:${userId}`, 300); // 5min heartbeat
}

export async function removeSession(userId: string): Promise<void> {
  await getRedis().del(`user:online:${userId}`);
}

export async function getSocketId(userId: string): Promise<string | null> {
  return getRedis().hget(`user:online:${userId}`, 'socketId');
}

export async function cacheKeyBundle(
  userId: string,
  bundle: object
): Promise<void> {
  await getRedis().setex(
    `keybundle:${userId}`,
    300,
    JSON.stringify(bundle)
  );
}

export async function getCachedKeyBundle(
  userId: string
): Promise<object | null> {
  const data = await getRedis().get(`keybundle:${userId}`);
  return data ? JSON.parse(data) : null;
}
