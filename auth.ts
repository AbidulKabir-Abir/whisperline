import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export interface AuthRequest extends Request {
  userId?: string;
  userTag?: string;
}

interface JwtPayload {
  sub: string;      // userId
  tag: string;      // @A7K2M9X4
  iat: number;
  exp: number;
}

export function requireAuth(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
    req.userId = payload.sub;
    req.userTag = payload.tag;
    next();
  } catch {
    res.status(401).json({ error: 'invalid_token' });
  }
}

export function signToken(userId: string, userTag: string): string {
  return jwt.sign(
    { sub: userId, tag: userTag },
    process.env.JWT_SECRET!,
    { expiresIn: '30d', algorithm: 'HS512' }
  );
}
