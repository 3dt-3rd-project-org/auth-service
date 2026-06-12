import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;

export function authenticateToken(request) {
  const authHeader = request.headers.get('authorization');
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    throw {
      status: 401,
      body: { error: 'Unauthorized', message: '요청 헤더에 Bearer 토큰이 존재하지 않습니다.' }
    };
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role
    };
  } catch (err) {
    throw {
      status: 403,
      body: { error: 'Forbidden', message: '유효하지 않거나 만료된 토큰입니다.' }
    };
  }
}
