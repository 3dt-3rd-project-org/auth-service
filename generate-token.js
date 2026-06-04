import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || '00a8aed58e54691c5c616353611a2a6abe97191421c1e125f9de00ba58e217e3';

const adminPayload = {
  id: 1, 
  email: 'admin-test@bookgraph.com',
  role: 'ADMIN'
};

const adminToken = jwt.sign(adminPayload, JWT_SECRET, { expiresIn: '7d' });

const userPayload = {
  id: 2, 
  email: 'user-test@bookgraph.com',
  role: 'USER'
};

const userToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

console.log('================================================================');
console.log('🔑 Azure Functions API 테스트를 위한 임시 JWT 발급기');
console.log('================================================================');
console.log('\n[ADMIN 권한 토큰 (관리자 API 전용)]');
console.log(`Bearer ${adminToken}`);
console.log('\n[USER 권한 토큰 (일반 사용자 API 전용)]');
console.log(`Bearer ${userToken}`);
console.log('================================================================');
