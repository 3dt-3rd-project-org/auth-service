import { logger } from '../utils/logger.js';

const REQUIRED_ENV_VARS = [
  'JWT_SECRET',
  'PGHOST',
  'PGPORT',
  'PGUSER',
  'PGPASSWORD',
  'PGDATABASE',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'GOOGLE_USER_REDIRECT_URI',
  'GOOGLE_ADMIN_REDIRECT_URI'
];

export function validateEnvironment() {
  const missingVars = [];

  for (const envVar of REQUIRED_ENV_VARS) {
    const val = process.env[envVar];
    if (!val || val.trim() === '' || val.includes('change-this-in-production') || val.includes('실제_구글_')) {
      missingVars.push(envVar);
    }
  }

  if (missingVars.length > 0) {
    logger.error('\n================================================================');
    logger.error('[Auth Service Error] 필수 보안 환경변수가 누락되었습니다!');
    logger.error('================================================================');
    missingVars.forEach(v => logger.error(`  - ${v}`));
    logger.error('================================================================\n');
    process.exit(1);
  }

  logger.info('[Auth Service] 모든 필수 보안 환경변수 검증 통과 완료.');
}
