import { app } from '@azure/functions';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { dbPool } from '../config/db.js';
import { logger } from '../utils/logger.js';
import { handleSuccess, handleError } from '../shared/responseHelper.js';

const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_USER_REDIRECT_URI = process.env.GOOGLE_USER_REDIRECT_URI;
const GOOGLE_ADMIN_REDIRECT_URI = process.env.GOOGLE_ADMIN_REDIRECT_URI;

// 1. 일반 사용자 구글 로그인 리다이렉트 URL 생성
app.http('userGoogleLogin', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'auth/user/google',
  handler: async (request, context) => {
    logger.info('[Auth User Login] 일반 사용자 구글 로그인 리다이렉트 URL 생성 시작');
    const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
      `response_type=code` +
      `&client_id=${encodeURIComponent(GOOGLE_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(GOOGLE_USER_REDIRECT_URI)}` +
      `&scope=openid%20email%20profile` +
      `&access_type=offline` +
      `&prompt=select_account`;

    return {
      status: 302,
      headers: { 'Location': googleAuthUrl }
    };
  }
});

// 2. 일반 사용자 로그인 및 토큰 교환 (대안 2 - POST)
app.http('userGoogleLoginPost', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'auth/user/login',
  handler: async (request, context) => {
    logger.info('[Auth User Login] 일반 사용자 구글 로그인(토큰 교환) 요청 접수');
    try {
      const reqBody = await request.json();
      const { code } = reqBody;

      if (!code) {
        return {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'Bad Request', message: '인가 코드(code)가 누락되었습니다.' })
        };
      }

      const tokenUrl = 'https://oauth2.googleapis.com/token';
      const tokenResponse = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          redirect_uri: GOOGLE_USER_REDIRECT_URI,
          grant_type: 'authorization_code'
        })
      });

      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        throw new Error(`구글 토큰 핸드셰이킹 실패: ${errorText}`);
      }

      const tokenData = await tokenResponse.json();
      
      const profileUrl = 'https://www.googleapis.com/oauth2/v3/userinfo';
      const profileResponse = await fetch(profileUrl, {
        headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
      });

      if (!profileResponse.ok) {
        throw new Error('구글 사용자 프로필 API 조회 실패');
      }

      const profileData = await profileResponse.json();
      logger.info(`[Auth User Login] 구글 프로필 정보 수신 완료 (Email: ${profileData.email})`);
      
      const googleUser = {
        google_id: profileData.sub,
        email: profileData.email,
        nickname: profileData.name || profileData.email.split('@')[0],
        role: 'USER'
      };

      const result = await dbPool.query(
        `INSERT INTO users (google_id, email, nickname, role, approved, created_at)
         VALUES ($1, $2, $3, $4, true, CURRENT_TIMESTAMP)
         ON CONFLICT (email) DO UPDATE 
           SET nickname = EXCLUDED.nickname, google_id = EXCLUDED.google_id, approved = true
         RETURNING *`,
        [googleUser.google_id, googleUser.email, googleUser.nickname, googleUser.role]
      );

      const user = result.rows[0];

      const token = jwt.sign(
        { id: user.id, email: user.email, role: 'USER' },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      const bearerToken = `Bearer ${token}`;
      logger.info(`[Auth User Login] DB 사용자 적재 및 JWT 발급 완료 (User ID: ${user.id}, Role: USER)`);

      return handleSuccess({
        message: '일반 독자용 Google 로그인에 성공하여 토큰이 발급되었습니다.',
        token: bearerToken,
        user: { id: user.id, email: user.email, nickname: user.nickname, role: user.role }
      });
    } catch (err) {
      return handleError(err, logger, 'Google OAuth USER Login');
    }
  }
});

// 3. 관리자 구글 로그인 리다이렉트
app.http('adminGoogleLogin', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'auth/admin/google',
  handler: async (request, context) => {
    logger.info('[Auth Admin Login] 관리자 구글 로그인 리다이렉트 URL 생성 시작');
    const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
      `response_type=code` +
      `&client_id=${encodeURIComponent(GOOGLE_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(GOOGLE_ADMIN_REDIRECT_URI)}` +
      `&scope=openid%20email%20profile` +
      `&access_type=offline` +
      `&prompt=select_account`;

    logger.info('[Auth Admin Login] 관리자 구글 로그인 리다이렉트 URL 생성 성공');
    return {
      status: 302,
      headers: { 'Location': googleAuthUrl }
    };
  }
});

// 4. 관리자 로그인 및 토큰 교환 (대안 2 - POST)
app.http('adminGoogleLoginPost', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'auth/admin/login',
  handler: async (request, context) => {
    logger.info('[Auth Admin Login] 관리자 구글 로그인(토큰 교환) 요청 접수');
    try {
      const reqBody = await request.json();
      const { code } = reqBody;

      if (!code) {
        return {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'Bad Request', message: '인가 코드(code)가 누락되었습니다.' })
        };
      }

      const tokenUrl = 'https://oauth2.googleapis.com/token';
      const tokenResponse = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          redirect_uri: GOOGLE_ADMIN_REDIRECT_URI,
          grant_type: 'authorization_code'
        })
      });

      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        throw new Error(`구글 토큰 핸드셰이킹 실패: ${errorText}`);
      }

      const tokenData = await tokenResponse.json();
      
      const profileUrl = 'https://www.googleapis.com/oauth2/v3/userinfo';
      const profileResponse = await fetch(profileUrl, {
        headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
      });

      if (!profileResponse.ok) {
        throw new Error('구글 사용자 프로필 API 조회 실패');
      }

      const profileData = await profileResponse.json();
      logger.info(`[Auth Admin Login] 구글 프로필 정보 수신 완료 (Email: ${profileData.email})`);
      
      const googleUser = {
        google_id: profileData.sub,
        email: profileData.email,
        nickname: profileData.name || profileData.email.split('@')[0],
        role: 'ADMIN'
      };

      // [임시 테스트용] 빠른 로컬/프론트 연동 테스트를 위해 approved = true 강제 인서트
      const result = await dbPool.query(
        `INSERT INTO users (google_id, email, nickname, role, approved, created_at)
         VALUES ($1, $2, $3, $4, true, CURRENT_TIMESTAMP)
         ON CONFLICT (email) DO UPDATE 
           SET nickname = EXCLUDED.nickname, 
               google_id = EXCLUDED.google_id,
               role = EXCLUDED.role,
               approved = true
         RETURNING *`,
        [googleUser.google_id, googleUser.email, googleUser.nickname, googleUser.role]
      );

      const user = result.rows[0];

      const token = jwt.sign(
        { id: user.id, email: user.email, role: 'ADMIN' },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      const bearerToken = `Bearer ${token}`;
      logger.info(`[Auth Admin Login] DB 사용자 적재 및 어드민 JWT 발급 완료 (User ID: ${user.id}, Role: ADMIN)`);

      return handleSuccess({
        message: '시스템 관리자용 Google 로그인에 성공하여 토큰이 발급되었습니다.',
        token: bearerToken,
        user: { id: user.id, email: user.email, nickname: user.nickname, role: user.role }
      });
    } catch (err) {
      return handleError(err, logger, 'Google OAuth ADMIN Login');
    }
  }
});

// 5. Teams 승인 수락 처리 API (사전 구현)
app.http('adminApprove', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'auth/admin/approve',
  handler: async (request, context) => {
    logger.info('[Auth Admin Approve] Teams 관리자 승인 요청 접수');
    try {
      const reqBody = await request.json();
      const { email, token } = reqBody;

      if (!email || !token) {
        return {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'Bad Request', message: 'email과 token 필드는 필수입니다.' })
        };
      }

      // 서버 내 HMAC 서명 검증
      const expectedToken = crypto.createHmac('sha256', JWT_SECRET).update(email).digest('hex');
      if (token !== expectedToken) {
        logger.warn(`[Auth Admin Approve] 허가되지 않은 토큰 서명 불일치 감지 (Email: ${email})`);
        return {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'Forbidden', message: '유효하지 않은 보안 서명 토큰입니다.' })
        };
      }

      // DB 승인 상태 true 처리
      const result = await dbPool.query(
        "UPDATE users SET approved = true WHERE email = $1 AND role = 'ADMIN' RETURNING *",
        [email]
      );

      if (result.rows.length === 0) {
        logger.warn(`[Auth Admin Approve] 승인 대상 도메인 관리자가 발견되지 않음 (Email: ${email})`);
        return {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'Not Found', message: '해당 관리자를 찾을 수 없습니다.' })
        };
      }

      const approvedUser = result.rows[0];
      logger.info(`[Auth Admin Approve] 관리자 ${approvedUser.email}의 가입 승인이 성공적으로 완료되었습니다.`);

      return {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: `관리자 ${approvedUser.nickname}(${approvedUser.email})의 가입 승인이 완료되었습니다.`
        })
      };
    } catch (err) {
      return handleError(err, logger, 'Auth Admin Approve');
    }
  }
});

// Teams 승인 카드 요청 웹훅 발송 헬퍼 함수
async function sendTeamsApprovalCard(user) {
  const webhookUrl = process.env.TEAMS_WEBHOOK_URL;
  if (!webhookUrl) {
    logger.warn('[Teams Notification] TEAMS_WEBHOOK_URL 환경 변수가 설정되어 있지 않아 승인 알림 전송을 생략합니다.');
    return;
  }

  const secureToken = crypto.createHmac('sha256', JWT_SECRET).update(user.email).digest('hex');

  const serviceDomain = process.env.SERVICE_DOMAIN || 'http://localhost:7071';
  const approveUrl = `${serviceDomain}/api/auth/admin/approve`;

  const payload = {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    "themeColor": "0284c7",
    "summary": "관리자 가입 승인 요청",
    "sections": [{
      "activityTitle": "🔑 신규 관리자 가입 승인 요청",
      "activitySubtitle": "ReadPoint Admin Console",
      "facts": [
        { "name": "닉네임", "value": user.nickname },
        { "name": "이메일", "value": user.email }
      ],
      "markdown": true
    }],
    "potentialAction": [{
      "@type": "HttpPOST",
      "name": "가입 승인 완료",
      "target": approveUrl,
      "headers": [
        { "name": "Content-Type", "value": "application/json" }
      ],
      "body": JSON.stringify({
        email: user.email,
        token: secureToken
      })
    }]
  };

  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      throw new Error(`Teams Webhook HTTP 응답 실패: ${res.statusText}`);
    }
    logger.info(`[Teams Notification] 관리자 ${user.email} 승인 요청 알림 카드 발송 성공.`);
  } catch (err) {
    logger.error(`[Teams Notification Error] Teams 알림 발송 중 오류: ${err.message}`);
  }
}
