import { app } from '@azure/functions';
import jwt from 'jsonwebtoken';
import { dbPool } from '../config/db.js';
import { logger } from '../utils/logger.js';
import { handleSuccess, handleError } from '../shared/responseHelper.js';

const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_USER_REDIRECT_URI = process.env.GOOGLE_USER_REDIRECT_URI;
const GOOGLE_ADMIN_REDIRECT_URI = process.env.GOOGLE_ADMIN_REDIRECT_URI;

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

app.http('userGoogleCallback', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'auth/user/google/callback',
  handler: async (request, context) => {
    logger.info('[Auth User Callback] 일반 사용자 구글 인증 콜백 요청 접수');
    const code = request.query.get('code');

    if (!code) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Bad Request', message: '인가 코드(code)가 수신되지 않았습니다.' })
      };
    }

    try {
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
      logger.info(`[Auth User Callback] 구글 프로필 정보 수신 완료 (Email: ${profileData.email})`);
      
      const googleUser = {
        google_id: profileData.sub,
        email: profileData.email,
        nickname: profileData.name || profileData.email.split('@')[0],
        role: 'USER'
      };

      const result = await dbPool.query(
        `INSERT INTO users (google_id, email, nickname, role, created_at)
         VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
         ON CONFLICT (email) DO UPDATE 
           SET nickname = EXCLUDED.nickname, google_id = EXCLUDED.google_id
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
      logger.info(`[Auth User Callback] DB 사용자 적재 및 JWT 발급 완료 (User ID: ${user.id}, Role: USER)`);
      const acceptHeader = request.headers.get('accept') || '';

      if (acceptHeader.includes('text/html')) {
        return {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
          body: renderSuccessHtml('일반 사용자(USER)', bearerToken, {
            id: user.id,
            email: user.email,
            nickname: user.nickname,
            role: user.role
          })
        };
      }

      return handleSuccess({
        message: '일반 독자용 Google 로그인에 성공하여 토큰이 발급되었습니다.',
        token: bearerToken,
        user: { id: user.id, email: user.email, nickname: user.nickname, role: user.role }
      });
    } catch (err) {
      return handleError(err, logger, 'Google OAuth USER Callback');
    }
  }
});

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

app.http('adminGoogleCallback', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'auth/admin/google/callback',
  handler: async (request, context) => {
    logger.info('[Auth Admin Callback] 관리자 구글 인증 콜백 요청 접수');
    const code = request.query.get('code');

    if (!code) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Bad Request', message: '인가 코드(code)가 수신되지 않았습니다.' })
      };
    }

    try {
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
      logger.info(`[Auth Admin Callback] 구글 프로필 정보 수신 완료 (Email: ${profileData.email})`);
      
      const googleUser = {
        google_id: profileData.sub,
        email: profileData.email,
        nickname: profileData.name || profileData.email.split('@')[0],
        role: 'ADMIN'
      };

      const result = await dbPool.query(
        `INSERT INTO users (google_id, email, nickname, role, created_at)
         VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
         ON CONFLICT (email) DO UPDATE 
           SET nickname = EXCLUDED.nickname, 
               google_id = EXCLUDED.google_id,
               role = EXCLUDED.role
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
      logger.info(`[Auth Admin Callback] DB 사용자 적재 및 어드민 JWT 발급 완료 (User ID: ${user.id}, Role: ADMIN)`);
      const acceptHeader = request.headers.get('accept') || '';

      if (acceptHeader.includes('text/html')) {
        return {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
          body: renderSuccessHtml('시스템 관리자(ADMIN)', bearerToken, {
            id: user.id,
            email: user.email,
            nickname: user.nickname,
            role: user.role
          })
        };
      }

      return handleSuccess({
        message: '시스템 관리자용 Google 로그인에 성공하여 토큰이 발급되었습니다.',
        token: bearerToken,
        user: { id: user.id, email: user.email, nickname: user.nickname, role: user.role }
      });
    } catch (err) {
      return handleError(err, logger, 'Google OAuth ADMIN Callback');
    }
  }
});

function renderSuccessHtml(roleName, tokenValue, userObj) {
  const userJson = JSON.stringify(userObj);
  return `
    <!DOCTYPE html>
    <html lang="ko">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Google 로그인 완료</title>
      <style>
        body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); padding: 40px; border-radius: 16px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3); max-width: 480px; width: 100%; border: 1px solid rgba(255,255,255,0.05); text-align: center; }
        h2 { color: #38bdf8; margin-top: 0; }
        .token-box { background-color: #020617; padding: 16px; border-radius: 8px; border: 1px dashed #38bdf8; font-family: monospace; word-break: break-all; text-align: left; max-height: 120px; overflow-y: auto; color: #34d399; font-size: 13px; margin: 20px 0; }
        .btn-group { display: flex; gap: 10px; justify-content: center; margin-top: 20px; }
        .btn { background: linear-gradient(135deg, #38bdf8, #0284c7); border: none; color: white; padding: 12px 24px; border-radius: 8px; font-weight: bold; cursor: pointer; text-decoration: none; display: inline-block; transition: all 0.2s; font-size: 14px; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(56, 189, 248, 0.4); }
        .btn.secondary { background: #334155; }
        .btn.secondary:hover { box-shadow: 0 4px 12px rgba(51, 65, 85, 0.4); }
      </style>
      <script>
        (function() {
          const token = "${tokenValue}";
          const user = ${userJson};
          
          if (window.opener) {
            window.opener.postMessage({ type: "LOGIN_SUCCESS", token, user }, "*");
          }
        })();
      </script>
    </head>
    <body>
      <div class="card">
        <h2>🔑 Google 인증 성공!</h2>
        <p>${roleName} 세션 가입 및 로그인이 완료되었습니다.</p>
        <p style="font-size: 12px; color: #94a3b8; margin: 0;">(프론트엔드 팝업 연동 시 토큰이 부모 창으로 자동 전달되었습니다)</p>
        <div class="token-box" id="token">${tokenValue}</div>
        <div class="btn-group">
          <button class="btn" onclick="navigator.clipboard.writeText(document.getElementById('token').innerText); alert('토큰이 클립보드에 복사되었습니다!');">JWT 토큰 복사</button>
          <button class="btn secondary" onclick="window.close();">창 닫기</button>
        </div>
      </div>
    </body>
    </html>
  `;
}
