const request = require('supertest');

const BASE_URL = 'http://localhost:8080';
const TEST_USER_ID = 'test-user-' + Math.random().toString(36).substring(7);

describe('Auth Service API', () => {

    let access_token = '';
    let refresh_token = '';
    let new_access_token = '';
    let new_refresh_token = '';

    beforeAll(async () => {
        await new Promise(resolve => setTimeout(resolve, 1000));
    }, 10000);

    test('POST /auth/token - should generate tokens', async () => {
        const response = await request(BASE_URL)
            .post('/auth/token')
            .send({ user_id: TEST_USER_ID });

        expect(response.body.access_token).toBeDefined();
        expect(response.body.refresh_token).toBeDefined();
        expect(response.status).toBe(200)
		
        access_token = response.body.access_token;
        refresh_token = response.body.refresh_token;
    });

    test('GET /auth/me - should return user info with valid token', async () => {
        const response = await request(BASE_URL)
            .get('/auth/me')
            .set('Authorization', `Bearer ${access_token}`)
            .expect(200);

        expect(response.body.user_id).toBe(TEST_USER_ID);
    });

    test('GET /auth/me - should reject with invalid token', async () => {
        const response = await request(BASE_URL)
            .get('/auth/me')
            .set('Authorization', 'Bearer invalid-token')
            .expect(401);

        expect(response.body.error).toBe('Invalid token');
    });

    test('POST /auth/refresh - should refresh tokens', async () => {
        const response = await request(BASE_URL)
            .post('/auth/refresh')
            .set('Authorization', `Bearer ${access_token}`)
            .send({ refresh_token: refresh_token });

        expect(response.body.access_token).toBeDefined();
        expect(response.body.refresh_token).toBeDefined();
        expect(response.status).toBe(200)
	
        new_access_token = response.body.access_token;
        new_refresh_token = response.body.refresh_token;
    });

    test('POST /auth/refresh - should reject with revoked refresh token', async () => {
        const response = await request(BASE_URL)
            .post('/auth/refresh')
            .send({ refresh_token: refresh_token }) // старый токен
            .set('Authorization', `Bearer ${access_token}`); // оставим старый токен
			
        expect(response.status).toBe(401)
        expect(response.body.error).toBe('Token revoked');
    });

    test('GET /auth/me - should work with new access token', async () => {
        const response = await request(BASE_URL)
            .get('/auth/me')
            .set('Authorization', `Bearer ${new_access_token}`)
            .expect(200);

        expect(response.body.user_id).toBe(TEST_USER_ID);
    });

    test('POST /auth/refresh - should reject with changed User-Agent', async () => {
        const response = await request(BASE_URL)
            .post('/auth/refresh')
            .set('User-Agent', 'Different-UA')
            .set('Authorization', `Bearer ${new_access_token}`) 
            .send({ refresh_token: new_refresh_token })
            .expect(401);

        expect(response.body.error).toBe('User-Agent changed');
    });

    
    test('POST /auth/token - should generate tokens after revoke', async () => {
        const response = await request(BASE_URL)
            .post('/auth/token')
            .send({ user_id: TEST_USER_ID });

        expect(response.body.access_token).toBeDefined();
        expect(response.body.refresh_token).toBeDefined();
        expect(response.status).toBe(200)
		
        new_access_token = response.body.access_token;
        new_refresh_token = response.body.refresh_token;
    });

    
    test('POST /auth/refresh - should detect IP change and send webhook', async () => {

        const response = await request(BASE_URL)
            .post('/auth/refresh')
            .set('X-Forwarded-For', '1.2.3.4')
            .set('Authorization', `Bearer ${new_access_token}`) 
            .send({ refresh_token: new_refresh_token });

        expect(response.body.access_token).toBeDefined();
        expect(response.body.refresh_token).toBeDefined();
        expect(response.status).toBe(200)
		
        new_access_token = response.body.access_token;
        new_refresh_token = response.body.refresh_token;
    });

    test('POST /auth/logout - should revoke tokens', async () => {
        await request(BASE_URL)
            .post('/auth/logout')
            .set('Authorization', `Bearer ${new_access_token}`)
            .expect(200);
    });

    test('GET /auth/me - should reject after logout', async () => {
        const response = await request(BASE_URL)
            .get('/auth/me')
            .set('Authorization', `Bearer ${new_access_token}`)
            .expect(401);

        expect(response.body.error).toBe('Token revoked');
    });

    test('POST /auth/refresh - should reject after logout', async () => {
        const response = await request(BASE_URL)
            .post('/auth/refresh')
            .send({ refresh_token: new_refresh_token })
            .set('Authorization', `Bearer ${new_access_token}`)
            .expect(401);

        expect(response.body.error).toBe('Token revoked');
    });

    test('POST /auth/token - should reject empty user_id', async () => {
        const response = await request(BASE_URL)
            .post('/auth/token')
            .send({}) // нет user_id
            .expect(400);

        expect(response.body.error).toBeDefined();
    });

    test('POST /auth/refresh - should reject with malformed refresh_token (not base64)', async () => {
        const response = await request(BASE_URL)
            .post('/auth/refresh')
            .send({ refresh_token: 'not-base64-token!' })
            .set('Authorization', `Bearer ${new_access_token}`)
            .expect(401);

        expect(response.body.error).toBe('Incorrect tokens pair');
    });

    test('POST /auth/refresh - should reject with mismatched pair_id', async () => {
        // сгенерируем новые токены с другим user_id
        const altUser = 'alt-user-' + Math.random().toString(36).substring(7);
        const alt = await request(BASE_URL)
            .post('/auth/token')
            .send({ user_id: altUser });

        const mismatched_refresh_token = alt.body.refresh_token;

        const response = await request(BASE_URL)
            .post('/auth/refresh')
            .send({ refresh_token: mismatched_refresh_token })
            .set('Authorization', `Bearer ${new_access_token}`) // токен от другого user
            .expect(401);

        expect(response.body.error).toBe('Incorrect tokens pair');
    });

    test('POST /auth/refresh - should reject with expired access token (manually revoked)', async () => {
        
        const token = await request(BASE_URL)
            .post('/auth/token')
            .send({ user_id: TEST_USER_ID });

        expect(token.body.access_token).toBeDefined();
        expect(token.body.refresh_token).toBeDefined();
        expect(token.status).toBe(200)
        
        // отозвём access_token
        await request(BASE_URL)
            .post('/auth/logout')
            .set('Authorization', `Bearer ${token.body.access_token}`)
            .expect(200);

        const response = await request(BASE_URL)
            .post('/auth/refresh')
            .send({ refresh_token: new_refresh_token })
            .set('Authorization', `Bearer ${token.body.access_token}`)
            .expect(401);

        expect(response.body.error).toBe('Incorrect tokens pair');
    });

    test('GET /auth/me - should reject when Authorization header is missing', async () => {
        const response = await request(BASE_URL)
            .get('/auth/me')
            .expect(401);

        expect(response.body.error).toBe('Authorization required');
    });
});