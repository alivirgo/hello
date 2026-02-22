export default {
    async fetch(request, env) {
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        const url = new URL(request.url);
        const path = url.pathname;

        // Resolve KV Namespace (Flexible for user's KV_BINDING or NUC7_STATS)
        const STATS_KV = env.NUC7_STATS || env.KV_BINDING;

        try {
            // 0. HEALTH CHECK (No Dependencies)
            if (path === '/ping') {
                return new Response(JSON.stringify({ status: 'online', timestamp: new Date().toISOString() }), {
                    headers: corsHeaders
                });
            }

            // 1. PRODUCTION VISITOR TRACKING (STRICT KV)
            if (path === '/track' && request.method === 'POST') {
                const hitData = await request.json();

                if (!STATS_KV) {
                    return new Response(JSON.stringify({ error: 'NUC7 Statistics KV Not Found. Visit your Cloudflare dashboard to bind it.' }), {
                        status: 500, headers: corsHeaders
                    });
                }

                const timestamp = new Date().toISOString();
                const hit = {
                    path: hitData.path,
                    referrer: hitData.referrer || 'Direct',
                    userAgent: hitData.userAgent || 'Unknown',
                    timestamp
                };

                // Update Recent Hits (Limited to 50)
                let hits = await STATS_KV.get('hits', 'json') || [];
                hits.unshift(hit);
                if (hits.length > 50) hits.pop();
                await STATS_KV.put('hits', JSON.stringify(hits));

                // Increment Total Views
                const totalViews = (parseInt(await STATS_KV.get('totalViews')) || 0) + 1;
                await STATS_KV.put('totalViews', totalViews.toString());

                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }

            // 2. ACTUAL ADMIN STATS (NO DUMMY DATA)
            if (path === '/stats' && request.method === 'POST') {
                const { password } = await request.json();

                // Auth Check
                const vaultRes = await fetch(`https://api.github.com/repos/alivirgo/nuc7-vault/contents/vault.json`, {
                    headers: {
                        'Authorization': `token ${env.GITHUB_PAT}`,
                        'Accept': 'application/vnd.github.v3.raw',
                        'User-Agent': 'nuc7-auth-bridge'
                    }
                });

                if (!vaultRes.ok) {
                    const errText = await vaultRes.text();
                    throw new Error(`Vault Access Failed: ${vaultRes.status} ${errText}`);
                }

                const vault = await vaultRes.json();
                const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
                const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

                if (hashHex !== vault.adminPasswordHash) {
                    return new Response('Unauthorized', { status: 401, headers: corsHeaders });
                }

                if (!STATS_KV) {
                    return new Response(JSON.stringify({ error: 'NUC7_STATS/KV_BINDING KV missing.' }), { status: 500, headers: corsHeaders });
                }

                const hits = await STATS_KV.get('hits', 'json') || [];
                const totalViews = await STATS_KV.get('totalViews') || '0';
                const registrations = await STATS_KV.get('totalReg') || '0';

                return new Response(JSON.stringify({
                    activeUsers: Math.max(1, Math.floor(hits.length / 4)), // Estimated live
                    pageViews: totalViews,
                    totalRegistrations: registrations,
                    hits: hits
                }), { headers: corsHeaders });
            }

            // 3. SECURE EMAIL REGISTRATION
            if (path === '/send-registration' && request.method === 'POST') {
                const { email } = await request.json();

                // 1. Generate Signed Token
                const salt = env.AUTH_SECRET || 'nuc7_prod_secret';
                const tokenSource = `${email}:${Date.now()}:${salt}`;
                const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(tokenSource));
                const token = btoa(Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join(''));

                // 2. Log Registration Stats
                if (STATS_KV) {
                    const totalReg = (parseInt(await STATS_KV.get('totalReg')) || 0) + 1;
                    await STATS_KV.put('totalReg', totalReg.toString());
                }

                // 3. INTEGRATION: SEND EMAIL (SENDGRID)
                // Note to User: Set env.SENDGRID_API_KEY and env.FRONTEND_URL in Cloudflare dashboard
                if (env.SENDGRID_API_KEY) {
                    const frontendUrl = env.FRONTEND_URL || url.origin;
                    const quizUrl = `${frontendUrl}/quiz.html?email=${encodeURIComponent(email)}&token=${token}`;
                    await fetch('https://api.sendgrid.com/v3/mail/send', {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${env.SENDGRID_API_KEY}`,
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            personalizations: [{ to: [{ email }] }],
                            from: { email: 'noreply@nuc7.com', name: 'NUC7 Course Team' },
                            subject: 'Your NUC7 Qualification Quiz Link',
                            content: [{ type: 'text/html', value: `<p>Start your Networking journey: <a href="${quizUrl}">Begin Qualification Test</a></p>` }]
                        })
                    });
                }

                return new Response(JSON.stringify({ success: true, message: 'Registry complete. Check email.' }), { headers: corsHeaders });
            }

            // 3.5 GET PRODUCTION TOKEN (After Quiz Success)
            if (path === '/get-token' && request.method === 'POST') {
                const { email, score } = await request.json();

                if (score < 7) {
                    return new Response(JSON.stringify({ error: 'Score too low.' }), { status: 403, headers: corsHeaders });
                }

                const salt = env.AUTH_SECRET || 'nuc7_prod_secret';
                const tokenSource = `${email}:course_access:${salt}`;
                const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(tokenSource));
                const token = btoa(Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join(''));

                return new Response(JSON.stringify({ token }), { headers: corsHeaders });
            }

            // 4. SECURE QUESTION FETCH
            if (path === '/get-questions' && request.method === 'GET') {
                const res = await fetch(`https://api.github.com/repos/alivirgo/nuc7-vault/contents/questions.json`, {
                    headers: {
                        'Authorization': `token ${env.GITHUB_PAT}`,
                        'Accept': 'application/vnd.github.v3.raw',
                        'User-Agent': 'nuc7-auth-bridge'
                    }
                });

                if (!res.ok) {
                    // Fallback questions for demo if vault is not yet ready
                    const fallback = [
                        { question: "What is the Physical Layer responsible for?", options: ["Raw bit transmission", "IP Routing", "Error correction", "Session management"], answer: 0 },
                        { question: "Which layer handles MAC addresses?", options: ["Physical", "Data Link", "Network", "Transport"], answer: 1 },
                        { question: "Port 80 is associated with which protocol?", options: ["FTP", "SSH", "HTTP", "HTTPS"], answer: 2 }
                    ];
                    return new Response(JSON.stringify(fallback), { headers: corsHeaders });
                }

                const allQuestions = await res.json();
                const shuffled = allQuestions.sort(() => 0.5 - Math.random()).slice(0, 10);
                return new Response(JSON.stringify(shuffled), { headers: corsHeaders });
            }

            return new Response('NUC7 Bridge: Path Not Found', { status: 404, headers: corsHeaders });

        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: corsHeaders });
        }
    }
};
