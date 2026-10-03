const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { Pool } = require('pg');

const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 10000;
const SECRET = process.env.JWT_SECRET;

if (!SECRET) {
    throw new Error('JWT_SECRET is required');
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 5
});

const tok = (u) =>
    jwt.sign(
        {
            id: u.id,
            email: u.email,
            role: u.role,
            name: u.name
        },
        SECRET,
        { expiresIn: '30d' }
    );

function auth(req, res, next) {
    try {
        const h = req.headers.authorization || '';

        if (!h.startsWith('Bearer ')) {
            throw 0;
        }

        req.user = jwt.verify(h.slice(7), SECRET);
        next();
    } catch (e) {
        res.status(401).json({
            error: 'Потрібна авторизація'
        });
    }
}

function admin(req, res, next) {
    return req.user?.role === 'admin'
        ? next()
        : res.status(403).json({
              error: 'Потрібні права адміністратора'
          });
}

function cleanRoute(r) {
    return {
        clientId: String(r.clientId ?? r.id ?? ''),
        district: String(r.district ?? ''),
        author: String(r.author ?? ''),
        date: String(r.date ?? ''),
        time: String(r.time ?? ''),
        title: String(r.title ?? ''),
        source: r.source === 'Загальний' ? 'Загальний' : 'Мої',
        points: Array.isArray(r.points) ? r.points : [],
        ratingSum: Number(r.ratingSum || 0),
        ratingCount: Number(r.ratingCount || 0)
    };
}

async function audit(user, action, entity, entityId, details = {}) {
    try {
        await pool.query(
            `INSERT INTO audit_log
            (user_id, action, entity, entity_id, details)
            VALUES ($1,$2,$3,$4,$5)`,
            [
                user?.id || null,
                action,
                entity,
                entityId ? String(entityId) : null,
                JSON.stringify(details)
            ]
        );
    } catch (e) {
        console.error('audit', e.message);
    }
}

async function init() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users(
            id BIGSERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'courier',
            active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS routes(
            id BIGSERIAL PRIMARY KEY,
            client_id TEXT NOT NULL,
            owner_id BIGINT REFERENCES users(id),
            district TEXT NOT NULL,
            author TEXT NOT NULL,
            date TEXT,
            time TEXT,
            title TEXT,
            source TEXT NOT NULL DEFAULT 'Мої',
            points JSONB NOT NULL DEFAULT '[]',
            rating_sum NUMERIC NOT NULL DEFAULT 0,
            rating_count INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            status TEXT NOT NULL DEFAULT 'published'
        )
    `);

    await pool.query(`
        ALTER TABLE routes
        ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'published'
    `);

    await pool.query(`
        ALTER TABLE routes
        ADD COLUMN IF NOT EXISTS created_at
        TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `);

    await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS routes_client_owner_uq
        ON routes(client_id, owner_id)
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS districts(
            id BIGSERIAL PRIMARY KEY,
            number TEXT UNIQUE NOT NULL,
            name TEXT,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            notes TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS ratings(
            id BIGSERIAL PRIMARY KEY,
            route_id BIGINT NOT NULL
                REFERENCES routes(id) ON DELETE CASCADE,
            user_id BIGINT NOT NULL
                REFERENCES users(id) ON DELETE CASCADE,
            stars INTEGER NOT NULL CHECK(stars BETWEEN 1 AND 5),
            comment TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(route_id, user_id)
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS audit_log(
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT REFERENCES users(id)
                ON DELETE SET NULL,
            action TEXT NOT NULL,
            entity TEXT NOT NULL,
            entity_id TEXT,
            details JSONB NOT NULL DEFAULT '{}',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // Створення адміністратора при першому запуску
    if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {

        const email = process.env.ADMIN_EMAIL
            .trim()
            .toLowerCase();

        const q = await pool.query(
            'SELECT id FROM users WHERE email=$1',
            [email]
        );

        if (!q.rowCount) {

            const hash = await bcrypt.hash(
                process.env.ADMIN_PASSWORD,
                12
            );

            const u = await pool.query(
                `INSERT INTO users
                (name,email,password_hash,role)
                VALUES($1,$2,$3,$4)
                RETURNING id`,
                [
                    process.env.ADMIN_NAME || 'Адміністратор',
                    email,
                    hash,
                    'admin'
                ]
            );

            await audit(
                { id: u.rows[0].id },
                'create',
                'user',
                u.rows[0].id,
                { source: 'bootstrap' }
            );
        }
    }
}


// =========================
// HEALTH
// =========================

app.get('/api/health', async (req, res) => {

    try {

        const q = await pool.query('SELECT 1');

        res.json({
            ok: true,
            db: q.rowCount === 1,
            serverTime: new Date().toISOString()
        });

    } catch (e) {

        res.status(503).json({
            ok: false,
            db: false,
            error: e.message
        });
    }
});


// =========================
// ADMIN PAGE
// =========================

// Правильний шлях:
// server.js знаходиться в корені,
// admin.html знаходиться в public/admin.html

app.get('/api/admin', auth, admin, (req, res) => {
    res.sendFile(
        path.join(__dirname, 'public', 'admin.html')
    );
});

app.use(
    '/admin',
    express.static(
        path.join(__dirname, 'public')
    )
);


// =========================
// REGISTER
// =========================

app.post('/api/register', async (req, res) => {

    try {

        let {
            name,
            email,
            password
        } = req.body || {};

        email = String(email || '')
            .trim()
            .toLowerCase();

        if (
            !name ||
            !email ||
            String(password || '').length < 6
        ) {
            return res.status(400).json({
                error:
                    'Заповніть дані; пароль мінімум 6 символів'
            });
        }

        if (
            (
                await pool.query(
                    'SELECT 1 FROM users WHERE email=$1',
                    [email]
                )
            ).rowCount
        ) {
            return res.status(409).json({
                error: 'Такий e-mail вже існує'
            });
        }

        const hash = await bcrypt.hash(
            password,
            12
        );

        const q = await pool.query(
            `INSERT INTO users
            (name,email,password_hash)
            VALUES($1,$2,$3)
            RETURNING id,name,email,role`,
            [
                String(name).trim(),
                email,
                hash
            ]
        );

        const u = q.rows[0];

        await audit(
            u,
            'create',
            'user',
            u.id,
            { role: u.role }
        );

        res.json({
            token: tok(u),
            email: u.email,
            name: u.name,
            role: u.role
        });

    } catch (e) {

        console.error(e);

        res.status(500).json({
            error: 'Помилка сервера'
        });
    }
});


// =========================
// LOGIN
// =========================

app.post('/api/login', async (req, res) => {

    try {

        const email = String(
            req.body?.email || ''
        )
            .trim()
            .toLowerCase();

        const password = String(
            req.body?.password || ''
        );

        const q = await pool.query(
            `SELECT *
             FROM users
             WHERE email=$1
             AND active=true`,
            [email]
        );

        const u = q.rows[0];

        if (
            !u ||
            !(await bcrypt.compare(
                password,
                u.password_hash
            ))
        ) {
            return res.status(401).json({
                error:
                    'Невірний e-mail або пароль'
            });
        }

        res.json({
            token: tok(u),
            email: u.email,
            name: u.name,
            role: u.role
        });

    } catch (e) {

        console.error(e);

        res.status(500).json({
            error: 'Помилка сервера'
        });
    }
});


// =========================
// CURRENT USER
// =========================

app.get('/api/me', auth, async (req, res) => {

    const q = await pool.query(
        `SELECT
            id,
            name,
            email,
            role,
            active,
            created_at
         FROM users
         WHERE id=$1`,
        [req.user.id]
    );

    if (!q.rowCount) {
        return res.status(404).json({
            error: 'Користувача не знайдено'
        });
    }

    res.json({
        user: q.rows[0]
    });
});


// =========================
// ROUTES
// =========================

app.get('/api/routes', auth, async (req, res) => {

    try {

        const q = await pool.query(
            `SELECT
                client_id AS "clientId",
                district,
                author,
                date,
                time,
                title,
                source,
                points,
                rating_sum AS "ratingSum",
                rating_count AS "ratingCount"
             FROM routes
             WHERE
                (
                    source='Загальний'
                    AND status='published'
                )
                OR
                (
                    source='Мої'
                    AND owner_id=$1
                )
             ORDER BY updated_at DESC`,
            [req.user.id]
        );

        res.json({
            routes: q.rows
        });

    } catch (e) {

        res.status(500).json({
            error:
                'Не вдалося отримати маршрути'
        });
    }
});


// =========================
// SYNC
// =========================

app.post('/api/sync', auth, async (req, res) => {

    const c = await pool.connect();

    try {

        await c.query('BEGIN');

        const incoming =
            Array.isArray(req.body?.routes)
                ? req.body.routes
                : [];

        let mine = 0;
        let general = 0;

        for (const raw of incoming) {

            if (!raw) continue;

            const r = cleanRoute(raw);

            const source = r.source;

            if (
                source === 'Загальний' &&
                req.user.role !== 'admin'
            ) {
                continue;
            }

            const cid =
                r.clientId ||
                (
                    'local-' +
                    Date.now() +
                    '-' +
                    Math.random()
                        .toString(36)
                        .slice(2)
                );

            await c.query(
                `INSERT INTO routes
                (
                    client_id,
                    owner_id,
                    district,
                    author,
                    date,
                    time,
                    title,
                    source,
                    points,
                    rating_sum,
                    rating_count,
                    updated_at,
                    status
                )
                VALUES
                (
                    $1,$2,$3,$4,$5,$6,$7,
                    $8,$9,$10,$11,NOW(),'published'
                )
                ON CONFLICT(client_id,owner_id)
                DO UPDATE SET
                    district=EXCLUDED.district,
                    author=EXCLUDED.author,
                    date=EXCLUDED.date,
                    time=EXCLUDED.time,
                    title=EXCLUDED.title,
                    source=EXCLUDED.source,
                    points=EXCLUDED.points,
                    rating_sum=EXCLUDED.rating_sum,
                    rating_count=EXCLUDED.rating_count,
                    updated_at=NOW()`,
                [
                    cid,
                    req.user.id,
                    r.district,
                    r.author,
                    r.date,
                    r.time,
                    r.title,
                    source,
                    JSON.stringify(r.points),
                    r.ratingSum,
                    r.ratingCount
                ]
            );

            if (source === 'Мої') {
                mine++;
            } else {
                general++;
            }
        }

        await c.query('COMMIT');

        const q = await pool.query(
            `SELECT
                client_id AS "clientId",
                district,
                author,
                date,
                time,
                title,
                source,
                points,
                rating_sum AS "ratingSum",
                rating_count AS "ratingCount"
             FROM routes
             WHERE
                (
                    source='Загальний'
                    AND status='published'
                )
                OR
                (
                    source='Мої'
                    AND owner_id=$1
                )
             ORDER BY updated_at DESC`,
            [req.user.id]
        );

        res.json({
            ok: true,
            savedMine: mine,
            savedGeneral: general,
            routes: q.rows
        });

    } catch (e) {

        await c.query('ROLLBACK');

        console.error(e);

        res.status(500).json({
            error: 'Синхронізація не виконана'
        });

    } finally {

        c.release();
    }
});


// =========================
// PROPOSE ROUTE
// =========================

app.post(
    '/api/routes/:clientId/propose',
    auth,
    async (req, res) => {

        try {

            const q = await pool.query(
                `SELECT *
                 FROM routes
                 WHERE client_id=$1
                 AND owner_id=$2
                 AND source='Мої'`,
                [
                    String(req.params.clientId),
                    req.user.id
                ]
            );

            if (!q.rowCount) {
                return res.status(404).json({
                    error:
                        'Особистий маршрут не знайдено'
                });
            }

            const r = q.rows[0];

            const cid =
                'proposal-' +
                r.client_id +
                '-' +
                req.user.id +
                '-' +
                Date.now();

            await pool.query(
                `INSERT INTO routes
                (
                    client_id,
                    owner_id,
                    district,
                    author,
                    date,
                    time,
                    title,
                    source,
                    points,
                    rating_sum,
                    rating_count,
                    status
                )
                VALUES
                (
                    $1,$2,$3,$4,$5,$6,$7,
                    'Загальний',$8,0,0,'pending'
                )`,
                [
                    cid,
                    r.owner_id,
                    r.district,
                    r.author,
                    r.date,
                    r.time,
                    r.title,
                    JSON.stringify(r.points || [])
                ]
            );

            await audit(
                req.user,
                'propose',
                'route',
                r.id,
                {
                    clientId: r.client_id
                }
            );

            res.json({
                ok: true,
                status: 'pending'
            });

        } catch (e) {

            console.error(e);

            res.status(500).json({
                error:
                    'Не вдалося подати маршрут на затвердження'
            });
        }
    }
);


// =========================
// RATING
// =========================

app.post(
    '/api/routes/:id/rating',
    auth,
    async (req, res) => {

        try {

            const stars = Math.max(
                1,
                Math.min(
                    5,
                    Number(req.body?.stars || 0)
                )
            );

            const comment = String(
                req.body?.comment || ''
            ).slice(0, 1000);

            const q = await pool.query(
                `SELECT id
                 FROM routes
                 WHERE client_id=$1
                 AND source='Загальний'
                 AND status='published'
                 LIMIT 1`,
                [String(req.params.id)]
            );

            if (!q.rowCount) {
                return res.status(404).json({
                    error: 'Маршрут не знайдено'
                });
            }

            const routeId = q.rows[0].id;

            await pool.query(
                `INSERT INTO ratings
                (route_id,user_id,stars,comment)
                VALUES($1,$2,$3,$4)
                ON CONFLICT(route_id,user_id)
                DO UPDATE SET
                    stars=EXCLUDED.stars,
                    comment=EXCLUDED.comment,
                    created_at=NOW()`,
                [
                    routeId,
                    req.user.id,
                    stars,
                    comment
                ]
            );

            await pool.query(
                `UPDATE routes
                 SET
                    rating_sum=
                    (
                        SELECT COALESCE(
                            SUM(stars),0
                        )
                        FROM ratings
                        WHERE route_id=$1
                    ),
                    rating_count=
                    (
                        SELECT COUNT(*)
                        FROM ratings
                        WHERE route_id=$1
                    ),
                    updated_at=NOW()
                 WHERE id=$1`,
                [routeId]
            );

            await audit(
                req.user,
                'rate',
                'route',
                routeId,
                { stars }
            );

            res.json({
                ok: true
            });

        } catch (e) {

            console.error(e);

            res.status(500).json({
                error:
                    'Не вдалося зберегти оцінку'
            });
        }
    }
);


// ==================================================
// ADMIN
// ==================================================


// ---------- SUMMARY ----------

app.get(
    '/api/admin/summary',
    auth,
    admin,
    async (req, res) => {

        try {

            const [
                u,
                r,
                d,
                p,
                a,
                ra
            ] = await Promise.all([

                pool.query(
                    `SELECT
                        COUNT(*)::int count,
                        COUNT(*) FILTER(
                            WHERE active
                        )::int active
                     FROM users`
                ),

                pool.query(
                    `SELECT
                        COUNT(*)::int count,
                        COUNT(*) FILTER(
                            WHERE
                            source='Загальний'
                            AND status='published'
                        )::int published,
                        COUNT(*) FILTER(
                            WHERE status='pending'
                        )::int pending
                     FROM routes`
                ),

                pool.query(
                    `SELECT COUNT(*)::int count
                     FROM districts
                     WHERE active`
                ),

                pool.query(
                    `SELECT COUNT(*)::int count
                     FROM routes
                     WHERE status='pending'`
                ),

                pool.query(
                    `SELECT COUNT(*)::int count
                     FROM audit_log`
                ),

                pool.query(
                    `SELECT COUNT(*)::int count
                     FROM ratings`
                )
            ]);

            res.json({
                users: u.rows[0],
                routes: r.rows[0],
                districts: d.rows[0],
                proposals: p.rows[0],
                audit: a.rows[0],
                ratings: ra.rows[0]
            });

        } catch (e) {

            res.status(500).json({
                error:
                    'Не вдалося отримати статистику'
            });
        }
    }
);


// ---------- USERS ----------

app.get(
    '/api/admin/users',
    auth,
    admin,
    async (req, res) => {

        const q = await pool.query(
            `SELECT
                id,
                name,
                email,
                role,
                active,
                created_at
             FROM users
             ORDER BY created_at DESC`
        );

        res.json({
            users: q.rows
        });
    }
);


app.post(
    '/api/admin/users',
    auth,
    admin,
    async (req, res) => {

        try {

            const name = String(
                req.body?.name || ''
            ).trim();

            const email = String(
                req.body?.email || ''
            ).trim().toLowerCase();

            const password = String(
                req.body?.password || ''
            );

            const role =
                [
                    'courier',
                    'experienced',
                    'admin'
                ].includes(req.body?.role)
                    ? req.body.role
                    : 'courier';

            if (
                !name ||
                !email ||
                password.length < 6
            ) {
                return res.status(400).json({
                    error:
                        'Ім’я, e-mail і пароль 6+ символів обов’язкові'
                });
            }

            const hash =
                await bcrypt.hash(
                    password,
                    12
                );

            const q = await pool.query(
                `INSERT INTO users
                (name,email,password_hash,role)
                VALUES($1,$2,$3,$4)
                RETURNING
                    id,
                    name,
                    email,
                    role,
                    active,
                    created_at`,
                [
                    name,
                    email,
                    hash,
                    role
                ]
            );

            await audit(
                req.user,
                'create',
                'user',
                q.rows[0].id,
                { role }
            );

            res.json({
                user: q.rows[0]
            });

        } catch (e) {

            res.status(
                e.code === '23505'
                    ? 409
                    : 500
            ).json({
                error:
                    e.code === '23505'
                        ? 'Такий e-mail вже існує'
                        : 'Не вдалося створити користувача'
            });
        }
    }
);


app.patch(
    '/api/admin/users/:id',
    auth,
    admin,
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);

            if (!Number.isFinite(id)) {
                return res.status(400).json({
                    error: 'Невірний ID'
                });
            }

            const fields = [];
            const vals = [];
            let i = 1;

            if (req.body.name !== undefined) {
                fields.push(`name=$${i++}`);
                vals.push(
                    String(
                        req.body.name
                    ).trim()
                );
            }

            if (
                req.body.role !== undefined &&
                [
                    'courier',
                    'experienced',
                    'admin'
                ].includes(req.body.role)
            ) {
                fields.push(`role=$${i++}`);
                vals.push(req.body.role);
            }

            if (
                req.body.active !== undefined
            ) {
                fields.push(`active=$${i++}`);
                vals.push(
                    !!req.body.active
                );
            }

            if (req.body.password) {

                if (
                    String(
                        req.body.password
                    ).length < 6
                ) {
                    return res.status(400).json({
                        error:
                            'Пароль мінімум 6 символів'
                    });
                }

                fields.push(
                    `password_hash=$${i++}`
                );

                vals.push(
                    await bcrypt.hash(
                        String(
                            req.body.password
                        ),
                        12
                    )
                );
            }

            if (!fields.length) {
                return res.status(400).json({
                    error: 'Немає змін'
                });
            }

            vals.push(id);

            const q = await pool.query(
                `UPDATE users
                 SET ${fields.join(',')}
                 WHERE id=$${i}
                 RETURNING
                    id,
                    name,
                    email,
                    role,
                    active,
                    created_at`,
                vals
            );

            if (!q.rowCount) {
                return res.status(404).json({
                    error:
                        'Користувача не знайдено'
                });
            }

            await audit(
                req.user,
                'update',
                'user',
                id,
                req.body
            );

            res.json({
                user: q.rows[0]
            });

        } catch (e) {

            res.status(500).json({
                error:
                    'Не вдалося змінити користувача'
            });
        }
    }
);


app.delete(
    '/api/admin/users/:id',
    auth,
    admin,
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);

            if (
                id ===
                Number(req.user.id)
            ) {
                return res.status(400).json({
                    error:
                        'Не можна видалити свій акаунт'
                });
            }

            const q = await pool.query(
                `DELETE FROM users
                 WHERE id=$1
                 RETURNING id`,
                [id]
            );

            if (!q.rowCount) {
                return res.status(404).json({
                    error:
                        'Користувача не знайдено'
                });
            }

            await audit(
                req.user,
                'delete',
                'user',
                id
            );

            res.json({
                ok: true
            });

        } catch (e) {

            res.status(500).json({
                error:
                    'Не вдалося видалити користувача'
            });
        }
    }
);


// ---------- ROUTES ----------

app.get(
    '/api/admin/routes',
    auth,
    admin,
    async (req, res) => {

        const q = await pool.query(
            `SELECT
                r.id,
                r.client_id AS "clientId",
                r.owner_id AS "ownerId",
                r.district,
                r.author,
                r.date,
                r.time,
                r.title,
                r.source,
                r.points,
                r.rating_sum AS "ratingSum",
                r.rating_count AS "ratingCount",
                r.status,
                r.created_at AS "createdAt",
                r.updated_at AS "updatedAt",
                u.email AS "ownerEmail"
             FROM routes r
             LEFT JOIN users u
             ON u.id=r.owner_id
             ORDER BY r.updated_at DESC`
        );

        res.json({
            routes: q.rows
        });
    }
);


app.patch(
    '/api/admin/routes/:id',
    auth,
    admin,
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);

            const allowed = [
                'district',
                'author',
                'date',
                'time',
                'title',
                'source',
                'status',
                'points'
            ];

            const fields = [];
            const vals = [];
            let i = 1;

            for (const k of allowed) {

                if (
                    req.body[k] !== undefined
                ) {

                    fields.push(
                        `${k}=$${i++}`
                    );

                    vals.push(
                        k === 'points'
                            ? JSON.stringify(
                                  req.body[k]
                              )
                            : String(
                                  req.body[k]
                              )
                    );
                }
            }

            if (!fields.length) {
                return res.status(400).json({
                    error: 'Немає змін'
                });
            }

            vals.push(id);

            const q = await pool.query(
                `UPDATE routes
                 SET
                    ${fields.join(',')},
                    updated_at=NOW()
                 WHERE id=$${i}
                 RETURNING *`,
                vals
            );

            if (!q.rowCount) {
                return res.status(404).json({
                    error:
                        'Маршрут не знайдено'
                });
            }

            await audit(
                req.user,
                'update',
                'route',
                id,
                req.body
            );

            res.json({
                route: q.rows[0]
            });

        } catch (e) {

            res.status(500).json({
                error:
                    'Не вдалося змінити маршрут'
            });
        }
    }
);


app.delete(
    '/api/admin/routes/:id',
    auth,
    admin,
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);

            const q = await pool.query(
                `DELETE FROM routes
                 WHERE id=$1
                 RETURNING id`,
                [id]
            );

            if (!q.rowCount) {
                return res.status(404).json({
                    error:
                        'Маршрут не знайдено'
                });
            }

            await audit(
                req.user,
                'delete',
                'route',
                id
            );

            res.json({
                ok: true
            });

        } catch (e) {

            res.status(500).json({
                error:
                    'Не вдалося видалити маршрут'
            });
        }
    }
);


app.post(
    '/api/admin/routes',
    auth,
    admin,
    async (req, res) => {

        try {

            const r =
                cleanRoute(
                    req.body || {}
                );

            if (
                !r.district ||
                !r.author
            ) {
                return res.status(400).json({
                    error:
                        'Район і автор обов’язкові'
                });
            }

            const cid =
                r.clientId ||
                'admin-' +
                Date.now();

            const q = await pool.query(
                `INSERT INTO routes
                (
                    client_id,
                    owner_id,
                    district,
                    author,
                    date,
                    time,
                    title,
                    source,
                    points,
                    rating_sum,
                    rating_count,
                    status
                )
                VALUES
                (
                    $1,$2,$3,$4,$5,$6,$7,
                    'Загальний',$8,0,0,'published'
                )
                RETURNING *`,
                [
                    cid,
                    req.user.id,
                    r.district,
                    r.author,
                    r.date,
                    r.time,
                    r.title,
                    JSON.stringify(r.points)
                ]
            );

            await audit(
                req.user,
                'create',
                'route',
                q.rows[0].id,
                {
                    district:
                        r.district
                }
            );

            res.json({
                route: q.rows[0]
            });

        } catch (e) {

            res.status(500).json({
                error:
                    'Не вдалося створити маршрут'
            });
        }
    }
);


// ---------- DISTRICTS ----------

app.get(
    '/api/admin/districts',
    auth,
    admin,
    async (req, res) => {

        const q = await pool.query(
            `SELECT *
             FROM districts
             ORDER BY
                CASE
                    WHEN number ~ '^[0-9]+$'
                    THEN number::int
                    ELSE 999999999
                END,
                number`
        );

        res.json({
            districts: q.rows
        });
    }
);


app.post(
    '/api/admin/districts',
    auth,
    admin,
    async (req, res) => {

        try {

            const number =
                String(
                    req.body?.number || ''
                ).trim();

            const name =
                String(
                    req.body?.name || ''
                ).trim();

            const notes =
                String(
                    req.body?.notes || ''
                ).trim();

            if (!number) {
                return res.status(400).json({
                    error:
                        'Номер району обов’язковий'
                });
            }

            const q = await pool.query(
                `INSERT INTO districts
                (number,name,notes)
                VALUES($1,$2,$3)
                RETURNING *`,
                [
                    number,
                    name,
                    notes
                ]
            );

            await audit(
                req.user,
                'create',
                'district',
                q.rows[0].id,
                { number }
            );

            res.json({
                district: q.rows[0]
            });

        } catch (e) {

            res.status(
                e.code === '23505'
                    ? 409
                    : 500
            ).json({
                error:
                    e.code === '23505'
                        ? 'Такий район вже існує'
                        : 'Не вдалося створити район'
            });
        }
    }
);


app.patch(
    '/api/admin/districts/:id',
    auth,
    admin,
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);

            const q = await pool.query(
                `UPDATE districts
                 SET
                    number=COALESCE(
                        $1,number
                    ),
                    name=COALESCE(
                        $2,name
                    ),
                    notes=COALESCE(
                        $3,notes
                    ),
                    active=COALESCE(
                        $4,active
                    ),
                    updated_at=NOW()
                 WHERE id=$5
                 RETURNING *`,
                [
                    req.body.number,
                    req.body.name,
                    req.body.notes,
                    req.body.active,
                    id
                ]
            );

            if (!q.rowCount) {
                return res.status(404).json({
                    error:
                        'Район не знайдено'
                });
            }

            await audit(
                req.user,
                'update',
                'district',
                id,
                req.body
            );

            res.json({
                district: q.rows[0]
            });

        } catch (e) {

            res.status(500).json({
                error:
                    'Не вдалося змінити район'
            });
        }
    }
);


app.delete(
    '/api/admin/districts/:id',
    auth,
    admin,
    async (req, res) => {

        const id =
            Number(req.params.id);

        await pool.query(
            'DELETE FROM districts WHERE id=$1',
            [id]
        );

        await audit(
            req.user,
            'delete',
            'district',
            id
        );

        res.json({
            ok: true
        });
    }
);


// ---------- RATINGS ----------

app.get(
    '/api/admin/ratings',
    auth,
    admin,
    async (req, res) => {

        const q = await pool.query(
            `SELECT
                rt.id,
                rt.stars,
                rt.comment,
                rt.created_at AS "createdAt",
                r.id AS "routeId",
                r.district,
                r.author,
                u.name AS "userName",
                u.email AS "userEmail"
             FROM ratings rt
             JOIN routes r
             ON r.id=rt.route_id
             JOIN users u
             ON u.id=rt.user_id
             ORDER BY rt.created_at DESC`
        );

        res.json({
            ratings: q.rows
        });
    }
);


app.delete(
    '/api/admin/ratings/:id',
    auth,
    admin,
    async (req, res) => {

        const id =
            Number(req.params.id);

        const q = await pool.query(
            `DELETE FROM ratings
             WHERE id=$1
             RETURNING route_id`,
            [id]
        );

        if (!q.rowCount) {
            return res.status(404).json({
                error:
                    'Оцінку не знайдено'
            });
        }

        const routeId =
            q.rows[0].route_id;

        await pool.query(
            `UPDATE routes
             SET
                rating_sum=(
                    SELECT COALESCE(
                        SUM(stars),0
                    )
                    FROM ratings
                    WHERE route_id=$1
                ),
                rating_count=(
                    SELECT COUNT(*)
                    FROM ratings
                    WHERE route_id=$1
                )
             WHERE id=$1`,
            [routeId]
        );

        await audit(
            req.user,
            'delete',
            'rating',
            id
        );

        res.json({
            ok: true
        });
    }
);


// ---------- AUDIT ----------

app.get(
    '/api/admin/audit',
    auth,
    admin,
    async (req, res) => {

        const q = await pool.query(
            `SELECT
                a.id,
                a.action,
                a.entity,
                a.entity_id AS "entityId",
                a.details,
                a.created_at AS "createdAt",
                u.name AS "userName",
                u.email AS "userEmail"
             FROM audit_log a
             LEFT JOIN users u
             ON u.id=a.user_id
             ORDER BY a.created_at DESC
             LIMIT 500`
        );

        res.json({
            logs: q.rows
        });
    }
);


// ---------- EXPORT / BACKUP ----------

app.get(
    '/api/admin/export',
    auth,
    admin,
    async (req, res) => {

        const [
            u,
            r,
            d,
            ra,
            a
        ] = await Promise.all([

            pool.query(
                `SELECT
                    id,
                    name,
                    email,
                    role,
                    active,
                    created_at
                 FROM users`
            ),

            pool.query(
                `SELECT *
                 FROM routes`
            ),

            pool.query(
                `SELECT *
                 FROM districts`
            ),

            pool.query(
                `SELECT *
                 FROM ratings`
            ),

            pool.query(
                `SELECT *
                 FROM audit_log`
            )
        ]);

        res.setHeader(
            'Content-Disposition',
            'attachment; filename="marshrutnyi-nova-poshta-backup.json"'
        );

        res.json({
            exportedAt:
                new Date().toISOString(),

            users: u.rows,
            routes: r.rows,
            districts: d.rows,
            ratings: ra.rows,
            audit: a.rows
        });
    }
);


// =========================
// ADMIN PAGE
// =========================

app.get('/admin', (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            'public',
            'admin.html'
        )
    );
});


// =========================
// START
// =========================

init()
    .then(() => {

        app.listen(
            PORT,
            '0.0.0.0',
            () => {
                console.log(
                    'API ready on ' + PORT
                );
            }
        );

    })
    .catch(e => {

        console.error(e);
        process.exit(1);

    });
