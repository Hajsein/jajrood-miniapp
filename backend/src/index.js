/**
 * jajrood mini-app backend — Cloudflare Worker
 * ------------------------------------------------------------------
 * این فایل تنها فایل کد بک‌اند است (بدون نیاز به build/bundler).
 * دیتابیس: Cloudflare D1 (باینددشده با نام env.DB — تنظیمش در wrangler.toml)
 *
 * متغیرهای محیطی مورد نیاز (در wrangler.toml یا با wrangler secret put):
 *   BOT_TOKEN      - توکن بات تلگرام (برای اعتبارسنجی initData و ارسال پیام)
 *   ADMIN_CHAT_ID  - آیدی عددی چت تلگرام کارفرما/ادمین (برای دریافت اعلان سفارش جدید)
 *   ADMIN_KEY      - یک رشته‌ی رمز دلخواه برای محافظت از endpoint های ادمین
 *
 * تمام پاسخ‌ها JSON هستند. خطاها با کد HTTP مناسب + {error: "..."} برمی‌گردند.
 * ------------------------------------------------------------------
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Telegram-Init-Data, X-Admin-Key',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function errorResponse(message, status = 400) {
  return json({ error: message }, status);
}

// ------------------------------------------------------------------
// اعتبارسنجی initData تلگرام — طبق الگوریتم رسمی تلگرام:
// https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
// ------------------------------------------------------------------
async function verifyTelegramInitData(initData, botToken) {
  if (!initData) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');

  const pairs = [];
  for (const [key, value] of params.entries()) pairs.push(`${key}=${value}`);
  pairs.sort();
  const dataCheckString = pairs.join('\n');

  const enc = new TextEncoder();
  // secret_key = HMAC_SHA256(key="WebAppData", message=bot_token)
  const secretKeyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode('WebAppData'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const secretKeyBytes = await crypto.subtle.sign('HMAC', secretKeyMaterial, enc.encode(botToken));

  // computed_hash = HMAC_SHA256(key=secret_key, message=data_check_string)
  const hmacKey = await crypto.subtle.importKey(
    'raw', secretKeyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', hmacKey, enc.encode(dataCheckString));
  const computedHash = [...new Uint8Array(signature)].map(b => b.toString(16).padStart(2, '0')).join('');

  if (computedHash !== hash) return null;

  const userRaw = params.get('user');
  if (!userRaw) return null;
  try {
    return JSON.parse(userRaw); // { id, first_name, last_name, username, ... }
  } catch {
    return null;
  }
}

function genTrackingCode() {
  const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // بدون حروف/ارقام مشابه‌الشکل
  let code = 'JJ-';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

async function notifyAdmin(env, text) {
  if (!env.BOT_TOKEN || !env.ADMIN_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: env.ADMIN_CHAT_ID, text, parse_mode: 'HTML' }),
    });
  } catch (e) {
    console.error('notifyAdmin failed', e);
  }
}

// هر درخواست کاربر (غیر از ادمین) باید initData معتبر تلگرام همراهش باشه
async function requireTelegramUser(request, env) {
  const initData = request.headers.get('X-Telegram-Init-Data');
  const user = await verifyTelegramInitData(initData, env.BOT_TOKEN);
  return user; // null یعنی نامعتبر
}

function requireAdmin(request, env) {
  const key = request.headers.get('X-Admin-Key');
  return key && env.ADMIN_KEY && key === env.ADMIN_KEY;
}

// ------------------------------------------------------------------
// روت‌ها
// ------------------------------------------------------------------
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // ---------- ثبت‌نام / به‌روزرسانی فروشگاه ----------
      if (path === '/api/shops' && request.method === 'POST') {
        const user = await requireTelegramUser(request, env);
        if (!user) return errorResponse('اعتبارسنجی تلگرام ناموفق بود', 401);

        const body = await request.json();
        const { phone, shop_name, shop_address, full_name, contact_phone } = body;
        if (!phone || !shop_name || !shop_address || !full_name) {
          return errorResponse('فیلدهای ضروری ناقص است');
        }

        await env.DB.prepare(
          `INSERT INTO shops (telegram_user_id, phone, shop_name, shop_address, full_name, contact_phone)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(telegram_user_id) DO UPDATE SET
             phone=excluded.phone, shop_name=excluded.shop_name,
             shop_address=excluded.shop_address, full_name=excluded.full_name,
             contact_phone=excluded.contact_phone`
        ).bind(String(user.id), phone, shop_name, shop_address, full_name, contact_phone || phone).run();

        return json({ ok: true });
      }

      // ---------- گرفتن پروفایل فروشگاه فعلی ----------
      if (path === '/api/shops/me' && request.method === 'GET') {
        const user = await requireTelegramUser(request, env);
        if (!user) return errorResponse('اعتبارسنجی تلگرام ناموفق بود', 401);

        const shop = await env.DB.prepare(
          `SELECT * FROM shops WHERE telegram_user_id = ?`
        ).bind(String(user.id)).first();

        return json({ shop: shop || null });
      }

      // ---------- لیست محصولات فعال ----------
      if (path === '/api/products' && request.method === 'GET') {
        const { results } = await env.DB.prepare(
          `SELECT id, name, description, price, category, image_url FROM products WHERE is_active = 1`
        ).all();
        return json({ products: results });
      }

      // ---------- ثبت سفارش جدید ----------
      if (path === '/api/orders' && request.method === 'POST') {
        const user = await requireTelegramUser(request, env);
        if (!user) return errorResponse('اعتبارسنجی تلگرام ناموفق بود', 401);

        const body = await request.json();
        const { items, delivery_time_selected } = body;
        if (!Array.isArray(items) || items.length === 0) {
          return errorResponse('سبد خرید خالی است');
        }

        const shop = await env.DB.prepare(
          `SELECT * FROM shops WHERE telegram_user_id = ?`
        ).bind(String(user.id)).first();
        if (!shop) return errorResponse('ابتدا باید ثبت‌نام فروشگاه انجام شود', 409);

        const subtotal = items.reduce((sum, it) => sum + it.unit_price * it.qty, 0);
        const shipping_cost = subtotal >= 200000 ? 0 : 25000;
        const total = subtotal + shipping_cost;

        let trackingCode = genTrackingCode();
        // تلاش برای یکتا بودن کد رهگیری (به‌ندرت تصادم پیش می‌آید)
        for (let i = 0; i < 5; i++) {
          const exists = await env.DB.prepare(`SELECT id FROM orders WHERE tracking_code = ?`).bind(trackingCode).first();
          if (!exists) break;
          trackingCode = genTrackingCode();
        }

        const orderInsert = await env.DB.prepare(
          `INSERT INTO orders (tracking_code, shop_id, subtotal, shipping_cost, total, delivery_time_selected, status)
           VALUES (?, ?, ?, ?, ?, ?, 'pending')`
        ).bind(trackingCode, shop.id, subtotal, shipping_cost, total, delivery_time_selected || null).run();

        const orderId = orderInsert.meta.last_row_id;

        for (const it of items) {
          await env.DB.prepare(
            `INSERT INTO order_items (order_id, product_id, product_name, qty, unit_price)
             VALUES (?, ?, ?, ?, ?)`
          ).bind(orderId, it.product_id || null, it.product_name, it.qty, it.unit_price).run();
        }

        const itemsText = items.map(it => `${it.product_name} × ${it.qty}`).join('\n');
        await notifyAdmin(env,
          `🆕 <b>سفارش جدید</b> #${trackingCode}\n` +
          `فروشگاه: ${shop.shop_name}\n` +
          `آدرس: ${shop.shop_address}\n` +
          `تماس: ${shop.contact_phone || shop.phone}\n\n` +
          `${itemsText}\n\n` +
          `مبلغ کل: ${total.toLocaleString('en-US')} تومان`
        );

        return json({ ok: true, tracking_code: trackingCode, total });
      }

      // ---------- لیست سفارش‌های همان کاربر ----------
      if (path === '/api/orders' && request.method === 'GET') {
        const user = await requireTelegramUser(request, env);
        if (!user) return errorResponse('اعتبارسنجی تلگرام ناموفق بود', 401);

        const shop = await env.DB.prepare(
          `SELECT id FROM shops WHERE telegram_user_id = ?`
        ).bind(String(user.id)).first();
        if (!shop) return json({ orders: [] });

        const { results } = await env.DB.prepare(
          `SELECT * FROM orders WHERE shop_id = ? ORDER BY created_at DESC LIMIT 50`
        ).bind(shop.id).all();

        for (const order of results) {
          const items = await env.DB.prepare(
            `SELECT product_name, qty, unit_price FROM order_items WHERE order_id = ?`
          ).bind(order.id).all();
          order.items = items.results;
        }

        return json({ orders: results });
      }

      // ---------- [ادمین] تغییر وضعیت سفارش (تحویل/مرجوعی + علت) ----------
      if (path.match(/^\/api\/admin\/orders\/\d+\/status$/) && request.method === 'PATCH') {
        if (!requireAdmin(request, env)) return errorResponse('دسترسی غیرمجاز', 401);

        const orderId = path.split('/')[4];
        const body = await request.json();
        const { status, return_reason } = body;
        const allowed = ['pending', 'confirmed', 'shipping', 'delivered', 'returned', 'cancelled'];
        if (!allowed.includes(status)) return errorResponse('وضعیت نامعتبر است');

        await env.DB.prepare(
          `UPDATE orders SET status = ?, return_reason = ?, updated_at = datetime('now') WHERE id = ?`
        ).bind(status, return_reason || null, orderId).run();

        return json({ ok: true });
      }

      // ---------- [ادمین] لیست همه‌ی سفارش‌ها ----------
      if (path === '/api/admin/orders' && request.method === 'GET') {
        if (!requireAdmin(request, env)) return errorResponse('دسترسی غیرمجاز', 401);

        const { results } = await env.DB.prepare(
          `SELECT o.*, s.shop_name, s.shop_address, s.contact_phone
           FROM orders o JOIN shops s ON s.id = o.shop_id
           ORDER BY o.created_at DESC LIMIT 200`
        ).all();

        return json({ orders: results });
      }

      // ---------- ثبت تیکت پشتیبانی ----------
      if (path === '/api/tickets' && request.method === 'POST') {
        const user = await requireTelegramUser(request, env);
        if (!user) return errorResponse('اعتبارسنجی تلگرام ناموفق بود', 401);

        const body = await request.json();
        const { subject, message, order_id } = body;
        if (!subject || !message) return errorResponse('موضوع و پیام الزامی است');

        const shop = await env.DB.prepare(
          `SELECT id FROM shops WHERE telegram_user_id = ?`
        ).bind(String(user.id)).first();
        if (!shop) return errorResponse('ابتدا باید ثبت‌نام فروشگاه انجام شود', 409);

        const ticketInsert = await env.DB.prepare(
          `INSERT INTO tickets (shop_id, order_id, subject, status) VALUES (?, ?, ?, 'open')`
        ).bind(shop.id, order_id || null, subject).run();
        const ticketId = ticketInsert.meta.last_row_id;

        await env.DB.prepare(
          `INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, 'shop', ?)`
        ).bind(ticketId, message).run();

        await notifyAdmin(env, `🎫 <b>تیکت جدید</b>\nموضوع: ${subject}\n${message}`);

        return json({ ok: true, ticket_id: ticketId });
      }

      // ---------- لیست تیکت‌های همان کاربر + پیام‌ها ----------
      if (path === '/api/tickets' && request.method === 'GET') {
        const user = await requireTelegramUser(request, env);
        if (!user) return errorResponse('اعتبارسنجی تلگرام ناموفق بود', 401);

        const shop = await env.DB.prepare(
          `SELECT id FROM shops WHERE telegram_user_id = ?`
        ).bind(String(user.id)).first();
        if (!shop) return json({ tickets: [] });

        const { results } = await env.DB.prepare(
          `SELECT * FROM tickets WHERE shop_id = ? ORDER BY created_at DESC`
        ).bind(shop.id).all();

        for (const t of results) {
          const msgs = await env.DB.prepare(
            `SELECT sender, message, created_at FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC`
          ).bind(t.id).all();
          t.messages = msgs.results;
        }

        return json({ tickets: results });
      }

      // ---------- افزودن پیام به تیکت (هم کاربر، هم ادمین) ----------
      if (path.match(/^\/api\/tickets\/\d+\/messages$/) && request.method === 'POST') {
        const ticketId = path.split('/')[3];
        const body = await request.json();
        const isAdmin = requireAdmin(request, env);

        if (isAdmin) {
          await env.DB.prepare(
            `INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, 'admin', ?)`
          ).bind(ticketId, body.message).run();
          await env.DB.prepare(`UPDATE tickets SET status = 'answered' WHERE id = ?`).bind(ticketId).run();
        } else {
          const user = await requireTelegramUser(request, env);
          if (!user) return errorResponse('اعتبارسنجی تلگرام ناموفق بود', 401);
          await env.DB.prepare(
            `INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, 'shop', ?)`
          ).bind(ticketId, body.message).run();
        }

        return json({ ok: true });
      }

      return errorResponse('یافت نشد', 404);
    } catch (err) {
      console.error(err);
      return errorResponse('خطای داخلی سرور: ' + err.message, 500);
    }
  },
};
