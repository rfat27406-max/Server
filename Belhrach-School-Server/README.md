# Belhrach School — API Server (Cloudflare Workers + D1)

## لماذا هذا الاستضافة؟
أوصي بـ **Cloudflare Workers + D1** لهذا المشروع: الخادم يعمل بنموذج serverless دون خادم تقليدي يحتاج إلى إبقاء جهاز شغال، ولا يدخل في وضع النوم مثل بعض الخطط المجانية لخدمات الاستضافة التقليدية. لا يمكن ضمان 100% عدم الانقطاع، لكن Cloudflare تدير البنية والتوسع والتوافر. قاعدة D1 تحفظ الطلبات بشكل دائم.

## المتطلبات
- حساب Cloudflare.
- Node.js LTS وnpm.
- تثبيت Wrangler عبر `npm install`.

## الإعداد والنشر
1. أنشئ مستودع GitHub مستقل وارفع ملفات هذا المجلد.
2. في الطرفية:
   ```bash
   npm install
   npx wrangler login
   npx wrangler d1 create belhrach-school
   ```
3. انسخ `database_id` الذي يظهر، وضعه مكان `REPLACE_WITH_D1_DATABASE_ID` في `wrangler.toml`.
4. أنشئ الجداول:
   ```bash
   npx wrangler d1 execute belhrach-school --remote --file=./schema.sql
   ```
5. اضبط أسماء نطاقات Pages الحقيقية في `STUDENT_ORIGIN` و`ADMIN_ORIGIN` داخل `wrangler.toml`.
6. أضف الأسرار إلى Worker (لا تضعها في GitHub):
   ```bash
   npx wrangler secret put ADMIN_ACCESS_CODE
   npx wrangler secret put ADMIN_SECURITY_ANSWER
   npx wrangler secret put SESSION_SECRET
   ```
   استخدم الكود القوي المخصص الذي استلمته في المحادثة، أو ولّد كوداً جديداً. إجابة سؤال التحقق المحددة: `كيف يعمل`.
   أنشئ SESSION_SECRET عشوائياً قوياً (32 بايت على الأقل)، مثلاً باستخدام:
   ```bash
   node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
   ```
7. انشر:
   ```bash
   npx wrangler deploy
   ```
8. انسخ رابط Worker وضعه في `config.js` بمشروعي الطالب والإدارة، ثم أعد نشر Pages.

## الحماية المضمنة في النسخة الأولية
- لا توجد أسرار إدارية في الواجهة الأمامية.
- كود الإدارة وإجابة سؤال التحقق محفوظان كـ Worker Secrets.
- جلسة الإدارة موقعة بـ HMAC، بمدة 8 ساعات، داخل Cookie من نوع HttpOnly + Secure + SameSite=Strict.
- تحقق من Origin للعمليات الإدارية، وCORS يسمح بنطاقي الواجهتين المحددين فقط.
- تحديد محاولات الدخول إلى 5 محاولات لكل عنوان IP خلال 15 دقيقة.
- استخدام SHA-256 لتخزين رمز متابعة التلميذ بدلاً من الرمز نفسه.
- استعلامات D1 مجهزة Prepared Statements، والتحقق من المدخلات، وعدم إظهار تفاصيل الأخطاء الداخلية.
- لا تخزن الواجهة كلمة مرور التلميذ؛ رمز متابعة عشوائي فقط.

## تنبيهات قبل الإطلاق الحقيقي
- سؤال "من هو أنا؟" وإجابته "كيف يعمل" كما حددته أنت، لكنه ليس عاملاً سرياً قوياً إذا كان معروفاً للآخرين؛ اعتبره خطوة إضافية فقط، واعتمد أساساً على كود عشوائي طويل.
- لا ترفع الأسرار أو ملفات `.dev.vars` إلى GitHub.
- فعّل حماية الحساب عبر MFA، واستخدم نطاقاً مخصصاً، وراجع سجلات Cloudflare.
- أضف لاحقاً إشعارات عند وصول الطلب، وسياسة خصوصية ونسخاً احتياطية واختبارات أمنية.
- النسخة الحالية MVP وليست تدقيقاً أمنياً مستقلاً أو ضماناً مطلقاً ضد الاختراق.
