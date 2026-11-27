"""Thai explanations of each finding, for report.md with --lang th.

A finding's detail is written in English by the check that found it and stays
as it is in report.json, so tools and searches keep working. When the report
is in Thai, each finding also gets a short Thai line: what the rule means and
what to do. Rules from pgrls and from Supabase's advisors come from outside
this project, so they get a line per source instead of per rule.
"""

from __future__ import annotations

from .model import Finding

RULES: dict[str, str] = {
    # credentials in files
    "supabase_service_role_jwt": "key service_role อยู่ในไฟล์ ใครได้ key นี้ข้าม RLS ได้ทั้งหมด ต้องเปลี่ยน key ทันที แม้ลบจากไฟล์แล้วก็ยังอยู่ในประวัติ git",
    "supabase_local_service_role_jwt": "key service_role ตัวทดลองของ supabase start ใช้ได้เฉพาะเครื่องตัวเอง ไม่อันตรายถ้าไม่ได้ใช้กับระบบจริง",
    "supabase_anon_jwt": "key สาธารณะ (anon) เปิดเผยได้ตามการออกแบบ บันทึกไว้ให้รู้ว่าอยู่ที่ไหน",
    "jwt_token": "พบ JWT ของผู้ใช้ในไฟล์ อาจเป็น session ของคนจริง ควรลบและตรวจว่ามาจากไหน",
    "supabase_secret_key": "secret key ของ Supabase อยู่ในไฟล์ ต้องเพิกถอนและออกใหม่",
    "supabase_publishable_key": "publishable key เปิดเผยได้ตามการออกแบบ บันทึกไว้ให้รู้ว่าอยู่ที่ไหน",
    "supabase_access_token": "access token ระดับบัญชีอยู่ในไฟล์ คุมได้ทุกโปรเจกต์ ต้องลบ token นี้ที่หน้า Access Tokens ทันที",
    "secret_in_public_env_name": "ตัวแปรที่ขึ้นต้นแบบนี้จะถูกส่งไปที่เบราว์เซอร์ แต่ชื่อบอกว่าเป็นความลับ ห้ามใส่ความลับในตัวแปรแบบนี้",
    "jwt_secret_assignment": "JWT secret อยู่ในไฟล์ ใครได้ไปสร้าง token เป็นใครก็ได้ ต้องเปลี่ยนทันที",
    "postgres_url_password": "รหัสผ่านฐานข้อมูลอยู่ใน connection string ในไฟล์ ต้องเปลี่ยนรหัสผ่าน",
    "postgres_url_password_local": "รหัสผ่านของฐานในเครื่องตัวเอง ความเสี่ยงต่ำ แต่ไม่ควรใช้รหัสเดียวกับระบบจริง",
    "postgres_dsn_password": "รหัสผ่านฐานข้อมูลอยู่ในไฟล์ ต้องเปลี่ยนรหัสผ่านและย้ายไปเก็บในตัวแปรสภาพแวดล้อม",
    "database_password_variable": "รหัสผ่านฐานข้อมูลถูกกำหนดค่าไว้ในไฟล์ ต้องเปลี่ยนรหัสผ่านและย้ายไปเก็บในตัวแปรสภาพแวดล้อมหรือ secret",
    "private_key_block": "private key อยู่ในไฟล์ ต้องออก key ใหม่และเพิกถอนตัวเดิม",
    "brevo_api_key": "API key ของ Brevo (ส่งอีเมล) อยู่ในไฟล์ ต้องเพิกถอนและออกใหม่",
    "resend_api_key": "API key ของ Resend (ส่งอีเมล) อยู่ในไฟล์ ต้องเพิกถอนและออกใหม่",
    "openai_api_key": "พบ API key ของ OpenAI ในไฟล์ ใครได้ไปก็ใช้เงินในบัญชีได้ ให้เพิกถอนที่ผู้ให้บริการแล้วออกใหม่ และเก็บไว้ฝั่งเซิร์ฟเวอร์เท่านั้น",
    "anthropic_api_key": "พบ API key ของ Anthropic ในไฟล์ ใครได้ไปก็ใช้เงินในบัญชีได้ ให้เพิกถอนแล้วออกใหม่ และเก็บไว้ฝั่งเซิร์ฟเวอร์เท่านั้น",
    "aws_access_key_id": "พบรหัส access key ของ AWS ในไฟล์ ถ้า secret key คู่กันหลุดด้วยจะเข้าบัญชี AWS ได้ ให้ตรวจและหมุนเวียน key",
    "github_token": "พบ token ของ GitHub ในไฟล์ ใครได้ไปก็เข้า repo ตามสิทธิ์ของ token ได้ ให้เพิกถอนทันที",
    "sendgrid_api_key": "พบ API key ของ SendGrid ในไฟล์ ใครได้ไปก็ส่งอีเมลในชื่อเราได้ ให้เพิกถอนแล้วออกใหม่",
    "google_api_key": "พบ API key ของ Google ในไฟล์ ใช้กับ Firebase หรือ Maps ได้ถ้าจำกัดการใช้ไว้ใน Google Cloud แต่ถ้าใช้กับ Gemini หรือบริการคิดเงิน ถือเป็นความลับ",
    "stripe_live_key": "secret key ของ Stripe ตัวจริงอยู่ในไฟล์ ต้องเพิกถอนทันที",
    # functions
    "secdef_public_execute": "ฟังก์ชัน SECURITY DEFINER ที่ทุก role เรียกได้ (ผ่าน PUBLIC) ทำงานด้วยสิทธิ์เจ้าของ ข้าม RLS ได้ ถอนสิทธิ์จาก PUBLIC และ anon",
    "secdef_anon_granted": "ฟังก์ชัน SECURITY DEFINER ที่ให้ผู้ไม่ล็อกอินเรียกได้ตรง ๆ ถ้าไม่ได้ตั้งใจให้ถอนสิทธิ์จาก anon",
    "secdef_anon_not_revoked": "ถอนสิทธิ์จาก PUBLIC แล้วแต่ anon ยังได้สิทธิ์จากค่าตั้งต้นของ Supabase ต้องถอนจาก anon ด้วย",
    "secdef_behind_schema_usage": "ผู้ไม่ล็อกอินมีสิทธิ์เรียกฟังก์ชัน SECURITY DEFINER นี้ แต่เข้า schema ของมันไม่ได้ จึงยังเรียกไม่ถึง สิ่งเดียวที่กันอยู่คือสิทธิ์เข้า schema ถ้ามีการเปิดสิทธิ์นั้น ฟังก์ชันกลุ่มนี้จะเปิดพร้อมกันทั้งหมด ควรถอน EXECUTE จาก PUBLIC และ anon ด้วย",
    "secdef_anon_executable": "ผู้ไม่ล็อกอินเรียกฟังก์ชัน SECURITY DEFINER นี้ได้ ถ้าไม่ได้ตั้งใจให้ถอนสิทธิ์ ถ้าตั้งใจให้อ่านโค้ดแล้วใส่ใน expected_anon_functions",
    "secdef_trusts_current_user": "ด่านตรวจในฟังก์ชันเช็ก current_user ซึ่งในฟังก์ชัน SECURITY DEFINER คือเจ้าของฟังก์ชันเสมอ ด่านจึงปล่อยทุกคนผ่าน ใช้ auth.uid() หรือ session_user แทน",
    "secdef_no_search_path": "ฟังก์ชัน SECURITY DEFINER ไม่ได้ตรึง search_path อาจถูกหลอกให้เรียกฟังก์ชันปลอม ใส่ SET search_path = ''",
    "expected_anon_function_missing": "รายการที่ประกาศว่าผู้ไม่ล็อกอินเรียกได้ มีฟังก์ชันที่ไม่มีแล้วหรือถูกปิดแล้ว ให้ลบออกจากรายการ",
    "default_function_privileges": "ฟังก์ชันใหม่ที่สร้างใน schema นี้จะเปิดให้ role ของ API เรียกได้อัตโนมัติ migration ที่ลืมถอนสิทธิ์จะเปิดฟังก์ชันออกไปทันที",
    "default_function_privileges_platform": "ค่าตั้งต้นของ role ของแพลตฟอร์ม โครงการแก้เองไม่ได้ บันทึกไว้ให้รู้",
    # tables
    "default_table_privileges": "ตารางใหม่ที่สร้างใน schema นี้จะให้สิทธิ์ role ของ API อัตโนมัติ ถ้าลืมเปิด RLS ตารางจะเปิดออกไปทันที",
    "update_without_select": "มี policy ให้แก้ไขแต่ไม่มี policy ให้อ่าน การแก้ไขจะไม่โดนแถวใดเลยโดยไม่แจ้ง error",
    "auth_role_deprecated": "policy ใช้ auth.role() ซึ่งเลิกใช้แล้ว ให้ระบุ role ในส่วน TO ของ policy แทน",
    "anon_write_without_rls": "ผู้ไม่ล็อกอินเขียนตารางนี้ได้ และไม่มี RLS กั้น (หรือเป็น view ที่รันด้วยสิทธิ์เจ้าของ) ต้องเปิด RLS หรือถอนสิทธิ์ทันที",
    "authenticated_write_without_rls": "ผู้ล็อกอินทุกคนเขียนตารางนี้ได้ และไม่มี RLS กั้น ต้องเปิด RLS หรือถอนสิทธิ์",
    "anon_write_undeclared": "ผู้ไม่ล็อกอินมีสิทธิ์เขียนตารางนี้ที่ไม่ได้ประกาศไว้ ตอนนี้ RLS เป็นด่านเดียว ถ้าเว็บไม่ได้ใช้ให้ถอนสิทธิ์",
    "authenticated_write_undeclared": "ผู้ล็อกอินมีสิทธิ์เขียนตารางนี้ที่ไม่ได้ประกาศไว้ ถ้าเว็บไม่ได้ใช้ให้ถอนสิทธิ์ ถ้าใช้ให้ตรวจ policy แล้วประกาศ",
    "anon_writes_not_declared": "ผู้ไม่ล็อกอินมีสิทธิ์เขียนหลายตาราง และยังไม่ได้ประกาศว่าเว็บต้องใช้ตารางไหน ให้ประกาศ expected_table_writes แล้วถอนที่เหลือ",
    "authenticated_writes_not_declared": "ผู้ล็อกอินมีสิทธิ์เขียนหลายตาราง และยังไม่ได้ประกาศว่าเว็บต้องใช้ตารางไหน ให้ประกาศ expected_table_writes",
    "authenticated_truncate": "ผู้ใช้ที่ล็อกอินมีสิทธิ์ล้างตาราง (TRUNCATE) ซึ่งไม่ผ่าน RLS Data API ไม่ใช้สิทธิ์นี้ ให้ถอนพร้อม REFERENCES, TRIGGER และ MAINTAIN",
    "anon_unused_table_privileges": "ผู้ไม่ล็อกอินถือ REFERENCES, TRIGGER หรือ MAINTAIN ซึ่ง Data API ไม่ใช้ ติดมากับค่าตั้งต้นของ schema ให้ถอนพร้อม TRUNCATE",
    "authenticated_unused_table_privileges": "ผู้ใช้ที่ล็อกอินถือ REFERENCES, TRIGGER หรือ MAINTAIN ซึ่ง Data API ไม่ใช้ ติดมากับค่าตั้งต้นของ schema ให้ถอนพร้อม TRUNCATE",
    "extension_in_public": "extension ติดตั้งอยู่ใน schema ที่ตรวจ (มักเป็น public) และเป็นของ role ของแพลตฟอร์ม ตารางและฟังก์ชันของมันได้สิทธิ์ให้ anon และ authenticated ที่โครงการถอนเองไม่ได้ ย้ายไป schema extensions",
    "update_all_columns": "role ของ API แก้ได้ทุกคอลัมน์ของตารางที่นโยบายให้แก้ RLS จำกัดแถว ไม่จำกัดคอลัมน์ ให้ GRANT UPDATE เฉพาะคอลัมน์ที่หน้าเว็บแก้จริง หรือใช้ทริกเกอร์คืนค่าคอลัมน์ที่ห้ามแก้ ดูก่อนว่านโยบายให้ใครแก้บ้าง",
    "anon_truncate": "ผู้ไม่ล็อกอินมีสิทธิ์ล้างตาราง (TRUNCATE) ซึ่งไม่ผ่าน RLS ให้ถอนพร้อมสิทธิ์เขียนที่ไม่ใช้",
    "view_runs_as_owner": "view นี้รันด้วยสิทธิ์เจ้าของ RLS ของตารางข้างใต้จึงไม่มีผลกับคนที่อ่านผ่าน view ตั้ง security_invoker = true หรือถอนสิทธิ์อ่าน",
    "schema_usable_but_unchecked": "role ของ API ใช้ schema นี้ได้ แต่ไม่ได้อยู่ในการตรวจ ปกติถ้า policy เรียกฟังก์ชันในนั้น ถ้า Data API เปิด schema นี้ด้วย ให้เพิ่มใน schemas",
    "served_schema_unchecked": "Data API เปิดให้เรียก schema นี้ แต่ไม่ได้อยู่ในการตรวจ เพิ่มใน schemas ของเป้าหมาย",
    "anon_can_read_rows": "ผู้ไม่ล็อกอินอ่านแถวในตารางนี้ได้จริงผ่าน Data API ถ้าไม่ได้ตั้งใจให้แก้ policy หรือถอนสิทธิ์",
    "anon_reachable_unclear": "ตอบไม่ได้แน่ชัดว่าผู้ไม่ล็อกอินอ่านตารางนี้ได้หรือไม่ ให้ตรวจด้วยมือ",
    # storage
    "storage_bucket_public": "bucket เปิดสาธารณะ ใครมี URL ก็ดาวน์โหลดได้ ถ้าตั้งใจให้ประกาศใน expected_public_buckets",
    "storage_anon_write": "ผู้ไม่ล็อกอินอัปโหลดหรือแก้ไฟล์ใน bucket นี้ได้",
    "storage_anon_read": "bucket เป็นส่วนตัว แต่ policy ให้ผู้ไม่ล็อกอินอ่านและดูรายชื่อไฟล์ได้",
    "storage_no_upload_limits": "bucket ไม่จำกัดขนาดและชนิดไฟล์ ใส่ขนาดสูงสุดและชนิดไฟล์ที่ยอมรับ",
    "storage_policy_every_bucket": "policy ของ storage ไม่ระบุ bucket จึงมีผลกับทุก bucket รวม bucket ที่จะสร้างในอนาคต",
    "storage_upsert_incomplete": "อัปโหลดไฟล์ใหม่ได้แต่แทนที่ไฟล์เดิมไม่ได้ เพราะขาด policy SELECT หรือ UPDATE",
    "storage_bucket_upsert_incomplete": "ผู้ล็อกอินอัปโหลดใน bucket นี้ได้แต่แทนที่ไฟล์ไม่ได้ เพิ่ม policy SELECT และ UPDATE ของ bucket นี้",
    "expected_public_bucket_missing": "รายการ bucket สาธารณะที่ประกาศไว้ มี bucket ที่ไม่มีแล้วหรือไม่ได้เปิด ให้ลบออกจากรายการ",
    # extensions and realtime
    "edge_open_to_anyone": "Edge Function นี้ปิดการตรวจ JWT และไม่พบการตรวจผู้เรียกในโค้ด ใครรู้ที่อยู่ก็เรียกได้ ให้ตรวจ JWT รหัสลับร่วม หรือลายเซ็น webhook ในฟังก์ชัน หรือเปิด verify_jwt",
    "edge_verify_jwt_off": "Edge Function นี้ปิดการตรวจ JWT แต่ดูเหมือนตรวจผู้เรียกเอง ซึ่งเป็นรูปแบบปกติของ webhook ให้ยืนยันว่าทุกเส้นทางในฟังก์ชันผ่านการตรวจ",
    "edge_service_role_no_caller_check": "Edge Function นี้ใช้ service role key ซึ่งข้าม RLS แต่ไม่พบการตรวจว่าผู้เรียกเป็นใคร ผู้ล็อกอินทุกคนหรือผู้ถือ anon key อาจสั่งให้ทำงานด้วยสิทธิ์เต็ม ให้ตรวจตัวผู้เรียกและสิทธิ์ก่อนทำงาน",
    "edge_cors_any_origin": "Edge Function นี้ตอบเบราว์เซอร์จากทุกเว็บไซต์ (Access-Control-Allow-Origin: *) ให้ระบุเฉพาะที่อยู่เว็บของเราเอง เว้นแต่ตั้งใจให้ทุกเว็บเรียกได้",
    "secdef_takes_user_id": "ฟังก์ชันสิทธิ์เจ้าของ (ข้าม RLS) นี้รับ user id จากผู้เรียก และไม่พบว่าถามว่าใครเป็นผู้เรียก ผู้เรียกอาจส่ง id ของคนอื่นเพื่ออ่านหรือแก้ข้อมูลของคนนั้น ให้อ่านฟังก์ชัน แล้วใช้ auth.uid() ข้างในหรือตรวจว่า id เป็นของผู้เรียก",
    "policy_always_true": "policy สำหรับเขียนนี้ไม่มีเงื่อนไข (true) ทุกคนที่ policy ครอบคลุมจึงเพิ่ม แก้ หรือลบได้ทุกแถว แทบไม่มีกรณีที่ถูกต้อง ให้ใส่เงื่อนไข",
    "policy_read_always_true": "policy สำหรับอ่านนี้ไม่มีเงื่อนไข (true) ทุกคนที่ policy ครอบคลุมจึงอ่านได้ทุกแถว ใช้ได้ถ้าตั้งใจให้ตารางนี้เปิด เช่น ธงฟีเจอร์ ถ้าเป็นข้อมูลของบุคคลหรือหน่วยงาน ให้ใส่เงื่อนไข",
    "policy_any_signed_in": "เงื่อนไขของ policy มีแค่ว่าล็อกอินแล้ว ผู้ใช้ที่ล็อกอินทุกคนจึงได้ทุกแถว ถ้าแถวเป็นของผู้ใช้แต่ละคน ให้เทียบคอลัมน์เจ้าของกับ auth.uid()",
    "extension_net_callable": "role ของ API เรียก pg_net ได้ ฐานข้อมูลจะยิง HTTP ไปที่ไหนก็ได้แทนเขา บน Supabase schema net เป็นของ supabase_admin จึงถอนสิทธิ์เองไม่ได้ ถ้าไม่มีอะไรใช้ pg_net ให้ปิด extension ถ้ามีให้ขอ Supabase ถอนสิทธิ์",
    "extension_vault_reachable": "role ของ API อ่าน Vault หรือเรียกฟังก์ชันของมันได้ ความลับใน Vault อาจหลุด ต้องถอนสิทธิ์ทันที",
    "extension_cron_reachable": "role ของ API ตั้งงานตามเวลาหรืออ่านรายการงานได้ ต้องถอนสิทธิ์",
    "realtime_table_without_rls": "Realtime ส่งการเปลี่ยนแปลงของตารางนี้ออกไป และไม่มี RLS กรอง ทุกคนที่อ่านได้จะเห็นทุกการเปลี่ยนแปลงทันที",
    "realtime_messages_open": "policy ของช่อง Realtime แบบส่วนตัวเปิดให้ทุกคน ใครมี key สาธารณะก็เข้าฟังและส่งข้อความได้",
    "realtime_messages_open_to_signed_in": "ผู้ล็อกอินทุกคนเข้าฟังและส่งข้อความในทุกช่อง Realtime แบบส่วนตัวได้ ถ้าผู้ใช้ต่างหน่วยงานต้องไม่เห็นกัน ให้จำกัดด้วย realtime.topic()",
    "matview_readable_by_api_roles": "materialized view เก็บข้อมูลไว้ล่วงหน้าและมี RLS ไม่ได้ ใครอ่านได้จะเห็นทุกแถวที่เก็บไว้ ถอนสิทธิ์อ่านหรือย้ายออกจาก schema ที่ API เปิด",
    # sign-in settings
    "auth_signup_open": "ใครก็สมัครบัญชีเองได้ ถ้าไม่ได้ตั้งใจให้ปิด หรือประกาศ expected_open_signup",
    "auth_anonymous_signins": "เปิดให้ล็อกอินแบบไม่ระบุตัวตน ผู้ใช้กลุ่มนี้ได้ role authenticated ด้วย policy ต้องแยกให้ออก",
    "auth_email_not_confirmed": "ไม่ต้องยืนยันอีเมลก่อนใช้งาน ใครก็สมัครด้วยอีเมลคนอื่นได้",
    "auth_password_short": "รหัสผ่านขั้นต่ำสั้นเกินไป",
    "auth_leaked_password_check_off": "ไม่ได้เปิดการตรวจรหัสผ่านที่เคยรั่ว",
    "auth_mfa_unavailable": "ยังไม่มีการยืนยันตัวตนสองชั้น",
    "auth_token_long_lived": "token อายุยาวเกินไป ถ้าหลุดจะใช้ได้นาน",
    "auth_refresh_rotation_off": "ไม่ได้หมุน refresh token ถ้าหลุดจะใช้ซ้ำได้",
    "auth_sessions_never_expire": "session ไม่มีวันหมดอายุ",
    "auth_redirect_wildcard": "รายการ redirect กว้างเกินไป อาจถูกพาไปเว็บปลอมพร้อม token",
    "auth_site_url_insecure": "Site URL ไม่ใช่ https",
    "auth_no_captcha": "ไม่มี CAPTCHA กันบอทสมัครหรือเดารหัส",
    "auth_builtin_mailer": "ใช้ระบบส่งอีเมลในตัวของ Supabase ซึ่งจำกัดจำนวน ควรตั้ง SMTP ของตัวเอง",
    # scheduled jobs, backups, logs
    "cron_job_last_run_failed": "งานตั้งเวลารอบล่าสุดล้ม ดูข้อความใน cron.job_run_details",
    "cron_job_failed_in_window": "งานตั้งเวลาเคยล้มในช่วงที่ดู",
    "cron_job_no_recent_run": "งานตั้งเวลาเปิดอยู่แต่ไม่ได้รันในช่วงที่ดู",
    "cron_job_inactive": "งานตั้งเวลาถูกปิดอยู่",
    "expected_cron_job_missing": "งานตั้งเวลาที่ประกาศว่าต้องมี ไม่มีหรือถูกปิด",
    "backup_none": "ไม่มี backup ที่สำเร็จเลย",
    "backup_stale": "backup ล่าสุดเก่าเกิน 48 ชั่วโมง",
    "backup_last_failed": "backup รอบล่าสุดล้ม",
    "log_server_errors": "มี server error (5xx) ใน 24 ชั่วโมงที่ผ่านมา",
    "log_denied_burst": "มีคำขอถูกปฏิเสธ (401/403) จำนวนมาก อาจเป็น key หมดอายุหรือมีคนลองเจาะ",
    "log_anon_rpc_unexpected": "มีการเรียกฟังก์ชันสำเร็จโดยไม่ล็อกอิน ทั้งที่ไม่ได้อยู่ในรายการที่อนุญาต",
    # database health
    "invalid_index": "index สร้างไม่เสร็จ ถูกอัปเดตทุกครั้งที่เขียนแต่ไม่ได้ใช้ ลบแล้วสร้างใหม่แบบ CONCURRENTLY",
    "table_bloat": "ตารางมีแถวตายสะสมมาก autovacuum ตามไม่ทัน ปรับค่า autovacuum ของตารางนี้",
    "xid_age": "transaction ID เก่าใกล้ขีดจำกัด ถ้าถึงขีด ฐานจะหยุดรับการเขียน ให้ VACUUM (FREEZE) และหาสาเหตุ",
    "idle_in_transaction": "มีเซสชันเปิดธุรกรรมค้างไว้ ล็อกข้อมูลและขวาง vacuum ตั้ง idle_in_transaction_session_timeout",
    "lock_wait": "มีเซสชันรอ lock นาน",
    "connections_near_limit": "การเชื่อมต่อฐานใกล้เต็มเพดาน เมื่อเต็มแล้วผู้ใช้ใหม่จะต่อไม่ได้ ให้ต่อผ่าน pooler แบบ transaction และหาโปรแกรมที่เปิดการเชื่อมต่อค้างไว้",
    "postgres_end_of_life": "Postgres รุ่นหลักนี้หมดหรือใกล้หมดช่วงที่ชุมชนออกตัวแก้ความปลอดภัย ให้วางแผนอัปเกรดเป็นรุ่นหลักที่ใหม่กว่า",
    "extension_update_available": "มี extension ที่เซิร์ฟเวอร์มีรุ่นใหม่กว่าที่ติดตั้ง อ่านบันทึกการเปลี่ยนแปลงของแต่ละตัว แล้วลองอัปเดตบน staging ก่อน",
    "slow_statement": "คำสั่งนี้ช้าโดยเฉลี่ยและถูกเรียกบ่อย อยู่ในกลุ่มที่ใช้เวลารวมมากที่สุด เครื่องมือไม่ได้อ่านข้อความคำสั่ง ให้นำ query id ไปค้นในหน้า Query Performance ของ dashboard",
    "sequence_near_limit": "sequence ใกล้ใช้เลขหมด ถ้าหมดจะเพิ่มแถวไม่ได้ เปลี่ยนเป็น bigint",
    # platform
    "ssl_not_enforced": "ฐานรับการเชื่อมต่อที่ไม่เข้ารหัส เปิดการบังคับ SSL ในหน้าตั้งค่าฐานข้อมูล",
    "database_open_to_every_address": "ต่อฐานตรงได้จากทุก IP รหัสผ่านฐานเป็นด่านเดียว จำกัด IP ที่ต้องใช้",
}

# pgrls rules (pgrls 0.57.1, `pgrls explain`). Short: the English detail beside it has the specifics.
PGRLS: dict[str, str] = {
    "SEC001": "ตารางนี้ไม่ได้เปิด RLS ใครมีสิทธิ์ก็เห็นทุกแถว เปิด RLS แล้วเขียน policy",
    "SEC002": "ไม่ได้ใส่ FORCE ROW LEVEL SECURITY เจ้าของตารางจึงข้าม RLS ได้ ทำให้ทดสอบ policy ผิดพลาดง่าย",
    "SEC003": "policy ให้สิทธิ์ PUBLIC ซึ่งรวมทุก role รวมผู้ไม่ล็อกอิน ระบุ role ให้แคบลง",
    "SEC004": "เงื่อนไขตรวจตัวตนกลับด้าน ทำให้ผู้ไม่ล็อกอินผ่านได้",
    "SEC005": "เงื่อนไขของ policy ไม่อ้างคอลัมน์ใดของตาราง จึงไม่ได้กรองแถวจริง",
    "SEC006": "policy สำหรับเขียนไม่มี WITH CHECK ผู้ใช้อาจเขียนแถวที่ไม่ใช่ของตัวเองได้",
    "SEC007": "ทุก policy เป็นแบบ permissive ข้อใดข้อหนึ่งผ่านก็พอ ตรวจว่าไม่มีข้อที่กว้างเกินไป",
    "SEC008": "policy ผ่านทุกแถว (USING true) ทุกคนที่มีสิทธิ์เห็นทั้งตาราง",
    "SEC009": "เปิด RLS แล้วแต่ไม่มี policy ไม่มีใครเข้าถึงผ่าน API ได้ ถ้าตั้งใจให้เข้าผ่านฟังก์ชันอย่างเดียวถือว่าปกติ",
    "SEC010": "policy ไม่ผ่านเลย (false) ไม่มีใครเข้าถึงได้",
    "SEC011": "เงื่อนไขมี OR true ทำให้ผ่านทุกแถว",
    "SEC012": "มีแต่ policy แบบ restrictive จึงปฏิเสธทุกคนโดยไม่แจ้ง",
    "SEC013": "trigger บนตารางนี้อาจทำงานข้าม policy",
    "SEC014": "ฟังก์ชัน SECURITY DEFINER ข้าม RLS ของผู้เรียก ตรวจด่านภายในฟังก์ชัน",
    "SEC015": "ฟังก์ชัน SECURITY DEFINER อาจถูกหลอกด้วย object ปลอมใน pg_temp ตรึง search_path",
    "SEC016": "role ที่มี BYPASSRLS ข้าม RLS ได้ทั้งหมด",
    "SEC017": "ฟังก์ชัน LEAKPROOF ผ่านด่าน RLS ได้ ตรวจว่าจำเป็นจริง",
    "SEC018": "policy เทียบกับ current_user หรือ session_user ซึ่งใน Supabase มักไม่ใช่ตัวผู้ใช้ ใช้ auth.uid()",
    "SEC019": "policy เรียก current_setting() โดยไม่กันค่าว่าง อาจ error",
    "SEC020": "WITH CHECK ผ่านทุกแถวแต่ USING ไม่ใช่ ผู้ใช้อาจเขียนแถวที่ตัวเองอ่านไม่ได้",
    "SEC021": "policy เทียบตัวตนกับค่าคงที่ที่เขียนตายตัว",
    "SEC022": "เปิด RLS แต่ไม่มี policy สำหรับเขียน ถ้าเว็บต้องเขียนตารางนี้จะเขียนไม่ได้",
    "SEC023": "policy ใช้กับ role ที่ข้าม RLS อยู่แล้ว ไม่มีผล",
    "SEC024": "current_setting() ใช้ชื่อพารามิเตอร์ที่ไม่ระบุกลุ่ม",
    "SEC025": "policy อ้างตารางที่ปิด RLS",
    "SEC026": "policy ใช้ LIKE หรือ regex กับข้อมูลตัวตน อาจถูกเลี่ยงได้",
    "SEC027": "ตารางมีคอลัมน์บอกเจ้าของ แต่ไม่มี policy ใดกรองด้วยคอลัมน์นั้น",
    "SEC028": "policy สำหรับเขียนผ่านทุกแถว (WITH CHECK true) ใครมีสิทธิ์ก็เขียนอะไรก็ได้",
    "SEC029": "role นี้สลับไปเป็น role ที่ข้าม RLS ได้",
    "SEC030": "policy กรองด้วยคอลัมน์ที่เป็นค่าว่างได้ แถวที่ค่าว่างอาจหลุด",
    "SEC031": "policy แบบ restrictive ผ่านทุกแถว จึงไม่ได้จำกัดอะไร",
    "SEC032": "มี policy แต่ไม่ได้เปิด RLS policy จึงไม่มีผล เปิด RLS",
    "SEC033": "policy เชื่อ user_metadata ซึ่งผู้ใช้แก้เองได้ ใช้ app_metadata หรือตารางสิทธิ์แทน",
    "SEC034": "policy ใช้ auth.email() ซึ่งผู้ใช้เปลี่ยนได้และสนตัวพิมพ์เล็กใหญ่",
    "SEC035": "UNIQUE ไม่ได้รวมคอลัมน์แยกหน่วยงาน อาจรู้ได้ว่าหน่วยงานอื่นมีข้อมูลอะไร",
    "SEC036": "policy อ้าง auth.users โดยไม่ผูกกับผู้เรียก",
    "SEC037": "policy เทียบ auth.role() กับชื่อ role ที่ไม่มีอยู่จริง จึงปฏิเสธเงียบ ๆ",
    "SEC038": "ผู้ไม่ล็อกอินอ่านแถวได้ทั้งหมด เพราะเงื่อนไขผ่านเสมอสำหรับเขา",
    "SEC039": "policy สำหรับเขียนเปิดให้ผู้ไม่ล็อกอิน",
    "SEC040": "WITH CHECK ไม่ได้จำกัดแถวแบบเดียวกับ USING ผู้ใช้อาจย้ายแถวไปเป็นของคนอื่น",
    "SEC041": "ตารางลูกของ partition ข้าม RLS ของตารางแม่",
    "SEC042": "ผู้ไม่ล็อกอินเรียกฟังก์ชัน SECURITY DEFINER ที่ข้าม RLS ได้",
    "SEC043": "ตารางลูกแบบ inheritance ข้าม RLS ของตารางแม่",
    "SEC044": "ค่าตั้งต้นให้สิทธิ์ตารางใหม่แก่ role สิทธิ์ต่ำโดยอัตโนมัติ",
    "SEC045": "คอลัมน์ที่อ่อนไหวเปิดให้ role สิทธิ์ต่ำ",
    "SEC046": "policy เรียกฟังก์ชัน IMMUTABLE ที่อ่านค่าของ session ผลอาจถูกแคชข้ามผู้ใช้",
    "SEC047": "foreign key ไปยังตารางที่มี RLS อาจใช้เดาว่ามีข้อมูลของหน่วยงานอื่น",
    "SEC048": "role สิทธิ์ต่ำเข้าถึงเจ้าของตารางที่ไม่ได้ FORCE RLS",
    "SEC049": "ตารางที่ Data API เปิดอยู่ role สิทธิ์ต่ำอ่านได้ ตรวจว่า policy จำกัดพอ",
    "SEC050": "policy ของ Storage ไม่ระบุ bucket มีผลกับทุก bucket",
    "SEC051": "Realtime ส่งการเปลี่ยนแปลงของตารางที่ปิด RLS ออกไปโดยไม่กรอง",
    "SEC052": "ตารางผู้ใช้ของระบบล็อกอินถูกเปิดผ่าน view ใน schema ของ API",
    "SEC053": "foreign table ถูกเปิดใน schema ของ API ซึ่งมี RLS ไม่ได้",
    "SEC054": "materialized view ถูกเปิดใน schema ของ API ซึ่งไม่ผ่าน RLS",
    "SEC055": "policy ใช้รูปแบบผูกตัวตนแบบเงียบ ทั้งที่ schema เปลี่ยนไปใช้แบบแจ้ง error แล้ว",
    "PERF001": "policy เรียก auth.uid() ทุกแถว ช้าเมื่อตารางใหญ่ ครอบด้วย (select auth.uid())",
    "PERF002": "policy ใช้ฟังก์ชัน VOLATILE ช้าและคาดเดาผลยาก",
    "PERF003": "คอลัมน์ที่ policy ใช้กรองไม่มี index ช้าเมื่อตารางใหญ่",
    "PERF004": "policy ครอบคอลัมน์ด้วยฟังก์ชัน ทำให้ใช้ index ไม่ได้",
    "PERF005": "ตารางที่มี RLS ถูกอ่านแบบสแกนทั้งตารางในระบบจริง",
    "HYG001": "policy อ้างคอลัมน์ที่ไม่มีในตาราง",
    "HYG002": "ชื่อ policy ดูเหมือนตั้งไว้ชั่วคราว",
    "HYG003": "policy ซ้ำกับอีกข้อบนตารางเดียวกัน",
    "HYG004": "policy นี้ยังไม่มีการทดสอบ",
    "VIEW001": "view ข้าม RLS เพราะไม่ได้ตั้ง security_invoker",
    "VIEW002": "view ไม่ได้ตั้งเป็น security barrier อาจหลุดข้อมูลผ่านฟังก์ชัน",
    "VIEW003": "materialized view เก็บข้อมูลที่มี RLS ไว้ตอน refresh ผู้อ่านเห็นข้อมูลของคนอื่นได้",
    "VIEW004": "view เรียกฟังก์ชัน SECURITY DEFINER ที่อ่านตารางที่มี RLS",
}

BY_SOURCE: dict[str, str] = {
    "pgrls": "ผลของ pgrls (ตรวจนโยบาย RLS) รายละเอียดเป็นภาษาอังกฤษจากเครื่องมือนั้น อ่านเทียบกับการออกแบบของระบบก่อนแก้",
    "advisor": "ผลตรวจของ Supabase เอง ลิงก์ในรายละเอียดอธิบายวิธีแก้",
}


def specific(finding: Finding) -> str:
    """A Thai line written for this very rule, or "" when there is only a per-source line."""
    if finding.rule in RULES:
        return RULES[finding.rule]
    if finding.source == "pgrls":
        return PGRLS.get(finding.rule, "")
    if finding.rule.startswith("parity_"):
        return (f"ส่วน {finding.rule.removeprefix('parity_')} เปลี่ยนไปจากรายการที่บันทึกไว้ "
                "ถ้าตั้งใจให้บันทึกรายการใหม่ ถ้าไม่ได้ตั้งใจให้ตรวจว่าใครเปลี่ยน")
    return ""


def explain(finding: Finding) -> str:
    """A Thai line for a finding, or "" when there is none."""
    return specific(finding) or BY_SOURCE.get(finding.source, "")
