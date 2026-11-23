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
    "stripe_live_key": "secret key ของ Stripe ตัวจริงอยู่ในไฟล์ ต้องเพิกถอนทันที",
    # functions
    "secdef_public_execute": "ฟังก์ชัน SECURITY DEFINER ที่ทุก role เรียกได้ (ผ่าน PUBLIC) ทำงานด้วยสิทธิ์เจ้าของ ข้าม RLS ได้ ถอนสิทธิ์จาก PUBLIC และ anon",
    "secdef_anon_granted": "ฟังก์ชัน SECURITY DEFINER ที่ให้ผู้ไม่ล็อกอินเรียกได้ตรง ๆ ถ้าไม่ได้ตั้งใจให้ถอนสิทธิ์จาก anon",
    "secdef_anon_not_revoked": "ถอนสิทธิ์จาก PUBLIC แล้วแต่ anon ยังได้สิทธิ์จากค่าตั้งต้นของ Supabase ต้องถอนจาก anon ด้วย",
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
    "extension_net_callable": "role ของ API เรียก pg_net ได้ ฐานข้อมูลจะยิง HTTP ไปที่ไหนก็ได้แทนเขา ถ้าไม่มีฟังก์ชันที่ต้องใช้ ให้ถอนสิทธิ์",
    "extension_vault_reachable": "role ของ API อ่าน Vault หรือเรียกฟังก์ชันของมันได้ ความลับใน Vault อาจหลุด ต้องถอนสิทธิ์ทันที",
    "extension_cron_reachable": "role ของ API ตั้งงานตามเวลาหรืออ่านรายการงานได้ ต้องถอนสิทธิ์",
    "realtime_table_without_rls": "Realtime ส่งการเปลี่ยนแปลงของตารางนี้ออกไป และไม่มี RLS กรอง ทุกคนที่อ่านได้จะเห็นทุกการเปลี่ยนแปลงทันที",
    "realtime_messages_open": "policy ของช่อง Realtime แบบส่วนตัวเปิดให้ทุกคน ใครมี key สาธารณะก็เข้าฟังและส่งข้อความได้",
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
    "sequence_near_limit": "sequence ใกล้ใช้เลขหมด ถ้าหมดจะเพิ่มแถวไม่ได้ เปลี่ยนเป็น bigint",
    # platform
    "ssl_not_enforced": "ฐานรับการเชื่อมต่อที่ไม่เข้ารหัส เปิดการบังคับ SSL ในหน้าตั้งค่าฐานข้อมูล",
    "database_open_to_every_address": "ต่อฐานตรงได้จากทุก IP รหัสผ่านฐานเป็นด่านเดียว จำกัด IP ที่ต้องใช้",
}

BY_SOURCE: dict[str, str] = {
    "pgrls": "ผลของ pgrls (ตรวจนโยบาย RLS) รายละเอียดเป็นภาษาอังกฤษจากเครื่องมือนั้น อ่านเทียบกับการออกแบบของระบบก่อนแก้",
    "advisor": "ผลตรวจของ Supabase เอง ลิงก์ในรายละเอียดอธิบายวิธีแก้",
}


def explain(finding: Finding) -> str:
    """A Thai line for a finding, or "" when there is none."""
    if finding.rule in RULES:
        return RULES[finding.rule]
    if finding.rule.startswith("parity_"):
        return (f"ส่วน {finding.rule.removeprefix('parity_')} เปลี่ยนไปจากรายการที่บันทึกไว้ "
                "ถ้าตั้งใจให้บันทึกรายการใหม่ ถ้าไม่ได้ตั้งใจให้ตรวจว่าใครเปลี่ยน")
    return BY_SOURCE.get(finding.source, "")
