"""Checks no script here can settle. They are listed in every report as NOT_RUN
so that nobody reads a clean automated run as a complete review.

The full method for each item is in
skills/supabase-web-care/references/manual-checklist.md.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ManualItem:
    id: str
    title_th: str
    how_th: str
    title_en: str = ""
    how_en: str = ""

    def title(self, lang: str) -> str:
        return self.title_th if lang == "th" else self.title_en

    def how(self, lang: str) -> str:
        return self.how_th if lang == "th" else self.how_en


MANUAL_ITEMS: tuple[ManualItem, ...] = (
    ManualItem(
        "advisor",
        "Supabase Security Advisor",
        "รันผ่าน Supabase MCP `get_advisors` หรือคำสั่ง `supabase db advisors` "
        "(ต้องต่ออินเทอร์เน็ต จึงรันบนเครื่องที่ตัดเน็ตไม่ได้) ถ้าใช้ `--via-api` ให้เพิ่ม `--with-advisors` เพื่ออ่านผลตรวจด้านความปลอดภัยให้",
        title_en='Supabase Security Advisor',
        how_en='Run it through the Supabase MCP `get_advisors` tool or `supabase db advisors` (it needs the internet, so it cannot run on a machine that is cut off). On the `--via-api` route, `--with-advisors` reads the security lints for you.',
    ),
    ManualItem(
        "storage_buckets",
        "bucket ของ Storage ที่ตั้งเป็น public",
        "ตรวจอัตโนมัติเมื่อใช้ `--via-api` (การตรวจ `storage_buckets`) ถ้าไม่ได้ใช้ทางนั้น "
        "ดูที่หน้า Storage ใน Dashboard หรือผลของ Security Advisor "
        "(role ตรวจสอบไม่มีสิทธิ์อ่านตาราง storage.buckets)",
        title_en='Storage buckets set to public',
        how_en='Checked automatically on the `--via-api` route (`storage_buckets`). Otherwise look at the Storage page of the dashboard or at Security Advisor: the audit role may not read storage.buckets.',
    ),
    ManualItem(
        "data_api_exposure",
        "schema ที่เปิดผ่าน Data API และการเปิดตารางใหม่อัตโนมัติ",
        "ดูที่ Project Settings → Data API ว่า schema ที่เปิดมีเท่าที่ตั้งใจ "
        "และตารางใหม่ต้องได้รับ GRANT พร้อมเปิด RLS เสมอ",
        title_en='Schemas exposed through the Data API, and automatic exposure of new tables',
        how_en='In Project Settings → Data API, confirm that only the intended schemas are exposed, and that a new table always gets its GRANTs together with RLS.',
    ),
    ManualItem(
        "auth_sessions",
        "อายุ token และการยกเลิก session",
        "การลบผู้ใช้ไม่ทำให้ access token ที่ออกไปแล้วหมดอายุ ตรวจอายุ JWT "
        "และขั้นตอน sign out หรือ revoke session ก่อนลบผู้ใช้",
        title_en='Token lifetime and ending sessions',
        how_en='Deleting a user does not expire an access token that was already issued. Check the JWT lifetime and the sign-out or session-revocation step before deleting a user.',
    ),
    ManualItem(
        "claims_freshness",
        "สิทธิ์ที่อ่านจาก JWT (`app_metadata`)",
        "ค่าใน JWT ไม่เปลี่ยนจนกว่าจะ refresh token ตรวจว่าการถอนสิทธิ์มีผลทันเวลาที่ยอมรับได้",
        title_en='Permissions read from the JWT (`app_metadata`)',
        how_en='A value in the JWT does not change until the token is refreshed. Check that removing a permission takes effect within a time you accept.',
    ),
    ManualItem(
        "edge_functions_deployed",
        "Edge Function ที่ deploy อยู่จริง",
        "การตรวจ `edge_functions` อ่านได้แค่ไฟล์ ให้เปิดหน้า Edge Functions ใน dashboard เทียบค่า Verify JWT ของแต่ละฟังก์ชันกับ `config.toml` และตรวจว่าโค้ดที่ deploy ตรงกับใน repo",
        title_en='Edge Functions as they are deployed',
        how_en="The `edge_functions` check reads files only. In the dashboard, compare each function's Verify JWT setting with `config.toml`, and check that the deployed code is the code in the repository.",
    ),
    ManualItem(
        "access_tokens",
        "ขอบเขตของ access token ที่ใช้ใน CI และ agent",
        "ใช้ scoped token ที่จำกัดโปรเจกต์และสิทธิ์ ไม่ใช้ token แบบ classic ที่เข้าถึงได้ทั้งบัญชี",
        title_en='Scope of the access tokens used in CI and by agents',
        how_en='Use scoped tokens limited to one project and the permissions needed, never a classic token that reaches the whole account.',
    ),
    ManualItem(
        "api_logs",
        "บันทึกการเรียกฟังก์ชันที่เปิดให้ผู้ไม่ล็อกอิน",
        "ดู log ของ API ว่าฟังก์ชันใดถูกเรียกสำเร็จโดยไม่มีผู้ใช้ล็อกอิน และเทียบกับ "
        "`expected_anon_functions` (`--with-logs` ดูให้ 24 ชั่วโมงล่าสุด ไกลกว่านั้นต้องดูเอง) ทำก่อนถอนสิทธิ์ทุกครั้ง และทำทันทีเมื่อพบฟังก์ชันที่เปิดโดยไม่ตั้งใจ "
        "เพราะ log มีอายุจำกัด (ต้องต่ออินเทอร์เน็ต)",
        title_en='Calls to functions that are open to anonymous visitors',
        how_en='Look in the API logs for functions called successfully with no signed-in user and compare with `expected_anon_functions`. `--with-logs` covers the last 24 hours; look further back by hand. Do this before every revoke, and at once when a function turns out to be open by mistake, because logs are kept for a limited time (needs the internet).',
    ),
    ManualItem(
        "migration_drift",
        "การเปลี่ยนแปลงที่รันนอกประวัติ migration",
        "เทียบรายการในตารางประวัติ migration กับไฟล์ใน repo และกับสิ่งที่รันผ่าน SQL Editor "
        "หรือ API โดยตรง ฐานที่ถูกแก้นอกประวัติจะทำให้การตรวจจากไฟล์ให้ผลไม่ตรงกับของจริง",
        title_en='Changes applied outside the migration history',
        how_en='Compare the migration history table with the files in the repository and with what was run through the SQL Editor or the API directly. A database changed outside its history makes file checks disagree with reality.',
    ),
    ManualItem(
        "environment_map",
        "เว็บไหนต่อกับฐานข้อมูลไหน",
        "ยืนยันจากค่าที่เว็บใช้งานจริงว่าแต่ละเว็บชี้ไปโปรเจกต์ใด เรียกฐานด้วยรหัสโปรเจกต์ "
        "และตรวจว่าไม่มีเว็บเก่าที่ยังเปิดอยู่ต่อกับฐานที่มีข้อมูลจริง",
        title_en='Which site talks to which database',
        how_en="Confirm from each site's live configuration which project it points at, name databases by project reference, and check that no old site is still up and connected to a database with real data.",
    ),
    ManualItem(
        "dependency_pins",
        "การล็อกเวอร์ชันแพ็กเกจ",
        "ตรวจว่ามี lockfile อยู่ใน repo และไม่มีการติดตั้งแบบ `@latest` ใน CI",
        title_en='Pinned package versions',
        how_en='Check that a lockfile is in the repository and that nothing in CI installs at `@latest`.',
    ),
)
