# ทดสอบบนเครื่องที่ตัดอินเทอร์เน็ต

เอกสารนี้สำหรับผู้ที่รันชุดเครื่องมือบนเครื่องส่วนตัว (VM) ที่มีทั้งฐานข้อมูลจำลองและฐานข้อมูลจริง จะเป็นคนหรือ AI agent ก็ได้ ทำตามลำดับ เพราะแต่ละขั้นเป็นเงื่อนไขของขั้นถัดไป

เครื่องมือไม่ต่ออินเทอร์เน็ตเองในทุกขั้น ยกเว้นการตรวจสิทธิ์ anon ซึ่งต่อเฉพาะ URL ที่ประกาศไว้ใน `webcare.toml`

## 1. เตรียมชุดติดตั้ง (ขณะยังต่อเน็ต)

wheel ของ `pgrls`, `z3-solver`, `pglast` และ `psycopg-binary` ขึ้นกับระบบปฏิบัติการ ชนิด CPU และเวอร์ชัน Python จึงต้องดาวน์โหลดบนเครื่องที่ตรงกับ VM ทางที่ง่ายที่สุดคือรันบน VM เองก่อนตัดเน็ต

```bash
cd supabase-web-care
scripts/make_offline_bundle.sh        # ดาวน์โหลด wheel ลง wheelhouse/ และตรวจ hash ทุกไฟล์
```

ต้องมี Python 3.11 ขึ้นไป สคริปต์ดาวน์โหลดเฉพาะแพ็กเกจและเวอร์ชันที่ระบุใน `requirements-dev.lock` และจะหยุดถ้า hash ไม่ตรง

## 2. ตัดอินเทอร์เน็ต แล้วติดตั้ง

```bash
scripts/install_offline.sh            # สร้าง .venv และติดตั้งจาก wheelhouse/ เท่านั้น
. .venv/bin/activate
python -m webcare --version
pgrls --version                        # ต้องได้ 0.57.1
```

## 3. ทดสอบตัวเครื่องมือ

```bash
python -m pytest tests
```

ถ้าไม่ได้ตั้ง `WEBCARE_TEST_ADMIN_DSN` การทดสอบส่วนที่ต่อฐานข้อมูลจะถูกข้าม ส่วนที่เหลือควรผ่านทั้งหมด

การทดสอบที่ต่อฐานข้อมูลจะสร้าง role `webcare_auditor` เปลี่ยนรหัสผ่าน และปิด login ของ role นั้นเมื่อจบ **ห้ามตั้งตัวแปรนี้ให้ชี้ไปที่ Postgres ตัวเดียวกับที่เก็บฐานข้อมูลจริง** ถ้าต้องการรันส่วนนี้ ให้ใช้ Postgres อีกตัวที่สร้างไว้ทดลองโดยเฉพาะ

## 4. ตรวจจากไฟล์ก่อน

```bash
python -m webcare check --repo <โฟลเดอร์โค้ดของเว็บ> --migrations <โฟลเดอร์ migration>
```

ขั้นนี้ไม่ต่อฐานข้อมูลใด ผลอยู่ที่ `webcare-output/report.md` ถ้าโฟลเดอร์ปัจจุบันเขียนไม่ได้ ให้ระบุ `--out-dir <โฟลเดอร์ที่เขียนได้>` หรือใช้ `--json` เพื่อพิมพ์รายงานออกหน้าจอ

ข้อควรรู้ของขั้นนี้

- ใช้ `webcare check` แทนการเรียก `pgrls` ตรง ๆ เพราะจะข้ามไฟล์ `ROLLBACK_*` ให้ ตัดผลที่รู้ว่าผิดของ schema ที่ Supabase ดูแลออก และสแกน key ไปพร้อมกัน
- ถ้าชุดไฟล์ migration ไม่ครบประวัติ ผล "RLS ไม่ได้เปิด" (SEC001, SEC032) จะแจ้งผิดได้ การทดลองเมื่อ 22 พ.ย. 2569 กับไฟล์ 37 ไฟล์พบกรณีนี้ 3 ตาราง ซึ่งฐาน staging เปิด RLS อยู่แล้ว ให้ยืนยันกับฐานข้อมูลทุกครั้ง
- กฎ 25 ข้อของ pgrls ที่เกี่ยวกับฟังก์ชัน `SECURITY DEFINER`, view และดัชนี ไม่ทำงานในขั้นนี้ ต้องทำขั้นที่ 5 ต่อ
- สิทธิ์ของฟังก์ชัน `SECURITY DEFINER` เครื่องมือตรวจจากไฟล์เองในขั้นนี้ (แถว "ฟังก์ชัน SECURITY DEFINER จากไฟล์ SQL" ในรายงาน) ผลขึ้นกับลำดับไฟล์ ถ้าชื่อไฟล์ไม่เรียงตามลำดับที่รันจริง ให้ระบุทีละไฟล์ด้วย `--sql-file`

## 5. ฐานข้อมูลจำลอง

1. ในฐานข้อมูลจำลอง รัน `sql/auditor-role.sql` ด้วยบัญชีผู้ดูแล แล้วเปิด login และตั้งรหัสผ่านตามขั้นที่ 2 ในไฟล์นั้น (ใช้ `\password` ใน psql)
2. คัดลอก `webcare.example.toml` เป็น `webcare.toml` แล้วประกาศเป้าหมาย โดยใส่ `data = "synthetic"` เฉพาะเมื่อฐานข้อมูลนั้นไม่มีข้อมูลจริงอยู่เลย
3. รัน

```bash
export WEBCARE_DATABASE_URL='postgresql://webcare_auditor:<รหัสผ่าน>@127.0.0.1:<port>/<ฐานข้อมูลจำลอง>'
python -m webcare preflight --target sim
python -m webcare check --target sim --repo <โฟลเดอร์โค้ด> --migrations <โฟลเดอร์ migration>
```

ในรายงานจะมีแถว "ฟังก์ชัน SECURITY DEFINER ที่ผู้ไม่ล็อกอินเรียกได้" รอบแรกจะแสดงทุกตัวที่เปิดอยู่ที่ระดับกลาง ให้อ่านโค้ดของแต่ละตัว แล้วใส่ตัวที่ตั้งใจเปิดไว้ใน `expected_anon_functions` ของเป้าหมายใน `webcare.toml` รอบถัดไปควรได้ PASS และฟังก์ชันที่เปิดเพิ่มนอกรายการจะขึ้นที่ระดับสูง

ผลของ `preflight` ที่ถูกต้องคือ `superuser=False`, `bypassrls=False`, `writable tables=0` และบรรทัดสุดท้ายขึ้นต้นด้วย `ok:` ถ้า `readable relations` มากกว่า 0 แปลว่ามีตารางที่ GRANT ให้ `PUBLIC` ซึ่งควรบันทึกเป็นข้อค้นพบ

ถ้า VM มี Supabase แบบ local (มี PostgREST) ให้เพิ่ม `rest = "http://127.0.0.1:<port>"` ในเป้าหมาย ตั้ง `WEBCARE_ANON_KEY` เป็น key สาธารณะ แล้วรัน `check` อีกครั้ง การตรวจสิทธิ์ anon จะทำงานเพิ่ม

### เมื่อ VM ต่อ Postgres ไม่ได้

ถ้า `preflight` จบด้วย timeout ทั้งแบบต่อตรงและแบบ pooler แปลว่าเครือข่ายของ VM ปล่อยเฉพาะการเชื่อมต่อแบบเว็บ ไม่ต้องลองพอร์ตอื่น ให้ใช้ภาพถ่ายโครงสร้างแทน มีสองทาง

**ทางที่ 1: เครื่องมือดึงเองผ่าน Management API**

1. เพิ่ม `project_ref = "<รหัสโปรเจกต์>"` ในเป้าหมายใน `webcare.toml`
2. สร้าง access token แบบจำกัดสิทธิ์สำหรับโปรเจกต์นั้น ให้มีสิทธิ์ `database_read` อย่างเดียว อายุสั้น
3. รัน

```bash
export WEBCARE_ACCESS_TOKEN='<token>'
python -m webcare check --target <ชื่อเป้าหมาย> --via-api --skip secrets --skip static
unset WEBCARE_ACCESS_TOKEN
```

เครื่องมือส่งคำสั่ง SELECT ไม่เกิน 7 ครั้งไปที่ช่องทางอ่านอย่างเดียวของโปรเจกต์ ถ้าได้ HTTP 403 แปลว่า token ไม่มีสิทธิ์ `database_read` ของโปรเจกต์นั้น เพิกถอน token เมื่อเสร็จ

**ทางที่ 2: ผู้ดูแลรันคำสั่งเองแล้วส่งไฟล์**

1. บน VM: `python -m webcare snapshot-sql --target <ชื่อเป้าหมาย> > snapshot.sql`
2. ผู้ดูแลรัน `snapshot.sql` ที่ SQL Editor ของโปรเจกต์นั้น (ตรวจรหัสโปรเจกต์ใน URL ก่อน) แล้วบันทึกผลลัพธ์ JSON ทั้งก้อนเป็นไฟล์
3. บน VM: `python -m webcare check --snapshot <ไฟล์> --target <ชื่อเป้าหมาย> --skip secrets --skip static`

ทั้งสองทางไม่ต้องสร้าง role และไม่ต้องตั้ง `WEBCARE_DATABASE_URL` แถว "นโยบาย RLS จากฐานข้อมูล (pgrls)" จะเป็น NOT_RUN เพราะ pgrls ต้องต่อฐาน ส่วนแถวอื่นทำงานครบ ไฟล์ภาพถ่ายมีแต่ชื่อและค่าใช่/ไม่ใช่ จัดเก็บเหมือนไฟล์รายงาน

## 6. ฐานข้อมูลจริง (ต้องได้รับอนุมัติก่อน)

ทำขั้นนี้เมื่อเจ้าของระบบอนุมัติด้วยคำพูดของตัวเองแล้วเท่านั้น

1. ประกาศเป้าหมายแยกอีกรายการ โดยใส่ `data = "real"` แม้ฐานข้อมูลจะอยู่บนเครื่อง local
2. สร้าง role `webcare_auditor` ในฐานข้อมูลนั้นเช่นเดียวกับขั้นที่ 5
3. รันโดยเพิ่ม `--owner-approved`

```bash
export WEBCARE_DATABASE_URL='postgresql://webcare_auditor:<รหัสผ่าน>@127.0.0.1:<port>/<ฐานข้อมูลจริง>'
python -m webcare preflight --target real --owner-approved
python -m webcare check --target real --owner-approved --skip secrets --skip static
```

เครื่องมืออ่านเฉพาะ catalog ของระบบ (policy, สิทธิ์, นิยามฟังก์ชัน) role `webcare_auditor` ไม่มีสิทธิ์ SELECT บนตารางใด จึงอ่านแถวข้อมูลไม่ได้แม้จะมีคนพยายามสั่ง ห้ามใช้ `--allow-privileged-role` กับฐานข้อมูลจริง เครื่องมือจะปฏิเสธอยู่แล้ว

## 7. ส่งผลกลับ

ไฟล์ `report.md` และ `report.json` มีชื่อ schema, ตาราง, policy และฟังก์ชัน ไม่มีข้อมูลแถว รหัสผ่าน หรือ key ให้อ่านไฟล์ก่อนส่งต่อทุกครั้ง และจัดเก็บตามกฎของโครงการ โฟลเดอร์ `webcare-output/` และไฟล์ `webcare.toml` ถูกกันไม่ให้เข้า git ไว้แล้ว

สิ่งที่ควรรายงานกลับ

- ผลของ `python -m pytest tests` (จำนวนที่ผ่าน ข้าม และล้มเหลว)
- ผลของ `preflight` ของแต่ละเป้าหมาย
- ตารางสรุปจาก `report.md` ของแต่ละเป้าหมาย
- ข้อใดในหัวข้อ "ยังไม่ทดสอบ" ด้านล่างที่ได้ทดสอบแล้ว และผลเป็นอย่างไร

## 8. เก็บกวาด

```sql
alter role webcare_auditor nologin;      -- ปิด login เมื่อตรวจเสร็จ
```

ถ้าไม่ใช้ต่อ ให้รัน `sql/auditor-role-drop.sql` ในแต่ละฐานข้อมูลที่เคยสร้าง role ไว้ แล้วล้างตัวแปร `WEBCARE_DATABASE_URL` และ `WEBCARE_ANON_KEY` ออกจาก shell

## ยังไม่ทดสอบ (not verified)

รายการต่อไปนี้ผ่านการทดสอบกับของจำลองเท่านั้น ยังไม่ได้ยืนยันกับระบบจริง

| หัวข้อ | สถานะ | วิธียืนยันบน VM |
|---|---|---|
| การตีความ `Content-Range` ของ PostgREST จริง (`0-0/*` = เห็นแถว, `*/*` = ไม่เห็น) | ยังไม่ทดสอบ ทดสอบกับเซิร์ฟเวอร์จำลองที่ตอบตามเอกสาร PostgREST | รันขั้นที่ 5 กับ Supabase local แล้วเทียบผลกับตารางที่รู้ว่า anon อ่านได้และอ่านไม่ได้ |
| การส่ง publishable key (`sb_publishable_…`) ในส่วนหัว `apikey` อย่างเดียว | ยังไม่ทดสอบ | รันขั้นที่ 5 ด้วย publishable key |
| `check --via-api` กับ Management API จริง | ผ่านบน โครงการ staging ของผู้เขียน ด้วยรุ่น 1.4 (22 พ.ย. 2569) ใช้ fine-grained token สิทธิ์ Database Read เฉพาะโครงการนั้น ได้ฟังก์ชันที่ผู้ไม่ล็อกอินเรียกได้ 19 ตัวตรงกับรายชื่อที่ประกาศ token ที่ไม่มีสิทธิ์นี้ได้ HTTP 403 และเครื่องมือหยุดพร้อมบอกเหตุผล | ไม่ต้องยืนยันเพิ่ม |
| การตรวจงานตั้งเวลา (`health_cron`) | ผ่านบน โครงการ staging ของผู้เขียน ผ่าน Management API ด้วยรุ่น 1.5.1 (pg_cron 1.6.4, 22 พ.ย. 2569) เห็นงานครบ 3 งาน ไม่มีรอบที่ล้ม ตรงกับที่อ่านจากฐานโดยตรง กรณีที่มีงานล้มจริงทดสอบกับฐานจำลองเท่านั้น ส่วน `expected_cron_jobs` ผ่านบนโครงการเดียวกันด้วยรุ่น 1.11.1: งานจริงสามงานผ่าน และชื่อที่ตั้งใจใส่ผิดได้ข้อระดับปานกลางหนึ่งข้อพอดี | ไม่ต้องยืนยันเพิ่ม |
| ผลตรวจความปลอดภัยของ Supabase เอง (`advisors`, `--with-advisors`) | รันกับปลายทางจริงบนโครงการ staging ของผู้เขียนแล้ว (22 พ.ย. 2569 รุ่น 1.14.0) ได้ HTTP 200 ด้วย token ที่เลือกสิทธิ์ Database Read อย่างเดียว แม้เอกสารระบุ `advisors_read` ปลายทางจริงส่งผลมาหนึ่งแถวต่อหนึ่งวัตถุที่ถูกชี้ (447 แถวสำหรับ 4 ชนิด) ไม่ใช่หนึ่งแถวต่อหนึ่งชนิดเหมือนเครื่องมือ MCP รุ่น 1.13.0 และ 1.14.0 จึงนับผิด แก้ในรุ่น 1.14.1 ยอดหลังแก้ยังไม่ได้รันซ้ำกับปลายทางจริง | รัน `check --target <ชื่อ> --via-api --with-advisors` แล้วเทียบจำนวนกับหน้า Advisor ใน Dashboard |
| การตรวจ backup (`health_backups`, `--with-backups`) | ผ่านบน โครงการ staging ของผู้เขียน ด้วยรุ่น 1.6.0 (22 พ.ย. 2569) ได้ HTTP 200 และผล "ไม่มี backup ที่สำเร็จ" ระดับต่ำ ครั้งนั้น token ที่เลือกสิทธิ์ Database Read อย่างเดียวในหน้าสร้าง token ก็อ่านรายการ backup ได้ แม้เอกสารของ Supabase ระบุสิทธิ์ `backups_read` กรณีที่มี backup อยู่จริงทดสอบกับข้อมูลจำลองเท่านั้น | รันกับโปรเจกต์ที่มี backup แล้วเทียบวันที่กับหน้า Backups ของ Supabase |
| การสรุป log (`health_logs`, `--with-logs`) | ผ่านบน โครงการ staging ของผู้เขียน ด้วยรุ่น 1.7.0 (22 พ.ย. 2569) นับได้ 3,411 คำขอใน 24 ชั่วโมง ไม่มี server error ไม่มีฟังก์ชันนอกรายชื่อที่ถูกเรียกโดยไม่ล็อกอิน ครั้งนั้น token ที่เลือกสิทธิ์ Database Read อย่างเดียวก็อ่าน log ได้ แม้เอกสารของ Supabase ระบุสิทธิ์ `analytics_logs_read` จึงควรถือว่า token นี้อ่าน log ซึ่งมี IP ของผู้ใช้ได้ด้วย และเพิกถอนทันทีหลังใช้ | ไม่ต้องยืนยันเพิ่ม |
| การตรวจ Storage (`storage_buckets`) | ผ่านทาง Management API ด้วยรุ่น 1.8.0 บนโครงการจริงสองแห่ง (22 พ.ย. 2569) แต่ละแห่งเห็น bucket 2 ตัว เป็นส่วนตัวทั้งหมด ไม่มีข้อที่ต้องรายงาน กรณี bucket สาธารณะและ policy ที่เปิดให้ผู้ไม่ล็อกอิน ทดสอบกับข้อมูลจำลองเท่านั้น | รันกับโครงการที่มี bucket สาธารณะ แล้วเทียบกับหน้า Storage ของ Supabase |
| การตรวจการตั้งค่าล็อกอิน (`auth_config`, `--with-auth-config`) | ผ่านบน โครงการ staging ของผู้เขียน ด้วยรุ่น 1.9.0 (22 พ.ย. 2569) การตั้งค่าในรายการครบทุกตัว ชื่อตรงกับเอกสาร ไม่มีค่าลับในรายงาน ครั้งนั้น token ที่เลือกสิทธิ์ Database Read อย่างเดียวก็อ่านปลายทางนี้ได้ แม้เอกสารระบุสิทธิ์ `auth_config_read` **จึงต้องถือว่า token Database Read อ่านค่าลับของระบบล็อกอินได้** (รหัสของระบบส่งอีเมล secret ของ OAuth และ hook) | ไม่ต้องยืนยันเพิ่ม |
| การเชื่อมต่อผ่าน pooler ของ Supabase (Supavisor) | ยังไม่ทดสอบ VM ที่ใช้ทดลองเมื่อ 22 พ.ย. 2569 ต่อ Postgres ไม่ได้ทั้งแบบตรงและแบบ pooler (timeout จากเครือข่ายของ VM) | ทดสอบจากเครื่องที่ต่อ Postgres ได้ ด้วย connection string แบบ session pooler |
| `sql/auditor-role.sql` บน Supabase จริง ซึ่งผู้ดูแลไม่ใช่ superuser | สร้าง role ได้โดยไม่มี error บน โครงการ staging ของผู้เขียน (Postgres 17.11, 22 พ.ย. 2569) การ login ด้วย role นี้ และคำสั่ง `preflight`, `check`, `inventory` รันกับฐาน Supabase จำลองในเครื่องแล้ว (Postgres 17.12, 26 พ.ย. 2569): role อ่านตารางไม่ได้และเขียนไม่ได้ รอบนั้นพบข้อบกพร่องสองข้อที่แก้ใน 1.39.2 ตัวแก้ทดสอบบน Postgres 16 แล้ว ยังไม่ได้รันซ้ำบน Supabase และยังไม่ได้ทดสอบกับโครงการบนคลาวด์ | รัน `preflight` จากเครื่องที่ต่อ Postgres ได้ |
| ภาพถ่ายโครงสร้าง (`snapshot-sql`, `check --snapshot`) กับ Supabase จริง | คำสั่งรันได้บน โครงการ staging ของผู้เขียน (Postgres 17.11, 22 พ.ย. 2569) ได้ฟังก์ชันที่ผู้ไม่ล็อกอินเรียกได้ 19 ตัว ตรงกับ Security Advisor ข้อ 0028 ส่วนการบันทึกผลจาก SQL Editor เป็นไฟล์แล้วป้อนให้เครื่องมือยังไม่ได้ทดสอบ | ทำตามหัวข้อ "เมื่อ VM ต่อ Postgres ไม่ได้" |
| การเทียบสองฐาน (`inventory`, `compare`) | คำสั่งอ่าน catalog หกคำสั่งและคำสั่งอ่านประวัติ migration รันบนโปรเจกต์ staging ของผู้เขียน (Postgres 17.11) ผ่าน Supabase connector ด้วย role `postgres` ได้ 107 ตาราง สิทธิ์คอลัมน์ 61 รายการ ค่าตั้งต้น 28 รายการ ฟังก์ชัน 374 policy 72 extension 7 และ migration 195 รวมราว 130 KB ทั้งคำสั่งรันกับฐานทดสอบเท่านั้น ยังไม่ได้ทดสอบว่า `supabase_read_only_user` อ่านประวัติ migration ผ่าน `--via-api` ได้หรือไม่ | รัน `inventory --via-api` กับสองโปรเจกต์ แล้ว `compare` สองไฟล์ |
| ตารางที่ role ของ API เขียนได้ (`table_writes`) | คำสั่งรันบนโปรเจกต์ staging ของผู้เขียน (Postgres 17.11) ผ่าน Supabase connector ด้วย role `postgres` ได้ `anon` เขียนได้ 9 ตาราง `authenticated` 22 ตาราง ทุกตารางเปิด RLS ตรงกับการอ่านสิทธิ์แยกอีกครั้ง ยังไม่ได้รันผ่าน `--via-api` ด้วย `supabase_read_only_user` | รัน `check --via-api` แล้วเทียบกับสิทธิ์ตารางในหน้า dashboard |
| ผลแบบ SARIF (`--sarif`) | ตรวจโครงสร้างตาม SARIF 2.1.0 ด้วยชุดทดสอบเท่านั้น ยังไม่เคยอัปโหลดเข้า GitHub code scanning | ทำตามหัวข้อ SARIF ใน `docs/CI_TH.md` กับ repository สาธารณะ |
| schema ของ extension (`extension_net_callable`, `extension_vault_reachable`, `extension_cron_reachable`) | รันบนโปรเจกต์ staging ของผู้เขียน (Postgres 17.11) ผ่าน Supabase connector: `anon` และ `authenticated` เรียกฟังก์ชันของ pg_net ได้ครบ 12 ตัว ส่วน Vault และ pg_cron ปิดอยู่ ยังไม่ได้รันผ่าน `--via-api` ด้วย `supabase_read_only_user` | รัน `check --via-api` |
| สุขภาพฐาน (`db_health`) และ Performance Advisor (`--with-performance`) | คำสั่งตรวจสุขภาพรันบนโปรเจกต์ staging ของผู้เขียน (Postgres 17.11) ผ่าน Supabase connector: เห็นทุกเซสชัน ไม่มีอะไรต้องรายงาน ทาง `--via-api` role `supabase_read_only_user` มี `pg_read_all_stats` (ตรวจบนโปรเจกต์เดียวกัน) จึงควรเห็นเซสชันเช่นกัน แต่ยังไม่ได้รันทางนั้น ยังไม่เคยเรียก Performance Advisor กับโปรเจกต์จริง | รัน `check --via-api --with-performance` |
| Realtime, view และ schema (`realtime_table_without_rls`, `realtime_messages_open`, `view_runs_as_owner`, `schema_usable_but_unchecked`) และ `--with-data-api` | คำสั่งทั้งสี่รันบนโปรเจกต์ staging ของผู้เขียน (Postgres 17.11) ผ่าน Supabase connector: ไม่มีตารางใน publication ของ Realtime ไม่มี policy บน `realtime.messages` ไม่มี view ที่รันด้วยสิทธิ์เจ้าของ และ `authenticated` ใช้ schema `private` ได้ตามที่ policy ต้องใช้ ยังไม่เคยเรียกช่องทางการตั้งค่า PostgREST กับโปรเจกต์จริง | รัน `check --via-api --with-data-api` |
| การตั้งค่าแพลตฟอร์ม (`--with-platform`) | ยังไม่ได้ทดสอบกับโปรเจกต์จริง สร้างจากเอกสารอ้างอิงที่ไม่ได้ระบุรูปแบบคำตอบ | รัน `check --via-api --with-platform` แล้วเทียบกับหน้าตั้งค่าฐานข้อมูล |
| GitHub Action (`action.yml`) และ pre-commit hook | สคริปต์ตรวจของ action รันในเครื่องกับฐานจำลองที่มีปัญหา และปฏิเสธค่าที่แฝงคำสั่ง ยังไม่เคยรันบน GitHub Actions หรือ pre-commit จริง | ใช้ใน repo ของเว็บ |
| Postgres เวอร์ชันอื่นนอกจาก 16 | ชุดทดสอบของเวอร์ชัน 1.1 ผ่านบน Postgres 17.12 บน VM (22 พ.ย. 2569) ส่วนการตรวจที่เพิ่มใน 1.2 ทดสอบบน 16 เท่านั้น | รัน `python -m pytest tests` ซ้ำบน VM |
| การตรวจฟังก์ชันที่เพิ่มในเวอร์ชัน 1.2 กับ Supabase จริง | ยังไม่ทดสอบ ทดสอบกับ Postgres 16 ในเครื่อง และลองอ่านไฟล์ migration ของ ผู้เขียน 14 ไฟล์ (พบไฟล์และฟังก์ชันที่เป็นต้นเหตุของปัญหาที่กำลังแก้อยู่ในตอนนั้น) | รันขั้นที่ 5 กับ staging แล้วเทียบจำนวนฟังก์ชันที่ผู้ไม่ล็อกอินเรียกได้กับผลของ Security Advisor ข้อ 0028 |
