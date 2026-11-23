# ต่อเข้า CI: ตรวจ migration ทุกครั้งที่มีการแก้

เอกสารนี้สำหรับ repo ของเว็บที่ต้องการให้ GitHub Actions ตรวจไฟล์ migration อัตโนมัติ การตรวจนี้อ่านไฟล์อย่างเดียว ไม่ต่อฐานข้อมูล และไม่ต้องใช้ key ของ Supabase

**สถานะ:** ไฟล์ตัวอย่างยังไม่เคยรันบน GitHub Actions จริง คำสั่งข้างในทดสอบในเครื่องแล้ว

## วิธีที่สั้นที่สุด: ใช้ action

ใน repo ของเว็บ สร้าง `.github/workflows/webcare.yml`

```yaml
name: webcare
on: pull_request
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
          fetch-depth: 0               # ต้องใช้เฉพาะเมื่อใส่ changed-since
      - uses: mnatee-commits/supabase-web-care@<เลข commit เต็มของรุ่นที่ใช้>
        with:
          migrations: supabase/migrations
          changed-since: origin/${{ github.base_ref }}   # ใส่หรือไม่ก็ได้
          fail-on: high
          lang: th                     # ใส่หรือไม่ก็ได้
```

ล็อก action ด้วยเลข commit เต็มของรุ่นที่อ่านแล้ว ไม่ใช้ชื่อ branch หรือ tag action ตรวจจากไฟล์อย่างเดียว ไม่ติดต่อฐานข้อมูล ค่าที่ใส่ใน `with:` ส่งเข้าสคริปต์เป็นตัวแปรสภาพแวดล้อมและถูกตรวจก่อนใช้ จึงไม่มีค่าใดกลายเป็นคำสั่ง shell ถ้าต้องการ workflow แบบเขียนเองเต็มรูปแบบ อ่านหัวข้อถัดไป

## pre-commit

ถ้าใช้ [pre-commit](https://pre-commit.com) เพิ่มใน `.pre-commit-config.yaml`

```yaml
- repo: https://github.com/mnatee-commits/supabase-web-care
  rev: v1.29.0
  hooks:
    - id: webcare-secrets
    - id: webcare-migrations
      args: [--migrations, supabase/migrations]
```

`webcare-secrets` สแกนไฟล์ที่กำลัง commit ส่วน `webcare-migrations` ตรวจ SQL ทุกครั้งที่ commit ไฟล์ `.sql` ทั้งสองอ่านไฟล์อย่างเดียว

## ขั้นตอน

1. **สร้าง baseline ครั้งเดียว** ในเครื่อง จาก migration ที่มีอยู่

   ```bash
   python -m webcare check --skip secrets --migrations supabase/migrations \
     --write-baseline webcare-baseline.json
   ```

   อ่านรายงานรอบนี้ให้จบก่อน ข้อใดที่ยังเป็นปัญหาจริงในฐานข้อมูลควรแก้ ไม่ใช่บันทึกทิ้งไว้ แล้ว commit ไฟล์ `webcare-baseline.json`

2. **คัดลอก** `docs/examples/webcare-migrations.yml` ไปไว้ที่ `.github/workflows/` ของ repo เว็บ แล้วแก้สามค่าที่ทำเครื่องหมายไว้ในไฟล์

3. **ล็อกรุ่น** ใช้เลข commit เต็มของรุ่นที่อ่านแล้ว (ดูที่หน้า Releases ของ repo) ไม่ใช้ชื่อ branch repo นี้เปิดสาธารณะแล้ว จึงไม่ต้องใช้ key ในการดึง

## สิ่งที่ CI ทำ

- ตรวจสิทธิ์ของฟังก์ชัน `SECURITY DEFINER` และกฎ RLS จากไฟล์ migration ทั้งหมด ตามลำดับชื่อไฟล์
- ข้อที่อยู่ใน baseline ถูกนับในรายงานแต่ไม่ทำให้ล้ม
- ข้อใหม่ระดับสูงทำให้งานล้ม (เปลี่ยนได้ด้วย `--fail-on`)
- แนบ `report.md` เป็นไฟล์ผลลัพธ์ของงาน

## ตรวจเฉพาะสิ่งที่ pull request เปลี่ยน

เพิ่ม `--changed-since origin/main` (ต้องดึง branch หลักมาก่อน เช่นใส่ `fetch-depth: 0` ใน `actions/checkout`) การสแกน key จะอ่านเฉพาะไฟล์ที่ pull request เปลี่ยน และตรวจ SQL เฉพาะเมื่อมีไฟล์ SQL เปลี่ยน บรรทัดขอบเขตในรายงานจะบอกไว้

## แสดงผลบนบรรทัดของ pull request

ใส่ `--sarif` ในคำสั่งตรวจ เครื่องมือจะเขียน `webcare-output/report.sarif` เพิ่ม ขั้นตอนที่ comment ไว้ท้ายตัวอย่าง workflow จะอัปโหลดไฟล์นี้ แล้ว GitHub แสดงแต่ละข้อบนบรรทัดของ migration ที่เป็นต้นเหตุ ต้องเป็น repository สาธารณะ หรือ repository ส่วนตัวที่เปิด GitHub Code Security และต้องให้สิทธิ์ `security-events: write`

ไฟล์นี้มีเฉพาะข้อที่ผูกกับบรรทัดในไฟล์ได้ ได้แก่ key ที่หลุด สิทธิ์ฟังก์ชันที่ได้จากการไล่ไฟล์ SQL และผลของ pgrls ซึ่งจะวางบนคำสั่งแรกในไฟล์ที่สร้างตาราง view ฟังก์ชัน หรือ policy นั้น (ค้นจากข้อความ ไม่ได้แยกไวยากรณ์) ข้ออื่นอยู่ใน `report.md` ตามเดิม และไฟล์บันทึกจำนวนข้อที่ไม่ได้ใส่ไว้ ไฟล์ SARIF ที่ว่างจึงไม่ได้แปลว่าไม่มีปัญหา

## ข้อจำกัด

- ผลขึ้นกับลำดับไฟล์ ถ้าชื่อไฟล์ไม่เรียงตามลำดับที่รันจริง ให้ระบุทีละไฟล์ด้วย `--sql-file`
- ไฟล์ที่ชื่อขึ้นต้นด้วย `ROLLBACK_` ถูกข้าม
- การตรวจจากไฟล์ไม่เห็นสิ่งที่แก้ตรงในฐานข้อมูลโดยไม่ผ่าน migration ต้องใช้การตรวจจากฐานจริงเป็นระยะคู่กัน
- baseline ผูกกับชื่อ rule ชื่อวัตถุ และชื่อไฟล์ ไม่ผูกกับเลขบรรทัด ข้อใหม่ของ rule เดิมบนวัตถุเดิมในไฟล์เดิมจึงถูกนับว่าอยู่ใน baseline แล้ว
- ล็อกเครื่องมือไว้ที่ commit ที่ตรวจแล้วเสมอ อย่าใช้ชื่อกิ่ง
