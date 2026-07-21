-- leads tablosuna panel icin gerekli kolonlari ekle (varsa dokunmaz)
ALTER TABLE leads ADD COLUMN IF NOT EXISTS call_status TEXT;
ALTER TABLE leads ADD COLUMN IF NOT EXISTS call_note TEXT;
ALTER TABLE leads ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();

-- saticilarin giris yapacagi tablo
CREATE TABLE IF NOT EXISTS sellers (
  id SERIAL PRIMARY KEY,
  phone TEXT UNIQUE NOT NULL,
  name TEXT,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);
