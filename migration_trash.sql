-- CRM Panel Soft Delete / Çöp Kutusu Migration
ALTER TABLE leads ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP DEFAULT NULL;
