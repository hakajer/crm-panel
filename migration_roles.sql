-- CRM Panel Rol Mimarisi Migration (Admin / Personel)
ALTER TABLE sellers ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'seller';
UPDATE sellers SET role = 'admin' WHERE id = (SELECT id FROM sellers ORDER BY id ASC LIMIT 1);
