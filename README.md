# Müşteri Paneli (CRM) — Kurulum Adımları

## 1. Veritabanını hazırla
Sunucuda şu komutu çalıştır (migration.sql dosyasını sunucuya kopyaladıktan sonra,
ya da içeriğini kopyala-yapıştır ile doğrudan çalıştır):

```bash
docker exec -i postgres_db psql -U n8n_user -d n8n_data_v2 < migration.sql
```

## 2. GitHub'a yükle
1. github.com'da yeni, boş bir repo oluştur (örn. `crm-panel`)
2. Bu klasördeki tüm dosyaları (server.js, package.json, Dockerfile, public/, .env.example)
   GitHub'ın web arayüzünden "Add file > Upload files" ile sürükle-bırak yükle.
3. Commit et.

## 3. Coolify'da yeni servis oluştur
1. Coolify > + New > "Public Repository" (veya GitHub App bağlıysa kendi reponu seç)
2. Repo adresini yapıştır, branch: main
3. Build Pack: Dockerfile (otomatik algılanmalı, Dockerfile repoda var)
4. Environment Variables kısmına şunları ekle:
   - DB_HOST=postgres_db
   - DB_PORT=5432
   - DB_USER=n8n_user
   - DB_PASSWORD=<gercek sifre>
   - DB_NAME=n8n_data_v2
   - JWT_SECRET=<uzun rastgele bir metin>
   - PORT=3000
5. Domain: panel.hakajer.online
6. Networks: n8n_network (postgres_db container'ına erişebilmesi için — n8n-v2 ile aynı adımı uygula)
7. Deploy'a bas.

## 4. DNS + Tünel
n8n-v2 için yaptığımız gibi:
- Cloudflare DNS'e CNAME kaydı ekle (panel -> aynı tunnel target)
- Cloudflare Zero Trust > Tunnels > Public Hostname > yeni giriş:
  subdomain: panel, domain: hakajer.online, service: HTTP,
  URL: <coolify'ın verdigi container adi>:3000

## 5. İlk satıcı hesabını oluştur
Claude'un sana vereceği hazır SQL INSERT komutunu çalıştır (şifre hash'lenmiş halde).

## Not
Panel şu an test veritabanına (n8n_data_v2) bağlı. Production'a geçmek istediğinde
sadece Coolify'daki DB_NAME değişkenini `n8n_data` yapman yeterli, kod değişmez.
