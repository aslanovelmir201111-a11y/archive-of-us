# 🦢 The Archive of Us — Təhlükəsiz Python Backend & Veb Tətbiqi

Bu layihə **"The Archive of Us"** şəxsi xatirə və sevgi arxivinin frontend interfeysi üçün hazırlanmış yüksək səviyyəli, təhlükəsiz və çoxcihazlı sinxronizasiyanı dəstəkləyən **Python (FastAPI + SQLite)** backend sistemidir.

---

## 🛡️ Həll Edilmiş Kritik Təhlükəsizlik Problemləri

Orijinal HTML faylında olan bütün kritik zəifliklər analiz edilmiş və backend səviyyəsində aradan qaldırılmışdır:

| # | Zəiflik (Vulnerability) | Orijinal Vəziyyət | Backend ilə Yeni Təhlükəsizlik Həlli |
|---|---|---|---|
| **1** | **Açıq Parol (Hardcoded Credentials - CWE-798)** | `const ACCESS_CODE = "21082026";` birbaşa JavaScript kodunda açıq saxlanılırdı. Saytın mənbə koduna baxan hər kəs parolu dərhal görürdü. | Parol JavaScript-dən tamamilə silindi. Server tərəfində **100,000 iterasiyalı PBKDF2-HMAC-SHA256** alqoritmi və 16-baytlıq təsadüfi duz (salt) ilə heşlənərək SQLite bazasında qorunur. |
| **2** | **Yalnız Müştəri Tərəfli Qoruma (CWE-602)** | Sadəcə CSS ilə `#gate` gizlədilir, `#site` göstərilirdi. F12 (DevTools) ilə heç bir kod yazmadan sayta girmək olurdu. | **Həqiqi Sessiya və Token Autentifikasiyası**. Hər bir API sorğusunda kriptoqrafik 256-bit təhlükəsizlik tokeni yoxlanılır. İcazəsiz sorğular `401 Unauthorized` alır. |
| **3** | **Möhürlənmiş Məktubların Sızması (Sealed Letters Leak)** | Gələcək tarix üçün yazılmış gizli məktubların tam mətni brauzerə yüklənirdi və konsoldan `data.letters` yazmaqla asanlıqla oxunurdu. | **Server Tərəfli Tarix Yoxlaması**. Əgər məktubun tarixi bugünkü server tarixindən böyükdürsə, backend `body` sahəsini müştəriyə **ƏSLA GÖNDƏRMİR** (`body: null`). Yalnız həmin gün çatdıqda məktub server tərəfindən açılır. |
| **4** | **Brute-Force (Kobud Güc) Hücumları (CWE-307)** | 8 rəqəmli kod skript vasitəsilə saniyələr ərzində yoxlanılıb sındırıla bilərdi. | **IP Əsaslı Rate Limiter**. 5 dəqiqə ərzində 5 ardıcıl uğursuz cəhd olarsa, həmin IP 15 dəqiqə müddətinə avtomatik bloklanır (`429 Too Many Requests`). |
| **5** | **Məlumat İtkisi və Sinxronizasiyanın Olmaması** | Bütün məlumatlar brauzerin `localStorage`-ində qalırdı. Brauzer təmizlənəndə xatirələr silinirdi və cütlük müxtəlif telefonlardan bir-birinin yazdıqlarını görə bilmirdi. | **Davamlı SQLite Verilənlər Bazası (`archive.db`)**. Bütün xatirələr, şəkillər və qeydlər mərkəzləşdirilmiş şəkildə saxlanılır və real vaxt rejimində bütün cihazlar arasında sinxronlaşır. |
| **6** | **Base64 Şəkillər və 5MB LocalStorage Limiti** | Şəkillər base64 kimi brauzer yaddaşına yazılırdı. 2-3 şəkildən sonra brauzer limiti dolur və sayt çökürdü. | **Təhlükəsiz Şəkil Yükləmə API-si (`/api/upload`)**. Şəkillər yoxlanılaraq diskdə (`uploads/`) saxlanılır. Magic bytes yoxlanışı ilə fayl maskalanmasının qarşısı alınır. |
| **7** | **XSS və Məlumatların Manipulyasiyası** | Təmizlənməmiş mətnlər və xarici URL-lər inyeksiya riski daşıyırdı. | Pydantic sxemləri ilə ciddi tip, uzunluq və format validasiyası aparılır. |
| **8** | **Müştəri Saatının Manipulyasiyası** | Kompüterin saatını dəyişməklə taymer və gələcək məktublar manipulyasiya edilə bilərdi. | Taymer və tarixlər **Server Vaxtı (`/api/time`)** ilə sinxronlaşdırılır. |

---

## 📁 Layihə Strukturu

```text
New folder (3)/
├── app.py                  # Bütün backend (FastAPI, SQLite bazası, Auth, API marşrutları)
├── requirements.txt        # Tələb olunan Python kitabxanaları
├── run.bat                 # Windows üçün 1 kliklə başlatma faylı
├── run.ps1                 # PowerShell ilə başlatma skripti
├── README.md               # Sənədləşmə və təlimat
├── archive.db              # SQLite məlumat bazası (avtomatik yaradılır)
├── static/
│   └── index.html          # Backend-ə qoşulmuş və qorunan frontend
└── uploads/                # Yüklənən şəkillərin təhlükəsiz qovluğu
```

---

## 🚀 Saytın Başladılması

### 1-ci Üsul: Sadəcə 1 kliklə (Ən Asan Yol)
Qovluqdakı **`run.bat`** faylının üzərinə iki dəfə klikləyin.

### 2-ci Üsul: Terminal / PowerShell ilə
Terminalı açıb bu əmri icra edin:
```bash
python app.py
```

Server işə düşdükdən sonra brauzerinizdə bu ünvana daxil olun:
👉 **`http://127.0.0.1:8000`**

---

## 🔑 Giriş və Arxiv Kodu

- **İlkin Arxiv Kodu:** `210826`
- **Kodu Dəyişdirmək:**
  Sayta daxil olduqdan sonra **"Editor's Desk"** bölməsinə keçin. Orada **"Change Archive Access Code"** formu vasitəsilə kodu istədiyiniz yeni güclü şifrə ilə əvəzləyə bilərsiniz.
- **Arxivi Kilidləmək:**
  Yuxarı sağ küncdəki **"🔒 Lock Archive"** düyməsini sıxmaqla arxivi dərhal bağlaya bilərsiniz.

## 🔄 Real-time Canlı Sinxronizasiya

Arxiv avtomatik **canlı sinxronizasiya** ilə təchiz olunub:
- Siz və ya qarşı tərəf hər hansı yeni foto, xatirə, məktub və ya plan əlavə etdikdə/sildikdə serverdə versiya yenilənir.
- Digər cihazlar hər 3 saniyədən bir arxa fonda dəyişiklikləri yoxlayır və səhifəni yeniləmədən (reload etmədən) yeni məlumatları avtomatik ekranda göstərir!
- Sayt pəncərəsinə qayıtdıqda (tab dəyişdikdə) ən son məlumatlar dərhal ekrana gəlir.

---

## 🌐 Saytı İnternetdə Canlı Veb Sayta Çevirmək (Online Hosting)

Saytın internetdə 24/7 işləməsi və dünyanın istənilən yerindən daxil ola bilməyiniz üçün 2 asan və pulsuz üsul var:

### 1-ci Üsul: Render.com (Tamamilə Pulsuz və Daimi HTTPS Link)
1. [GitHub](https://github.com)-da pulsuz hesab açıb bu qovluqdakı faylları yeni bir repo-ya yükləyin (və ya GitHub Desktop ilə göndərin).
2. [Render.com](https://render.com)-a daxil olub GitHub ilə qeydiyyatdan keçin.
3. **"New +" -> "Web Service"** seçin və həmin GitHub repo-nu seçin.
4. Render parametrləri avtomatik tanıyacaq (`render.yaml` və `Procfile` artıq hazırdır):
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python app.py`
5. **"Deploy"** düyməsini sıxın! Bir neçə dəqiqə ərzində saytınız internetdə canlı olacaq:
   👉 Məsələn: `https://archive-of-us.onrender.com`

### 2-ci Üsul: Cloudflare Tunnel / Ngrok (Kompüterinizdən Dərhal İnternetə Açmaq)
Əgər GitHub-a yükləmədən kompüterinizdən dərhal qarşı tərəfə link göndərmək istəyirsinizsə:
1. `python app.py` ilə serveri işə salın.
2. Terminalda pulsuz Cloudflare Tunnel işə salın:
   ```bash
   npx cloudflared tunnel --url http://127.0.0.1:8000
   ```
   (və ya `ngrok http 8000`).
3. Sizə verilən təhlükəsiz HTTPS linkini (`https://xxxx.trycloudflare.com`) qarşı tərəfə göndərin. Kodsuz (`210826`) heç kim daxil ola bilməyəcək!

---

Cütlük hər ikisi eyni Wi-Fi şəbəkəsində olduqda telefonlarından da arxivə daxil ola bilər:
1. Serveri bütün şəbəkə üçün başladın:
   ```bash
   python -m uvicorn app:app --host 0.0.0.0 --port 8000
   ```
2. Kompüterinizin yerli IP ünvanını öyrənin (məsələn: `192.168.1.5`).
3. Telefonda brauzeri açıb daxil olun:
   👉 **`http://192.168.1.5:8000`**

---

## 🔌 Əsas API Endpoint-ləri

- `POST /api/auth/login` — Arxiv kodunu yoxlayır, sessiya tokeni yaradır (Rate-limit qorumalı).
- `POST /api/auth/logout` — Cari sessiyanı bağlayır.
- `GET /api/auth/check` — Giriş vəziyyətini yoxlayır.
- `POST /api/auth/change-code` — Arxiv kodunu dəyişir.
- `GET /api/time` — Dəqiq server vaxtını və taymeri qaytarır.
- `GET/POST/DELETE /api/chronicles` — Aylıq fəsillər (Chronicles).
- `GET/POST/DELETE /api/catalogue` — Xırda detallar kataloqu.
- `GET/POST/DELETE /api/letters` — Möhürlənmiş gizli məktublar (Tarixi çatmayanların mətni gizlədilir).
- `GET/POST/DELETE /api/favorites` — Əziz mesajlar və ekran görüntüləri.
- `GET/POST/DELETE /api/nights` — Xatirə gecələri və fotolar.
- `GET/POST/DELETE /api/matching` — Uyğunlaşan qeydlər və musiqilər.
- `GET/POST/PUT/DELETE /api/todos` — Planlar siyahısı (To-do list).
- `POST /api/upload` — Şəkil yükləmə (Tip, ölçü və magic bytes yoxlaması).
- `GET /api/backup/export` — Bütün arxivi JSON formatında kompüterə yükləmə.
- `POST /api/backup/import` — JSON faylından arxivi tam bərpa etmə.
- `POST /api/backup/reset` — Arxiv məlumatlarını ilkin başlanğıc vəziyyətinə gətirmə.
