# Log Analiz Ajanı (yerel LLM)

Sürekli akan sistem loglarını izleyen ve her zaman penceresi için karar veren bir motor:

| Karar | Anlamı |
|---|---|
| `normal` | Olağan trafik ya da bağlamda yetkili olduğu belirtilen etkinlik |
| `dinamik_hata` | Saldırı olmayan, çalışma anında oluşan operasyonel sorun (kaynak tükenmesi, bellek sızıntısı, hatalı sürüm) |
| `imzasiz_saldiri` | Hiçbir imzaya uymayan ama davranışı kötü niyet gösteren etkinlik |
| `bilinen_saldiri` | İmza kuralına uyan tanınmış saldırı (SQLi payload, saldırı aracı, brute force eşiği) |
| `belirsiz` | Sapma var ama sınıflandırmaya kanıt yetmiyor |

Her karar şunları içerir: başlık, özet, önem ve güven puanı, insan incelemesi gerekip gerekmediği,
kanıt satırları (`web:4935` gibi kimliklerle), etkilenen varlıklar, saldırıysa MITRE taktiği,
hataysa olası kök neden ve önerilen adımlar.

LLM yerelde, Ollama üzerinden çalışır; loglar makineden çıkmaz.

## Mimari

```
 logs/*.log (sürekli büyüyen dosyalar)
     │  Tailer: tail -f gibi okur                                  engine.py
     ▼
 Ayrıştırma: nginx / syslog / JSON / süreç kayıtları → Event        parsers.py
     ▼
 60 sn'lik pencereler (zaman damgasına göre, gecikmeli kapanış)       engine.py
     ▼
 Dedektör (her pencere, ucuz)                                         detector.py
   • 16 sayısal öznitelik → öğrenilmiş baseline'a göre z-skoru
   • Yenilik: daha önce görülmemiş IP, kullanıcı@IP, URL kalıbı, süreç, hata mesajı
   • Küçük bir imza kümesi (bilinen saldırıyı imzasızdan ayırmak için)
     │ sapma yok → "normal" (LLM çağrılmaz, baseline öğrenmeye devam eder)
     ▼ sapma var
 LLM yargıcı (Ollama, JSON şemasına bağlı çıktı)                       judge.py
   girdi: sapmalar + yenilikler + imza eşleşmeleri + bağlam + önceki 3 karar
          + gruplanarak seçilmiş ≤40 kanıt satırı
     ▼
 results/decisions.jsonl  +  konsol akışı
```

**Neden iki katman?** Yerel LLM pencere başına 10-60 saniye sürer. Dedektör pencerelerin çoğunu
LLM'siz geçirir; LLM yalnızca "ne oluyor?" sorusunun cevabı gereken yerde çalışır.
`--llm-all` ile her pencereyi LLM'e sorup bu ayrımın neyi kaçırdığını ölçebilirsiniz.

**İmzasız tespit nasıl?** Dedektör saldırıyı tanımaz; yalnızca öğrenilmiş normalden sapmayı görür.
Sapmanın hata mı saldırı mı olduğunu LLM, aktör davranışına ve bağlama bakarak ayırır.
Baseline yalnızca temiz pencerelerden öğrenir. LLM'in "normal" dediği sapmalardan ise yalnızca
yeni varlıkları öğrenir, uç sayısal değerleri öğrenmez.

## Sahte loglar ve senaryolar

`python main.py generate` 4 kaynakta yaklaşık 11 bin satırlık, 54 dakikalık bir zaman çizelgesi üretir.
İlk 10 dakika temizdir (baseline öğrenme), ardından şu senaryolar gelir:

| Senaryo | Gerçek sınıf | Ne oluyor |
|---|---|---|
| db_pool | dinamik_hata | DB bağlantı havuzu tükenir, 503 ve 30 sn zaman aşımları |
| sqli_scan | bilinen_saldiri | sqlmap ile SQLi ve path traversal |
| cred_stuffing | imzasiz_saldiri | 70 IP'den yavaş, dağıtık parola denemesi; sonunda bir hesap ele geçirilir |
| scanner | normal (decoy) | Yetkili Nessus taraması: çok sayıda 404, ama context.json'da yetkili |
| bad_deploy | dinamik_hata | 2.4.1 sürümünden sonra checkout'ta NullPointerException |
| webshell | imzasiz_saldiri | Avatar yüklemesiyle php dosyası, www-data altında `sh -c` komutları |
| idor | imzasiz_saldiri | Meşru kullanıcı başkalarının profillerini sırayla çeker |
| memleak | dinamik_hata | Heap dolar, OutOfMemoryError, servis yeniden başlar, 502'ler |
| exfil | imzasiz_saldiri | Yeni IP'den python-requests ile toplu müşteri verisi indirme |
| ssh_brute | bilinen_saldiri | Tek IP'den klasik SSH brute force |
| backup | normal (decoy) | Planlı yedekleme: exfil'e çok benzer ama yetkili |

Decoy senaryolar özellikle zordur: dedektör bunları da tetikler. Doğru kararı LLM ancak
`logs/context.json`'daki yetkili etkinlik bilgisini kullanarak verebilir.
`logs/ground_truth.json` yalnızca değerlendirme içindir; motor bu dosyayı hiç okumaz.

## Kurulum

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
ollama pull qwen2.5:14b      # önerilen; kurulu herhangi bir model de olur
```

## Kullanım

```powershell
# Toplu: üret → analiz et → değerlendir
python main.py generate
python main.py run --model qwen2.5:14b
python main.py evaluate

# Canlı demo (iki terminal)
python main.py generate --live --speed 20     # 1. terminal: loglar gerçek zamanlı akar
python main.py run --follow                   # 2. terminal: ajan akışı izler ve karar basar

# LLM olmadan hattı denemek
python main.py run --mock --out results_mock/decisions.jsonl
python main.py evaluate --decisions results_mock/decisions.jsonl
```

Ortam değişkenleri: `LOGAGENT_MODEL`, `OLLAMA_HOST`, `LOGAGENT_NUM_CTX` (varsayılan 12288).

## Değerlendirme çıktısı

- **Dedektör:** anomali pencerelerinin kaçı yakalandı, temiz ve decoy pencerelerde kaç kez tetiklendi
- **Senaryo bazında:** doğru sınıfla tespit edildi mi, kaç dakika gecikmeyle
- **Sınıf bazında** precision / recall / F1 ve karışıklık matrisi
- **Uydurma kanıt oranı:** LLM'in kendisine gösterilmeyen satır kimliği uydurma oranı
- **İnsan incelemesi oranı** ve ortalama LLM süresi

Farklı modelleri ayrı `--out` dosyalarına yazıp karşılaştırmak raporda doğrudan bir deney olur.
`--seed` ile farklı gürültüye sahip log setleri üretilebilir.
