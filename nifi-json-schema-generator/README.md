# JSON Schema Generator Processor for Apache NiFi

Bu özel NiFi processor'ı giriş JSON verilerini otomatik olarak analiz ederek JSON Schema dokümanı oluşturur. JSON verilerin yapısını ve içeriğini inceleyerek belirtilen JSON Schema standardına uygun bir şema dokümanı üretir.

## Özellikler

- **Farklı JSON Schema Versiyonları**: JSON Schema Draft-07, 2019-09 ve 2020-12 standartlarını destekler
- **Tür Çıkarımı**: Değerlere uygun veri türlerini otomatik olarak belirler
- **Format Algılama**: Email, tarih, UUID ve URI gibi yaygın formatları tanır
- **Dizi ve Nesne İşleme**: İç içe geçmiş karmaşık yapıları düzgün şekilde işler
- **Dairesel Referans Algılama**: Kendine referans veren yapılarda sonsuz özyinelemeyi önler
- **Örnekler**: Kaynak veriden örnek değerler içerebilir
- **Şema Doğrulama**: Oluşturulan şemalar NiFi'ın ValidateJson işlemcisiyle kullanılabilir

## Kurulum

1. Projeyi derleyin:
   ```bash
   cd nifi-custom-processors
   mvn clean package
   ```

2. NAR dosyasını hedef dizinde bulun:
   ```
   nifi-json-schema-generator/target/nifi-json-schema-generator-1.1.nar
   ```

3. Bu dosyayı NiFi'ın `lib` dizinine kopyalayın.

4. NiFi'ı yeniden başlatın.

## Processor Yapılandırması

### Özellikler

| Özellik Adı | Açıklama | Varsayılan |
|---------------|-------------|---------|
| Schema Version | Oluşturulacak JSON Schema sürümü | draft-07 |
| Infer Field Types | Alanlar için veri tiplerinin değerlere göre belirlenip belirlenmeyeceği | true |
| Require All Fields | Tespit edilen tüm alanların şemada gerekli olarak işaretlenip işaretlenmeyeceği | false |
| Schema Title | Oluşturulan şema için kullanılacak başlık | |
| Schema Description | Oluşturulan şema için kullanılacak açıklama | |
| Include Examples | Şemada örnek değerlerin dahil edilip edilmeyeceği | true |
| Max Array Samples | Tür çıkarımı için örneklenecek maksimum dizi öğesi sayısı | 5 |
| Pretty Print | Çıktı şemasının girintili olarak biçimlendirilip biçimlendirilmeyeceği | true |

### İlişkiler

| İlişki | Açıklama |
|--------------|-------------|
| success | Başarıyla oluşturulan JSON Schema'lar bu ilişkiye yönlendirilir |
| failure | Oluşturma işlemi başarısız olan JSON Schema'lar bu ilişkiye yönlendirilir |

## Kullanım Örnekleri

### Temel Kullanım

1. JSONSchemaGeneratorProcessor'ı akış şemasına ekleyin
2. JSON içeriği almak için bir GetFile veya benzer bir processor'a bağlayın
3. İşlemciyi istediğiniz ayarlarla yapılandırın (varsayılanlar genellikle uygundur)
4. "success" ilişkisini şemanın gideceği yere bağlayın
5. İşlemciyi başlatın

### Tür Çıkarımı

İşlemci, JSON verilerinizde bulunan değerleri otomatik olarak analiz ederek uygun JSON Schema türlerini belirler. Örneğin:

Giriş JSON:
```json
{
  "name": "John Doe",
  "age": 30,
  "email": "john@example.com",
  "active": true
}
```

Oluşturulan şema (basitleştirilmiş):
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "name": {
      "type": "string"
    },
    "age": {
      "type": "integer"
    },
    "email": {
      "type": "string",
      "format": "email"
    },
    "active": {
      "type": "boolean"
    }
  }
}
```

### Format Algılama

İşlemci otomatik olarak yaygın formatları algılar:

- E-posta adresleri (`example@domain.com`)
- Tarihler (`2023-05-12`)
- Tarih-saat (`2023-05-12T13:45:00Z`)
- UUID'ler (`123e4567-e89b-12d3-a456-426614174000`)
- URI'ler (`https://example.com`)

### Karmaşık Veri Yapılarını İşleme

İşlemci, iç içe geçmiş nesneleri ve dizileri işleyebilir:

Giriş JSON:
```json
{
  "person": {
    "name": "John",
    "contacts": [
      {
        "type": "email",
        "value": "john@example.com"
      },
      {
        "type": "phone",
        "value": "555-1234"
      }
    ]
  }
}
```

Oluşturulan şema, her seviyede uygun tür tanımlamalarıyla aynı yapıyı koruyacaktır.

## Yaygın Kullanım Modelleri

### Şema Doğrulama Hattı

1. Örnek verilerden şema oluşturmak için bu işlemciyi kullanın
2. Şemayı bir içerik deposunda saklayın
3. Bu şemaya referans veren bir ValidateJson işlemcisi kurun
4. Gelen JSON'ları doğrulama hattı üzerinden yönlendirin

### API Dokümantasyonu

1. JSON API yanıtlarınız için şemalar oluşturun
2. Bu şemaları API dokümantasyonu otomatik olarak oluşturmak için kullanın
3. Daha iyi entegrasyon için şemaları API tüketicileriyle paylaşın

### Veri Kalitesi Güvencesi

1. Bilinen iyi veri örneklerinden şemalar oluşturun
2. Gelen veri akışlarını doğrulamak için bu şemaları kullanın
3. Geçerli ve geçersiz verileri farklı işlemlere yönlendirin

## Sorun Giderme

### Yaygın Sorunlar

1. **Geçersiz JSON Girişi**: Giriş geçerli JSON değilse, işlemci "failure" ilişkisine yönlendirilir.

2. **Büyük Dosyalar için Bellek Sorunları**: Çok büyük JSON dosyaları için NiFi'ın JVM ayarlarını ayarlamanız gerekebilir.

3. **Çok Kısıtlayıcı Şema**: Örnek veri tüm olası varyasyonları temsil etmiyorsa, şema çok katı olabilir. Birden fazla örnekten şemalar birleştirmeyi düşünün.

### Günlükler

Ayrıntılı hata mesajları için `logs/nifi-app.log` konumundaki NiFi günlüklerini kontrol edin.

## İşlemciyi Genişletme

İşlemci, genişletilebilecek modüler bir tasarım kullanır:

- `handleStringConstraints` metodunda yeni format algılayıcılar ekleyin
- `SchemaVersion` enum'unda ek şema sürümleri uygulayın
- `getNodeType` metodunda daha gelişmiş tür çıkarım mantığı ekleyin

## Performans Konuları

- İşlemci, bir şema oluşturmak için tüm JSON yapısını çaprazlar
- Çok büyük belgeler için bu işlem kaynak yoğun olabilir
- Şema oluşturma için verinizin temsili bir alt kümesini kullanmayı düşünün

## Lisans

Bu proje Apache License 2.0 altında lisanslanmıştır.
