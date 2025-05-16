# LDAP Protokolünde Control Objelerini Kullanma

LDAP (Lightweight Directory Access Protocol) sorguları yapılırken, standart LDAP işlemlerinin yeteneklerini genişletmek için özel kontroller (controls) kullanabilirsiniz. Bu belge, LDAP kontrollerinin ne olduğunu, nasıl kullanıldığını ve özellikle nTSecurityDescriptor gibi özel niteliklere erişmek için nasıl yapılandırılacağını açıklar.

## LDAP Kontrolleri Nedir?

LDAP kontrolleri, standart LDAP işlem çağrılarını değiştiren veya genişleten ek bilgiler sağlayan mekanizmalardır. Her LDAP kontrolü şu bileşenlerden oluşur:

1. **OID (Object Identifier)**: Kontrolü benzersiz olarak tanımlayan bir sayı dizisi (örn: 1.2.840.113556.1.4.801)
2. **Kritiklik Değeri**: Kontrolün "kritik" olup olmadığını belirten bir bayrak (true/false)
3. **Kontrol Değeri**: Kontrolün davranışını belirleyen isteğe bağlı bir değer (bazen BER kodlanmış)

## Yaygın LDAP Kontrolleri

| OID | İsim | Açıklama |
|-----|------|----------|
| 1.2.840.113556.1.4.319 | LDAP_PAGED_RESULT_OID_STRING | Sayfalanmış arama sonuçları |
| 1.2.840.113556.1.4.801 | LDAP_SERVER_SD_FLAGS_OID | Güvenlik tanımlayıcısı bayrakları |
| 1.2.840.113556.1.4.417 | LDAP_SERVER_SHOW_DELETED_OID | Silinmiş nesneleri göster |
| 1.2.840.113556.1.4.619 | LDAP_SERVER_LAZY_COMMIT_OID | Tembel yazma işlemi |
| 1.2.840.113556.1.4.1781 | LDAP_SERVER_PERMISSIVE_MODIFY_OID | Esnek değişiklik işlemi |
| 1.2.840.113556.1.4.473 | LDAP_SERVER_SORT_OID | Sonuçları sırala |
| 1.2.840.113556.1.4.841 | LDAP_SERVER_DIRSYNC_OID | Dizin senkronizasyonu |

## LDAP Kontrollerini Kullanma

LDAP kontrollerini eklemek için format genellikle şöyledir:
```
OID|kritiklik|değer
```

Örnek:
```
1.2.840.113556.1.4.801|true|7
```

Bu örnekte:
- **OID**: 1.2.840.113556.1.4.801 (SD Flags kontrolü)
- **Kritiklik**: true (sunucu bu kontrolü desteklemiyorsa işlem başarısız olur)
- **Değer**: 7 (OWNER + GROUP + DACL bayraklarının toplamı)

## SD Flags Kontrolü (1.2.840.113556.1.4.801)

Bu kontrol, güvenlik tanımlayıcısı niteliklerinin (nTSecurityDescriptor) hangi bölümlerinin LDAP işlemlerinde kullanılacağını belirtir. Değer, aşağıdaki bayrakların bitkisel OR'u ile oluşturulur:

| Bayrak | Değer | Açıklama |
|--------|-------|----------|
| OWNER_SECURITY_INFORMATION | 0x01 (1) | Sahip bilgisi |
| GROUP_SECURITY_INFORMATION | 0x02 (2) | Grup bilgisi |
| DACL_SECURITY_INFORMATION | 0x04 (4) | DACL bilgisi (erişim hakları) |
| SACL_SECURITY_INFORMATION | 0x08 (8) | SACL bilgisi (denetim/audit) |

### Yaygın SD Flags Değerleri

| Değer | Bileşenler | Açıklama |
|-------|------------|----------|
| 7 | OWNER + GROUP + DACL | Normal kullanıcıların erişebileceği standart erişim hakları |
| 15 | OWNER + GROUP + DACL + SACL | Tam güvenlik tanımlayıcısı (genellikle yönetici hakları gerektirir) |
| 4 | Sadece DACL | Sadece erişim kontrol listesi |
| 8 | Sadece SACL | Sadece denetim (audit) bilgisi |

## BER Kodlanmış Değerler

Birçok LDAP kontrolü, BER (Basic Encoding Rules) formatında kodlanmış değerler kullanır. SD Flags değeri için BER kodlaması:

```
0x30, 0x03, 0x02, 0x01, (değer)
```

Burada:
- 0x30: SEQUENCE tipi
- 0x03: Uzunluk (3 bayt)
- 0x02: INTEGER tipi
- 0x01: Integer uzunluğu (1 bayt)
- (değer): Bayrak değeri (örn: 0x07 = 7, 0x0F = 15)

## Örnek Senaryolar

### nTSecurityDescriptor'ın DACL Bölümüne Erişim

```
LDAP Controls: 1.2.840.113556.1.4.801|true|4
```

Bu kontrol, nTSecurityDescriptor niteliğinin sadece DACL bölümünü okur/yazar.

### Tam Güvenlik Tanımlayıcısına Erişim (Yönetici Hakları Gerektirir)

```
LDAP Controls: 1.2.840.113556.1.4.801|true|15
```

Bu kontrol, nTSecurityDescriptor niteliğinin tüm bölümlerini (OWNER + GROUP + DACL + SACL) okur/yazar.

### Silinmiş Nesneleri Gösterme + DACL Erişimi

```
LDAP Controls: 1.2.840.113556.1.4.801|true|4,1.2.840.113556.1.4.417|false|
```

Bu kombinasyon, hem silinmiş nesneleri arama sonuçlarına dahil eder hem de güvenlik tanımlayıcılarının DACL bölümlerine erişir.

## nTSecurityDescriptor Sonuçlarını Yorumlama

LDAP sorgusundan dönen nTSecurityDescriptor sonuçları şuna benzer:

```
"nTSecurityDescriptor": "Security Descriptor (Rev:1, Flags:0x14 SE_DACL_PRESENT SE_SACL_PRESENT) Offsets: Owner=8388, Group=8416, SACL=20, DACL=2460"
```

Bu yanıt şunları gösterir:
- **Revizyon**: 1
- **Bayraklar**: 0x14 (SE_DACL_PRESENT + SE_SACL_PRESENT)
- **Offset Değerleri**: OWNER, GROUP, SACL ve DACL'nin ikili veri içindeki konumları

## İpuçları ve En İyi Uygulamalar

1. **Yetki Gereklilikleri**:
   - DACL'e normal kullanıcılar erişebilir
   - SACL'e genellikle sadece yöneticiler erişebilir
   - Değişiklik yapmak için ek izinler gerekebilir

2. **LDAP İstemcisinin Yapılandırılması**:
   - İstemcinizin kontrolleri desteklediğinden emin olun
   - Kritik kontroller için hata işleme kodunu ekleyin

3. **Değer Formatı**:
   - Bazı istemciler BER kodlamasını otomatik yapar
   - Diğerleri için manuel olarak bayt dizisini oluşturmanız gerekebilir

4. **Sayfalama ve Kontrol Çakışmaları**:
   - Bazı LDAP kontrolleri sayfalama (paging) kontrolü ile birlikte çalışmayabilir
   - Bu durumda sayfalamayı devre dışı bırakın veya kontrolleri bir talep içinde birleştirin

## InsecureLDAPProcessor ile LDAP Kontrolleri Kullanma

InsecureLDAPProcessor, Apache NiFi için geliştirilmiş özel bir işlemci olup, LDAP işlemlerinde kontrol objelerini kolayca kullanmanıza olanak tanır. Aşağıda, bu işlemciyi kullanarak nTSecurityDescriptor gibi özel niteliklere erişim için yapılandırma örnekleri bulunmaktadır.

### Temel Yapılandırma

InsecureLDAPProcessor'ı LDAP kontrolleriyle kullanmak için şu özellikleri ayarlayın:

| Özellik | Değer | Açıklama |
|---------|-------|----------|
| LDAP URL | ldap://your-dc.example.com:389 | Active Directory sunucunuzun adresi |
| LDAP Operation | SEARCH | LDAP arama işlemi |
| Base DN | DC=example,DC=com | Aramanın başlayacağı DN |
| Search Filter | (objectClass=user) | LDAP arama filtresi |
| Return Attributes | cn,distinguishedName,nTSecurityDescriptor | Döndürülecek nitelikler |
| Binary Attributes | nTSecurityDescriptor | İkili olarak işlenecek nitelikler |
| LDAP Controls | 1.2.840.113556.1.4.801\|true\|7 | SD Flags kontrolü (OWNER+GROUP+DACL) |
| Control Value Format | (boş bırakın) | Otomatik format kullanımı |

### Farklı Senaryolar için LDAP Kontrolleri

#### Sadece DACL'e Erişim

```
LDAP Controls: 1.2.840.113556.1.4.801|true|4
```

#### Tam Güvenlik Tanımlayıcısına Erişim (SACL dahil)

```
LDAP Controls: 1.2.840.113556.1.4.801|true|15
```

#### Silinmiş Nesneleri Gösterme ile Birlikte

```
LDAP Controls: 1.2.840.113556.1.4.801|true|7,1.2.840.113556.1.4.417|false|
```

#### LDAP Sorgularında Sayfalama Kullanımı

InsecureLDAPProcessor, sayfalama ile kontrolleri birlikte kullanabilir. "Page Size" özelliğini ayarlayarak (örn. 1000) ve LDAP kontrollerini ekleyerek her ikisini de birlikte kullanabilirsiniz.

### Sonuçların Yorumlanması

InsecureLDAPProcessor'dan dönen sonuç şuna benzer:

```json
{
  "entries": [
    {
      "dn": "CN=User,CN=Users,DC=example,DC=com",
      "attributes": {
        "cn": "User",
        "nTSecurityDescriptor": "Security Descriptor (Rev:1, Flags:0x14 SE_DACL_PRESENT SE_SACL_PRESENT) Offsets: Owner=8388, Group=8416, SACL=20, DACL=2460"
      }
    }
  ],
  "count": 1
}
```

Bu çıktı, nTSecurityDescriptor niteliğinin temel özelliklerini (revizyon, bayraklar, offset değerleri) gösterir.

## Resmi Referans Belgeleri

LDAP kontrolleri ve güvenlik tanımlayıcıları hakkında daha fazla bilgi için şu resmi belgelere başvurabilirsiniz:

1. **[MS-ADTS] Active Directory Technical Specification**
   - [5.1.3.2 LDAP Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/974856fe-cfd4-4fe1-93c4-16646641e440) - LDAP kontrolleri ve OID'leri hakkında detaylı bilgi
   - [3.1.1.3.4.1.14 LDAP_SERVER_SD_FLAGS_OID](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea) - SD Flags kontrolünün detaylı açıklaması

2. **[MS-DTYP] Windows Data Types**
   - [2.4 Security Descriptor](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d) - Güvenlik tanımlayıcısı yapısının detaylı açıklaması
   - [2.4.6 SECURITY_DESCRIPTOR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c92a27b1-c772-4fa7-a432-15df5b1b66a6) - Güvenlik tanımlayıcısı yapısı

3. **[MS-SAMR] Security Account Manager (SAM) Remote Protocol**
   - [3.1.5.12 Access Control on Active Directory Objects](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/da88df9c-4cbb-449b-af65-6b35dcd52fec) - Erişim kontrolü ve güvenlik tanımlayıcıları hakkında bilgi

4. **LDAP RFC Belgeleri**
   - [RFC 4511](https://tools.ietf.org/html/rfc4511) - LDAP: Protokol
   - [RFC 4512](https://tools.ietf.org/html/rfc4512) - LDAP: Dizin Bilgi Modelleri

## Sonuç

LDAP kontrolleri, LDAP işlemlerinin yeteneklerini önemli ölçüde genişletir. Özellikle güvenlik tanımlayıcısı (nTSecurityDescriptor) gibi karmaşık niteliklere erişmek için SD Flags kontrolünü anlamak ve kullanmak önemlidir. Bu kontroller, arama, okuma ve yazma işlemlerinin hangi güvenlik tanımlayıcısı bileşenlerini içereceğini belirlemek için kullanılır.

Bu bilgiyi kullanarak, Active Directory ve diğer LDAP dizinlerinde bulunan güvenlik yapılandırmalarını etkin bir şekilde sorgulayabilir, analiz edebilir ve değiştirebilirsiniz.
