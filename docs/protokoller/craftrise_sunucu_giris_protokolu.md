---

layout: default

title: CraftRise Sunucu Giriş Protokolü

parent: Protokoller

nav_order: 1

---

# CraftRise Giriş Protokolü Teknik Rehberi

Bu doküman, CraftRise sunucu giriş protokolünün teknik detaylarını açıklar. Protokolün nasıl işlediğini, paket yapılarını ve şifreleme mantığını adım adım anlatır.

## 1. Ağ Bağlantısı ve Protokol Yapısı

CraftRise sunucusu **TCP** üzerinden özel bir **Netty Object Serialization** protokolü kullanır.

*   **Sunucu Adresi:** `185.255.92.10`
*   **Port:** `4754`
*   **Paket Yapısı:** Her paket, verinin uzunluğunu belirten 4 baytlık bir başlık (header) ile başlar, ardından Netty'ye özgü nesne başlıkları ve veri gelir.

### Paket Formatı
İstemci tarafından gönderilen her paket şu bayt dizilimine sahiptir:

```
[Length (4 Byte)] [0x05] [0x74] [StrLen (2 Byte)] [Payload (String)]
```

*   `Length`: Paketin toplam uzunluğu (Header hariç veri uzunluğu + 4).
*   `0x05 0x74`: Netty Object Serialization "String" belirteci.
*   `StrLen`: Gönderilen JSON verisinin uzunluğu.

**Genel Implementasyon:**
```go
func sendNettyPacket(conn net.Conn, jsonPayload string) error {
    payloadBytes := []byte(jsonPayload)
    strLen := len(payloadBytes)
    packetLen := 4 + strLen // Netty header + payload

    buf := new(bytes.Buffer)
    buf.WriteByte(byte(packetLen >> 24))
    buf.WriteByte(byte(packetLen >> 16))
    // ... (Length yazılır)
    buf.WriteByte(0x05) 
    buf.WriteByte(0x74) 
    buf.WriteByte(byte(strLen >> 8))
    buf.WriteByte(byte(strLen))
    buf.Write(payloadBytes)
    // ...
}
```

---

## 2. Adım 1: Handshake (`getHashs`)

Giriş işleminin ilk adımı sunucudan güncel hash veya doğrulama verilerini istemektir. Bu adım atlanırsa sunucu sonraki `tryLogin` paketini reddeder.

*   **Gönderilen Veri:** `{"messageType":"getHashs"}`
*   **Sunucu Cevabı:** Yaklaşık 90KB boyutunda büyük bir veri paketi.

**Önemli Detay:**
Sunucudan gelen bu büyük cevabın **tamamen okunup tüketilmesi** (drain) gerekmektedir. Eğer bu veri tamamen okunmazsa, bir sonraki adımda gönderilen giriş isteğinin cevabı ile bu veriler karışabilir (TCP Stream yapısı nedeniyle).

**Genel Implementasyon:**
```go
// Handshake Başlat
handshakeJson := `{"messageType":"getHashs"}`
sendNettyPacket(conn, handshakeJson)

// Cevabı Tüket (Drain Loop)
conn.SetReadDeadline(time.Now().Add(10 * time.Second))
// Döngü ile conn.Read çağrılarak tüm veri (~90KB) okunur.
```

---

## 3. Adım 2: Güvenlik Payload'ı Oluşturma

Giriş işleminin en kritik kısmı, `tryLogin` paketinde gönderilecek olan kriptografik değerlerin üretimidir. Bu değerler, sunucuya istemcinin meşru olduğunu ve şifresinin doğru olduğunu kanıtlar.

### Şifreleme Anahtarı
*   **Default Key:** `2650053489059452` (16 Byte, AES için)

### A. Şifreli Anahtar Üretimi
key değeri, kullanıcı adı, şifre ve zaman damgasını içeren bir yapının çok katmanlı şifrelenmesiyle oluşturulur.

**Algoritma Zinciri:**
1.  **Ham Veri:** `KullanıcıAdı + "###" + MD5(Şifre) + "###" + ZamanDamgası`
2.  **Base64:** Ham veri Base64 kodlanır.
3.  **AES Şifreleme (Katman 1):** Base64 verisi AES ile şifrelenir.
4.  **Base64:** Şifreli veri Base64 stringine çevrilir.
5.  **AES Şifreleme (Katman 2):** Bu string tekrar AES ile şifrelenir.
6.  **Base64 (Final):** Son binary veri tekrar Base64 stringine çevrilir.

**Genel Implementasyon:**
```go
passHash := md5Hash(password)
original := fmt.Sprintf("%s###%s###%s", username, passHash, timestamp)

// Zincirleme İşlemler
step1 := base64.StdEncoding.EncodeToString([]byte(original))
step2Bytes := aesEncrypt(step1, DefaultKey)
step2 := base64.StdEncoding.EncodeToString(step2Bytes)
step3Bytes := aesEncrypt(step2, DefaultKey) 
step3 := base64.StdEncoding.EncodeToString(step3Bytes)

// Final Key
finalKey := base64.StdEncoding.EncodeToString([]byte(step3))
```

### B. Hash Zinciri (`sum`, `sumBig`...)
Üretilen `finalKey` kullanılarak doğrulama hash'leri üretilir. Bu hash'ler birbirine bağlıdır.

1.  **sum:** `MD5(finalKey)`
2.  **sumBig:** `MD5(sum + username + ".....")` (Beş nokta suffix)
3.  **sumBigX:** `MD5("......" + sumBig + "......")` (Altı nokta prefix/suffix)
4.  **sumBigY:** `MD5("craftrise#" + username)`

---

## 4. Adım 3: Giriş İsteği (`tryLogin`)

Hesaplanan değerler, bir JSON nesnesi içinde sunucuya gönderilir.

**Payload Formatı:**
```json
{
  "messageType": "tryLogin",
  "datas": {
    "username": "KullaniciAdi",
    "password": "Sifre",
    "key": "...",      // Hesaplanan finalKey
    "sum": "...",      // Hesaplanan sum
    "sumBig": "...",   // Hesaplanan sumBig
    "sumBigX": "...",  // Hesaplanan sumBigX
    "sumBigY": "...",  // Hesaplanan sumBigY
    "staticSessionKey": "null"
  }
}
```

**Kritik Detay:**
Bu JSON verisi sunucuya gönderilirken sonuna mutlaka **bir yeni satır (`\n`) karakteri** eklenmelidir. Aksi takdirde sunucu paketi işlemeyebilir veya bağlantıyı kesebilir.

**Genel Implementasyon:**
```go
// Payload sonuna \n eklenir
jsonPayload = jsonPayload + "\n"
sendNettyPacket(conn, jsonPayload)
```

---

## 5. Adım 4: Sunucu Cevabını Analiz Etme

Sunucudan gelen cevap JSON formatındadır.

*   **Başarılı Giriş:**
    JSON içinde `globalSessionHash` alanı bulunur. Bu değer, oturumun başarıyla açıldığını gösterir ve sonraki oyun sunucusu bağlantılarında kullanılır.
    
    ```json
    {
      "messageType": "tryLogin",
      "status": "true",
      "globalSessionHash": "..."
    }
    ```

*   **Hatalı Giriş:**
    JSON içinde `message` alanında hata kodu döner.
    *   `"message": "3"` veya `"4"` -> Şifre veya Kullanıcı Adı Yanlış.

**Genel Implementasyon:**
```go
reHash := regexp.MustCompile(`"globalSessionHash":\s*"([^"]+)"`)
matchesHash := reHash.FindStringSubmatch(jsonStr)

if len(matchesHash) > 1 {
    fmt.Println("Sunucuya giriş yapıldı.")
    // Başarılı
} else if strings.Contains(jsonStr, `"message":"4"`) {
    // Şifre Hatalı
}
```
