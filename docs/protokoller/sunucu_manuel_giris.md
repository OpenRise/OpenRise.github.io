---
layout: default
title: Sunucu Manuel Giriş Rehberi
parent: Protokoller
nav_order: 1
---


# Sunucu Manuel Giriş Rehberi

## 1. Genel Bakış

Bu belge, CraftRise launcher'ının sunucu ile nasıl iletişim kurduğunu, giriş sürecinin adım adım nasıl işlediğini ve tüm bu sürecin Go dilinde nasıl tekrarlanabileceğini anlatır.

**Analiz Kaynakları:**
- 5 adet `.pcapng` ağ yakalama dosyası (2 hesap × 2 başarılı oturum + 1 başarısız oturum)
- Decompile edilmiş Java kaynak kodları (CFR ile)
- Wireshark `.txt` export dosyaları

---

## 2. Sunucu Bağlantı Detayları

| Özellik | Değer | Kaynak |
|---|---|---|
| **Sunucu IP** | `185.255.92.10` | `h.java` satır 81, Base64 decode |
| **Port** | `4754` | `h.java` satır 81: `this.c = 4754` |
| **Protokol** | TCP | `NioSocketChannel.class` kullanımı |
| **Şifreleme** | **Yok** | TLS/SSL handler pipeline'da yok |
| **Serileştirme** | Java Object Serialization | `ObjectEncoder` / `ObjectDecoder` |

### Neden TLS Yok?

Netty pipeline'ında (`h.java` satır 85-98) sadece şu handler'lar var:
```
ObjectDecoder → ObjectEncoder → p (mesaj handler)
```
`SslHandler` veya benzeri bir şifreleme katmanı **bulunmamaktadır**. Bu, tüm trafiğin düz metin olarak iletildiği ve Wireshark ile doğrudan okunabildiği anlamına gelir.

### Neden Java Serialization?

CraftRise, Netty'nin `ObjectEncoder`/`ObjectDecoder` sınıflarını kullanır. Bu, gönderilen her verinin bir Java nesnesi olarak serialize edildiği anlamına gelir. Pratikte gönderilen nesneler `String` (JSON) ve `JSONObject` türündedir.

**Orijinal Java Kodu (`h.java`, satır 96-97):**
```java
channelPipeline.addLast(new ObjectDecoder(
    ClassResolvers.softCachingResolver(ClassLoader.getSystemClassLoader())
));
channelPipeline.addLast(new ObjectEncoder());
```

---

## 3. Paket Çerçevesi (Framing) — Detaylı Açıklama

### Doğru Format

Netty'nin `ObjectEncoder` sınıfı, her nesneyi şu formatta yazar:

```
┌──────────────────┬─────────┬──────────┬───────────────┬──────────────┐
│ 4 bayt: Uzunluk  │ 1 bayt  │ 1 bayt   │ 2 bayt        │ N bayt       │
│ (Big-Endian)     │ 0x05    │ 0x74     │ String Uzunl. │ JSON Verisi  │
└──────────────────┴─────────┴──────────┴───────────────┴──────────────┘
```

| Bayt(lar) | Değer | Açıklama |
|---|---|---|
| Bayt 0-3 | `00 00 01 E6` | Uzunluk ön eki: Sonraki kaç bayt okunacağını belirtir |
| Bayt 4 | `05` | Java Serialization: TC_ENDBLOCKDATA — nesne verisi başlıyor |
| Bayt 5 | `74` | Java Serialization: TC_STRING — String nesnesi |
| Bayt 6-7 | `01 E2` | String uzunluğu (Big-Endian): 482 karakter |
| Bayt 8+ | `7B 22 6D...` | UTF-8 JSON: `{"messageType":"try...` |

### Doğru Go Implementasyonu

```go
func sendPacket(conn net.Conn, jsonStr string) error {
    jsonBytes := []byte(jsonStr)
    strLen := len(jsonBytes)
    
    // Toplam yük = 0x05 (1) + 0x74 (1) + string uzunluk (2) + string (N)
    totalPayload := 1 + 1 + 2 + strLen
    
    packet := make([]byte, 0, 4+totalPayload)
    
    // 4 bayt uzunluk ön eki
    lenBuf := make([]byte, 4)
    binary.BigEndian.PutUint32(lenBuf, uint32(totalPayload))
    packet = append(packet, lenBuf...)
    
    // Java Serialization baytları
    packet = append(packet, 0x05)  // TC_ENDBLOCKDATA
    packet = append(packet, 0x74)  // TC_STRING
    
    // 2 bayt string uzunluğu
    strLenBuf := make([]byte, 2)
    binary.BigEndian.PutUint16(strLenBuf, uint16(strLen))
    packet = append(packet, strLenBuf...)
    
    // JSON verisi
    packet = append(packet, jsonBytes...)
    
    _, err := conn.Write(packet)
    return err
}
```

### ❌ Yanlış Yapılırsa Ne Olur?

**Hata 1: Uzunluk ön eki olmadan göndermek**
```go
// YANLIŞ — sunucu paketi parse edemez
conn.Write([]byte(`{"messageType":"tryLogin",...}`))
```
Sonuç: Sunucu gelen veriyi `ObjectDecoder` ile çözemez, bağlantı kesilir veya hata fırlatılır.

**Hata 2: Little-Endian kullanmak**
```go
// YANLIŞ — Java Big-Endian kullanır
binary.LittleEndian.PutUint32(lenBuf, uint32(totalPayload))
```
Sonuç: Sunucu yanlış uzunluk okur, ya çok fazla ya da çok az veri bekler, bağlantı bozulur.

**Hata 3: 0x05 ve 0x74 baytlarını unutmak**
```go
// YANLIŞ — Java Serialization format baytları eksik
packet = append(packet, lenBuf...)
packet = append(packet, jsonBytes...)
```
Sonuç: Sunucu veriyi Java nesnesi olarak deserialize edemez.

---

## 4. Bağlantı Kurulumu — Adım 1: TCP + Header

### Doğru Sıralama

```go
// 1. TCP bağlantısı kur
conn, err := net.Dial("tcp", "185.255.92.10:4754")
if err != nil {
    fmt.Println("Bağlantı hatası:", err)
    return
}
defer conn.Close()

// 2. Java Serialization Stream Header gönder
// 0xACED = Magic Number ("Java Serialization başlıyor")
// 0x0005 = Stream Version 5
header := []byte{0xAC, 0xED, 0x00, 0x05}
_, err = conn.Write(header)
```

### Neden `0xACED0005`?

Java'nın `ObjectOutputStream` sınıfı, bir stream başlatıldığında **ilk iş** bu 4 baytı yazar. Bu, karşı taraftaki `ObjectInputStream`'e "ben Java Serialization formatında konuşacağım" mesajını verir.

- `0xACED` → Java Serialization Magic Number (sabit)
- `0x0005` → Stream Version 5 (Java'nın tüm modern sürümlerinde sabit)

### ❌ Header gönderilmezse?

```go
// YANLIŞ — Header olmadan doğrudan paket göndermeye çalışmak
conn, _ := net.Dial("tcp", "185.255.92.10:4754")
sendPacket(conn, `{"messageType":"trySplashLogin",...}`)
```
Sonuç: Sunucu tarafındaki `ObjectDecoder`, stream magic number'ı bulamaz ve `StreamCorruptedException` fırlatır. Bağlantı anında kesilir.

### ❌ Header yanlış gönderilirse?

```go
// YANLIŞ — yanlış magic number
header := []byte{0x00, 0x00, 0x00, 0x05}
```
Sonuç: `ObjectDecoder` magic number'ı doğrulayamaz, `InvalidStreamException` fırlatır.

---

## 5. Aşama 1: `trySplashLogin` — Ön Kontrol

### Nedir ve Neden Var?

`trySplashLogin`, istemcinin **kimlik bilgisi vermeden** sunucuya gönderdiği ilk pakettir. Amacı:
1. İstemci yazılımının **bütünlük kontrolü** (doğru hash'ler üretebiliyor mu?)
2. **Donanım parmak izi** doğrulama (key alanı ile)
3. Sunucunun **ayakta olup olmadığını** kontrol etme

### Paket Yapısı

```json
{
  "messageType": "trySplashLogin",
  "datas": {
    "sumBigX":         "<32 karakter MD5>",
    "password":        "",
    "sumBig":          "<32 karakter MD5>",
    "sumBigY":         "<31-32 karakter hash>",
    "sum":             "<32 karakter MD5>",
    "key":             "<Base64 kodlanmış donanım anahtarı>",
    "username":        "",
    "staticSessionKey": null
  }
}
```

### Neden `username` ve `password` Boş?

Bu aşama bir ön kontrol aşamasıdır — sunucu henüz kimin giriş yaptığını bilmek istemiyor. Sadece istemcinin **geçerli bir CraftRise launcher'ı** olup olmadığını kontrol ediyor. Yani:
- `username: ""` → Henüz kimlik bilgisi istenmemiş
- `password: ""` → Henüz kimlik bilgisi istenmemiş
- `staticSessionKey: null` → Henüz oturum yok

### Go Implementasyonu

```go
splashLogin := map[string]interface{}{
    "messageType": "trySplashLogin",
    "datas": map[string]interface{}{
        "sumBigX":          "your_sumBigX_hash",
        "password":         "",                    // MUTLAKA boş olmalı
        "sumBig":           "your_sumBig_hash",
        "sumBigY":          "your_sumBigY_hash",
        "sum":              "your_sum_hash",
        "key":              "your_base64_key",
        "username":         "",                    // MUTLAKA boş olmalı
        "staticSessionKey": nil,                   // MUTLAKA null olmalı
    },
}

jsonData, _ := json.Marshal(splashLogin)
err = sendPacket(conn, string(jsonData))
```

### Sunucu Yanıtı

```json
{"messageType":"trySplashLogin","message":"4","status":"false"}
```

> [!IMPORTANT]
> **Bu yanıt bir hata DEĞİLDİR!** Sunucu Aşama 1'e **her zaman** `status: false`, `message: 4` ile yanıt verir. Bu beklenen davranıştır. Aşama 2'ye devam edilmelidir.

### ❌ Yanlış: Aşama 1'de kullanıcı adı göndermek

```go
// YANLIŞ — Aşama 1'de kullanıcı bilgisi gönderilmemeli
"username": "your_username",
"password": "your_password",
```
Sonuç: Sunucu bu aşamada kimlik bilgisi beklemez. Davranış belirsiz olabilir.

### ❌ Yanlış: `status: false` yanıtını hata sanıp bağlantıyı kesmek

```go
// YANLIŞ — Bu yanıt normal, durma!
if response.Status == "false" {
    fmt.Println("Hata! Bağlantı kesiliyor")
    conn.Close() // ← YAPMA!
}
```
Doğru yaklaşım: Yanıtı görmezden gel ve Aşama 2'ye geç.

---

## 6. Aşama 2: `tryLogin` — Asıl Kimlik Doğrulama

### Nedir?

Aşama 1'den yanıt alındıktan sonra, istemci **gerçek kullanıcı adı ve şifresini** içeren paketi gönderir.

### Aşama 1'den Farkları

| Özellik | Aşama 1 | Aşama 2 |
|---|---|---|
| `messageType` | `trySplashLogin` | `tryLogin` |
| `username` | `""` (boş) | `"your_username"` (gerçek) |
| `password` | `""` (boş) | `"your_password"` (gerçek) |
| `key` | Makine sabiti | Hesaba özgü (farklı!) |
| `sumBigY` | Makine sabiti | Hesaba özgü (farklı!) |
| `staticSessionKey` | `null` | `null` veya önceki oturumdan UUID |

### Go Implementasyonu

```go
tryLogin := map[string]interface{}{
    "messageType": "tryLogin",
    "datas": map[string]interface{}{
        "sumBigX":          "your_sumBigX_hash",
        "password":         "your_password",
        "sumBig":           "your_sumBig_hash",
        "sumBigY":          "your_sumBigY_account_hash",   // Aşama 1'den FARKLI!
        "sum":              "your_sum_hash",
        "key":              "your_base64_account_key",     // Aşama 1'den FARKLI!
        "username":         "your_username",
        "staticSessionKey": nil, // İlk giriş: nil, sonraki: "uuid-saved-from-server"
    },
}

jsonData, _ = json.Marshal(tryLogin)
err = sendPacket(conn, string(jsonData))
```

### Başarılı Yanıt

```json
{
    "globalSessionHash": "<base64_oturum_hashi>",
    "password": "your_password",
    "messageType": "tryLogin",
    "skinURL": "<minecraft_skin_url>",
    "playerRankId": 1,
    "keyValidator": "<base64_dogrulayici ~344 karakter>",
    "staticSessionKey": "<uuid>",
    "status": "true",
    "username": "your_username"
}
```

**Önemli alanlar:**
- `keyValidator`: RSA benzeri imza, **aynı hesap+makine** için oturumlar arası sabit
- `globalSessionHash`: Her oturumda değişir — oturum tanımlayıcı
- `staticSessionKey`: UUID formatında — ilk girişte atanır, sonraki oturumlarda tekrar gönderilir

### Başarısız Yanıt

```json
{"messageType":"tryLogin","message":"3","status":"false"}
```

| `message` Kodu | Muhtemel Anlam |
|---|---|
| `3` | Geçersiz kullanıcı adı veya şifre |
| `4` | Aşama 1 kontrol yanıtı (normal) |

### ❌ Yanlış: Aşama 1'deki `key` değerini Aşama 2'de kullanmak

```go
// YANLIŞ — Aşama 1 ve 2'nin key değerleri FARKLIDIR!
key := "your_base64_key"  // Aşama 1 için doğru
// ... Aşama 2'de aynı key'i kullanmak
"key": key,  // ← YANLIŞ! Aşama 2 hesaba özgü key gerektirir
```

### ❌ Yanlış: Aşama 1'i atlayıp doğrudan tryLogin göndermek

```go
// YANLIŞ — Sunucu önce trySplashLogin bekler
conn.Write(header)
sendPacket(conn, tryLoginJSON) // ← Aşama 1 atlandı!
```
Sonuç: Sunucu beklediği paket sırasını bulamaz, kimlik doğrulama başarısız olabilir.

---

## 7. Yanıt Okuma

### Doğru Implementasyon

```go
func readPacket(conn net.Conn) (string, error) {
    // 1. 4 bayt uzunluk ön ekini oku
    lenBuf := make([]byte, 4)
    _, err := io.ReadFull(conn, lenBuf)
    if err != nil {
        return "", fmt.Errorf("uzunluk okunamadı: %w", err)
    }
    totalLen := binary.BigEndian.Uint32(lenBuf)
    
    // 2. Yük verisini oku
    payload := make([]byte, totalLen)
    _, err = io.ReadFull(conn, payload)
    if err != nil {
        return "", fmt.Errorf("yük okunamadı: %w", err)
    }
    
    // 3. İlk 4 baytı atla: 0x05 + 0x74 + 2 bayt string uzunluk
    if len(payload) < 4 {
        return "", fmt.Errorf("yük çok kısa: %d bayt", len(payload))
    }
    return string(payload[4:]), nil
}
```

### Neden `io.ReadFull` Kullanmalı?

```go
// YANLIŞ — conn.Read() tüm veriyi tek seferde okuyamayabilir
buf := make([]byte, 4096)
n, _ := conn.Read(buf) // TCP parçalı gönderebilir!
```

TCP bir **stream** protokolüdür — veri parçalar halinde gelebilir. Örneğin 500 baytlık bir yanıt, 200+300 bayt olarak iki parçada gelebilir. `io.ReadFull` tam olarak istenen bayt sayısı okunana kadar bekler.

---

## 8. Heartbeat (Kalp Atışı) Mekanizması

### Kaynak Kod Analizi

**Dosya: `t.java`, satır 34-49:**
```java
k.a(new Object[0]).scheduleWithFixedDelay(() -> {
    if (!d.get()) { return; }
    JSONObject jSONObject = new JSONObject();
    jSONObject.put("messageType", "alive");
    jSONObject.put("username", c);       // Kullanıcı adı
    jSONObject.put("sessionKey", a);     // Oturum anahtarı
    h.d(new Object[]{jSONObject});
}, 0L, 1000L, TimeUnit.MILLISECONDS);
```

### Teknik Detaylar

| Parametre | Değer | Açıklama |
|---|---|---|
| **Aralık** | 1000ms (1 saniye) | `scheduleWithFixedDelay(..., 1000L, TimeUnit.MILLISECONDS)` |
| **İlk Gecikme** | 0ms | Giriş başarılı olur olmaz başlar |
| **Zamanlama Tipi** | `scheduleWithFixedDelay` | Önceki görev bittikten sonra 1 saniye bekler |
| **Durdurma Koşulu** | `d.get() == false` | `AtomicBoolean` ile kontrol edilir |

### Go Implementasyonu

```go
func startHeartbeat(conn net.Conn, username, sessionKey string) {
    fmt.Println("[♥] Heartbeat başlatıldı (her 1 saniye)")
    
    go func() {
        ticker := time.NewTicker(1 * time.Second)
        defer ticker.Stop()
        
        for range ticker.C {
            heartbeat := map[string]interface{}{
                "messageType": "alive",
                "username":    username,
                "sessionKey":  sessionKey,
            }
            err := sendPacket(conn, heartbeat)
            if err != nil {
                fmt.Println("[!] Heartbeat gönderilemedi, bağlantı koptu:", err)
                return
            }
        }
    }()
}
```

### Heartbeat Gönderilmezse Ne Olur?

1. Sunucu belirli bir süre (muhtemelen 5-10 saniye) heartbeat almadığında istemciyi **timeout** ile düşürür
2. TCP bağlantısı sunucu tarafından kapatılır
3. İstemci `connection reset` veya `EOF` hatası alır
4. Yeniden bağlanmak için **tüm süreç baştan** tekrarlanmalıdır (header → trySplashLogin → tryLogin)

### ❌ Yanlış: Heartbeat'i çok seyrek göndermek

```go
// YANLIŞ — 30 saniye çok uzun, sunucu timeout yapar
ticker := time.NewTicker(30 * time.Second)
```

### ❌ Yanlış: Heartbeat'i çok sık göndermek

```go
// YANLIŞ — 100ms çok sık, sunucu rate limit uygulayabilir
ticker := time.NewTicker(100 * time.Millisecond)
```

---

## 9. Hash Alanları — Detaylı Analiz

### 9.1 Karşılaştırma Matrisi (5 Pcap Dosyası)

| Alan | Hesap A Oturum 1 | Hesap A Oturum 2 | Hesap B Oturum 1 | Hesap B Oturum 2 | Başarısız |
|---|---|---|---|---|---|
| key (A1) | ✅ Aynı | ✅ Aynı | ✅ Aynı | ✅ Aynı | ✅ Aynı |
| key (A2) | K1 | K1 | K2 | K2 | K3 |
| sumBigY (A1) | ✅ Aynı | ✅ Aynı | ✅ Aynı | ✅ Aynı | ✅ Aynı |
| sumBigY (A2) | Y1 | Y1 | Y2 | Y2 | Y3 |
| sumBig | Farklı | Farklı | Farklı | Farklı | Farklı |
| sumBigX | Farklı | Farklı | Farklı | Farklı | Farklı |
| sum | Farklı | Farklı | Farklı | Farklı | Farklı |
| keyValidator | KV1 | KV1 | — | — | — |

**Notasyon:** A1=Aşama 1, A2=Aşama 2, K=key değeri, Y=sumBigY değeri, KV=keyValidator

### 9.2 Her Alanın Açıklaması

#### `key` — Donanım Parmak İzi
- **Ne:** Base64 kodlanmış, ~200 karakter uzunluğunda bir string
- **Nereden türetilir:** `c.java` — işletim sistemi adı, sürüm, mimari bilgisi
- **Aşama 1:** Makine sabiti — tüm hesap/oturumlar boyunca aynı
- **Aşama 2:** Hesaba özgü — kullanıcı bilgisi de hash'e dahil edilir
- **Neden var:** Sunucunun istemcinin gerçek bir bilgisayarda çalışıp çalışmadığını doğrulaması için

#### `sumBigY` — Sabit Bileşen Hash'i
- **Ne:** 31-32 karakter, MD5 benzeri hash
- **Aşama 1:** Makine sabiti
- **Aşama 2:** Hesaba özgü — aynı hesapta değişmez, farklı hesaplarda farklı
- **Neden var:** Donanım + hesap bilgisi kombinasyonunun doğrulanması

#### `sumBig`, `sumBigX`, `sum` — Oturum Hash'leri
- **Ne:** 32 karakter MD5 hash'ler
- **Davranış:** Her oturumda farklı — zaman damgası veya nonce ile hesaplanır
- **Neden var:** Replay attack'leri önlemek — eski paketler tekrar kullanılamaz

#### `keyValidator` — Kimlik Doğrulama İmzası
- **Ne:** RSA benzeri Base64 string, ~344 karakter
- **Nereden gelir:** Sunucu tarafından başarılı giriş yanıtında gönderilir
- **Davranış:** Aynı hesap+makine için oturumlar arası **sabit**
- **Neden var:** İstemcinin sonraki isteklerde kimliğini kanıtlaması için

#### `staticSessionKey` — Kalıcı Oturum Anahtarı
- **Ne:** UUID formatında (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
- **İlk giriş:** `null` gönderilir, sunucu yanıtta atar
- **Sonraki girişler:** Önceki oturumdan kaydedilen UUID gönderilir
- **Neden var:** "Beni hatırla" benzeri işlev — sunucu bu cihazı tanır

---

## 10. Tam Çalışır Go Programı

```go
package main

import (
    "encoding/binary"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "time"
)

func main() {
    // ===== ADIM 1: TCP Bağlantısı =====
    conn, err := net.Dial("tcp", "185.255.92.10:4754")
    if err != nil {
        fmt.Println("[-] Bağlantı hatası:", err)
        return
    }
    defer conn.Close()
    fmt.Println("[+] Sunucuya bağlandı")

    // ===== ADIM 2: Java Serialization Header =====
    conn.Write([]byte{0xAC, 0xED, 0x00, 0x05})
    fmt.Println("[+] Serialization header gönderildi")

    // ===== ADIM 3: Aşama 1 — trySplashLogin =====
    splash := map[string]interface{}{
        "messageType": "trySplashLogin",
        "datas": map[string]interface{}{
            "sumBigX": "your_sumBigX_hash", "password": "",
            "sumBig":  "your_sumBig_hash",  "sumBigY": "your_sumBigY_hash",
            "sum":     "your_sum_hash",     "key": "your_base64_key",
            "username": "", "staticSessionKey": nil,
        },
    }
    sendJSON(conn, splash)
    fmt.Println("[+] Aşama 1 gönderildi")

    resp1, _ := readPacket(conn)
    fmt.Println("[<] Aşama 1 yanıtı:", resp1)
    // Beklenen: {"messageType":"trySplashLogin","message":"4","status":"false"}

    // ===== ADIM 4: Aşama 2 — tryLogin =====
    login := map[string]interface{}{
        "messageType": "tryLogin",
        "datas": map[string]interface{}{
            "sumBigX": "your_sumBigX_hash", "password": "your_password",
            "sumBig":  "your_sumBig_hash",  "sumBigY": "your_sumBigY_account_hash",
            "sum":     "your_sum_hash",     "key": "your_base64_account_key",
            "username": "your_username",    "staticSessionKey": nil,
        },
    }
    sendJSON(conn, login)
    fmt.Println("[+] Aşama 2 gönderildi")

    resp2, _ := readPacket(conn)
    fmt.Println("[<] Aşama 2 yanıtı:", resp2)

    // ===== ADIM 5: Yanıt Kontrol & Heartbeat =====
    var result map[string]interface{}
    json.Unmarshal([]byte(resp2), &result)
    if s, ok := result["status"].(string); ok && s == "true" {
        fmt.Println("[✓] Giriş başarılı!")
        go heartbeatLoop(conn, "your_username",
            result["staticSessionKey"].(string))
    } else {
        fmt.Println("[✗] Giriş başarısız:", resp2)
    }
    select {} // Programı açık tut
}

func sendJSON(conn net.Conn, data map[string]interface{}) {
    j, _ := json.Marshal(data)
    sLen := len(j)
    total := 1 + 1 + 2 + sLen
    p := make([]byte, 0, 4+total)
    lb := make([]byte, 4); binary.BigEndian.PutUint32(lb, uint32(total))
    p = append(p, lb...)
    p = append(p, 0x05, 0x74)
    sl := make([]byte, 2); binary.BigEndian.PutUint16(sl, uint16(sLen))
    p = append(p, sl...)
    p = append(p, j...)
    conn.Write(p)
}

func readPacket(conn net.Conn) (string, error) {
    lb := make([]byte, 4)
    io.ReadFull(conn, lb)
    total := binary.BigEndian.Uint32(lb)
    payload := make([]byte, total)
    _, err := io.ReadFull(conn, payload)
    if err != nil { return "", err }
    if len(payload) < 4 { return "", fmt.Errorf("kısa yük") }
    return string(payload[4:]), nil
}

func heartbeatLoop(conn net.Conn, user, key string) {
    t := time.NewTicker(1 * time.Second)
    for range t.C {
        hb := map[string]interface{}{
            "messageType": "alive", "username": user, "sessionKey": key,
        }
        sendJSON(conn, hb)
    }
}
```

---

## 11. Sık Yapılan Hatalar Özeti

| Hata | Sonuç | Doğrusu |
|---|---|---|
| Header göndermemek | `StreamCorruptedException`, bağlantı kesilir | İlk iş `0xACED0005` gönder |
| Little-Endian kullanmak | Yanlış uzunluk, veri bozulur | `binary.BigEndian` kullan |
| `0x05 0x74` baytlarını unutmak | Deserialize hatası | Her pakette ekle |
| Aşama 1'de kullanıcı adı göndermek | Beklenmeyen davranış | `""` gönder |
| `status:false` yanıtında durmak | Giriş tamamlanmaz | Aşama 2'ye devam et |
| Aşama 1'i atlamak | Kimlik doğrulama başarısız | Sırayı takip et |
| Heartbeat'i 1sn'den farklı göndermek | Timeout veya rate limit | Tam 1 saniye aralık |
| `conn.Read` ile yanıt okumak | Eksik/parçalı veri | `io.ReadFull` kullan |
| A1 key'i A2'de kullanmak | Yanlış hash, giriş başarısız | Her aşamanın key'i farklı |
