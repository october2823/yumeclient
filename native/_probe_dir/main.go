package main

import (
 "fmt"
 tls "github.com/bogdanfinn/utls"
 tls_client "github.com/bogdanfinn/tls-client"
)

func main() {
 ja3 := "771,4865-4866-4867-49195-49199-52393-52392-49196-49200-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-17513,29-23-24,0"
 sf, err := tls_client.GetSpecFactoryFromJa3String(ja3, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0)
 if err != nil { fmt.Println("factory err:", err); return }
 spec, err := sf()
 if err != nil { fmt.Println("spec err:", err); return }
 for i, e := range spec.Extensions {
  if sv, ok := e.(*tls.SupportedVersionsExtension); ok {
   fmt.Printf("[%d] ext 43 Versions=%v\n", i, sv.Versions)
  }
  if ks, ok := e.(*tls.KeyShareExtension); ok {
   fmt.Printf("[%d] ext 51 KeyShares=%v\n", i, ks.KeyShares)
  }
 }
}
