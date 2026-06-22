package api

import "net/http"

func ClearOCSPCacheHandler(w http.ResponseWriter, r *http.Request) {
    ocspCache = make(map[string]cachedResponse)
    w.Write([]byte("OCSP cache cleared"))
}
