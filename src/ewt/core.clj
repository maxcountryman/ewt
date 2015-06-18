(ns ewt.core
  "EDN Web Tokens.

  Much like JSON Web Tokens, EDN Web Tokens are a way of formatting claims
  which may be stored with a client. However, instead of using JSON as the
  transit format, EDN is used. This facilitates encoding of richer data and is
  a natural fit for applications already using Clojure."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as string])
  (:import [java.io PushbackReader]
           [java.util Base64]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))

(def ^{:private true :static true} HMAC-SHA256 "HmacSHA256")
(def ^{:private true :static true} algorithms #{:HS256})


;; Utils.

(defn base64-url-encode
  "Returns a base 64 encoded string."
  [^bytes unencoded]
  (let [encoder (.withoutPadding (Base64/getUrlEncoder))]
    (String. (.encode encoder unencoded))))

(defn base64-url-decode
  "Returns a base 64 decoded byte array."
  [^String encoded]
  (let [decoder (Base64/getUrlDecoder)]
    (.decode decoder encoded)))

(defn bytes->pushback-reader
  "Given a byte array, returns a java.io.PushbackReader wrapped around the
  byte array."
  [^bytes bs]
  (let [reader (io/reader bs)]
    (PushbackReader. reader)))

(defn hmac-sha256
  "Given a string of data and a string key, returns a new HMAC."
  [^String data ^String key]
  (let [mac (Mac/getInstance HMAC-SHA256)
        ks  (SecretKeySpec. (.getBytes key) HMAC-SHA256)]
    (.init mac ks)
    (->> (.getBytes data) (.doFinal mac))))

(defn segments
  "Returns a sequence of base64 URL encoded args."
  [& args]
  (map (comp base64-url-encode #(.getBytes ^String %) str) args))

(defn sign
  "Returns a signature string of the encoded segements, i.e. headers and
  payload. The key is used by the signer as the secret and the signer"
  [encoded key signer]
  (-> (string/join "." encoded)
      (signer key)
      base64-url-encode))

(defn constant-time-compare?
  "Given two byte arrays, a and b, checks that they are equal in constant
  time; returns true if they are otherwise false. This is particularly
  important for protection against timing attacks."
  [a b]
  (if (= (count a) (count b))
    (zero? (reduce (fn [acc [x y]]
                     (bit-or acc (bit-xor x y)))
                   0 (map vector a b)))
    false))


;; Encode and decode.

(defmulti encode :algorithm)

(defmethod encode :HS256
  [{:keys [payload key headers]}]
  {:pre [(not (nil? key)) (string? key)]}
  (let [headers   (merge headers {:typ :EWT :alg :HS256})
        encoded   (segments headers payload)
        signature (sign encoded key hmac-sha256)]
    (string/join "." (concat encoded (list signature)))))

(defmulti decode :algorithm)

(defmethod decode :HS256
  [{:keys [token key]}]
  (let [[headers payload signature] (string/split token #"\.")
        [headers payload]           (map (comp edn/read
                                               bytes->pushback-reader
                                               base64-url-decode)
                                         [headers payload])]
    (if (= (:alg headers) :HS256)
      (let [encoded (segments headers payload)
            a    (.getBytes ^String signature)
            b    (.getBytes ^String (sign encoded key hmac-sha256))]
        (when (constant-time-compare? a b)
          payload))
      (throw
        (Exception. "Expected algorithm :HS256 but got" (:alg headers))))))
