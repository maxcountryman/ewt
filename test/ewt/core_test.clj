(ns ewt.core-test
  (:require [clojure.test :refer [deftest is]]
            [ewt.core :refer [encode decode]]))

(deftest test-encode-decode
  (let [secret  "secret"
        payload {:foo :bar}
        token   (encode {:key       secret
                         :payload   payload
                         :algorithm :HS256})]

    ;; Test decoding with the correct key returns expected values.
    (is (= payload (decode {:key       secret
                            :token     token
                            :algorithm :HS256})))

    ;; Test decoding with a bad key returns nil.
    (is (nil? (decode {:key       "bogus"
                       :token     token
                       :algorithm :HS256})))))

(deftest test-encode-rich-types
  (let [secret "secret"
        payload {:date    (java.util.Date. 0)
                 :keyword :test/kw
                 :vector  [\space 'foo]
                 :set     #{1 2/3 3.14}
                 :map     {:foo :bar}}
        token   (encode {:key secret
                         :payload payload
                         :algorithm :HS256})]
    (is (= payload (decode {:key       secret
                            :token     token
                            :algorithm :HS256})))))
