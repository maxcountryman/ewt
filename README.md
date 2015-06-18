# ewt

EDN Web Tokens.

Much like JSON Web Tokens, except for EDN contexts.

## Usage

Tokens may be encoded and decoded via the `encode` and `decode` functions,
respectively. Simply reaquire the `ewt.core` namespace.

```clojure
=> (require '[ewt.core :as ewt])
=> (ewt/encode {:key "secret" :payload {:user-id 42} :algorithm :HS256})
"ezp0eXAgOkVXVCwgOmFsZyA6SFMyNTZ9.ezp1c2VyLWlkIDQyfQ.IcnjVWhobnSxLAbYGomZ1ZHFn4FadQ1Z0PD4hGe5zYQ"
```

The resulting string is a token which can later be decoded when the proper
algorithm and secret are provided.

```clojure
=> (def token "ezp0eXAgOkVXVCwgOmFsZyA6SFMyNTZ9.ezp1c2VyLWlkIDQyfQ.IcnjVWhobnSxLAbYGomZ1ZHFn4FadQ1Z0PD4hGe5zYQ")
=> (ewt/decode {:key "secret" :token token :algorithm :HS256})
{:user-id 42}
```

## Design

EDN Web Tokens closely resemble [JSON Web Tokens](http://jwt.io/). The structure and encoding of
the token is nearly identitical. 

```
token = base64url(<header>).base64url(<payload>).base64url(<signature>)
```

The header and payload are base64url encoded. In the case of the HS256
algorithm, a Mac is produced, base64url encoded and then used as the signature
of the token.

Once produced the token can later be verified, its contents decoded, and used.
This facilities the transference of claims between applications.

## License

Copyright © 2015 Max Countryman

Distributed under the BSD 3-Clause license.
