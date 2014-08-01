-record(oauth1_signature_args_cons,
    { method               :: oauth1_signature:method()
    , http_req_method      :: binary()
    , http_req_host        :: binary()
    , resource             :: oauth1_resource:t()
    , consumer_key         :: oauth1_credentials:id(client)
    , timestamp            :: oauth1_timestamp:t()
    , nonce                :: oauth1_nonce:t()

    , client_shared_secret :: oauth1_credentials:secret(client)

    , token         = none :: hope_option:t(oauth1_credentials:t(tmp | token))
    , verifier      = none :: hope_option:t(oauth1_verifier:t())
    , callback      = none :: hope_option:t(oauth1_uri:t())

    , version       = none :: hope_option:t('1.0')
    }).
