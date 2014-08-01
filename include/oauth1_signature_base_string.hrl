-record(oauth1_signature_base_string_args_cons,
    { signature_method     :: oauth1_signature:method()
    , http_req_method      :: binary()
    , http_req_host        :: binary()
    , resource             :: oauth1_resource:t()
    , consumer_key         :: oauth1_credentials:id(client)
    , timestamp            :: oauth1_timestamp:t()
    , nonce                :: oauth1_nonce:t()

    , token_id      = none :: hope_option:t(oauth1_credentials:id(tmp | token))
    , verifier      = none :: hope_option:t(oauth1_verifier:t())
    , callback      = none :: hope_option:t(oauth1_uri:t())

    , version       = none :: hope_option:t('1.0')
    }).
