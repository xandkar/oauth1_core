-record(oauth1_signature_base_string_args_cons,
    { signature_method     :: oauth1_signature:method()
    , http_req_method      :: binary()
    , http_req_host        :: binary()
    , resource             :: oauth1_resource:t()
    , consumer_key         :: oauth1_credentials:id(client)
    , timestamp            :: oauth1_timestamp:t()
    , nonce                :: oauth1_nonce:t()
    }).
