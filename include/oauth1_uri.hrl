-record(oauth1_uri_cons,
    { scheme         :: http | https
    , user = none    :: hope_option:t(binary())
    , host           :: binary()
    , port           :: integer()
    , path_and_query :: binary()
    }).

-type oauth1_uri_cons() :: #oauth1_uri_cons{}.
