%%% vim: set filetype=erlang:
{incl_app , oauth1_core, details}.

{excl_mods,  oauth1_core,
    [ oauth1_http_header_authorization_lexer
    , oauth1_http_header_authorization_parser
    ]}.
