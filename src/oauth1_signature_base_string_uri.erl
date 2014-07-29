-module(oauth1_signature_base_string_uri).

-include_lib("oauth1_module_abbreviations.hrl").

-export_type(
    [ t/0
    ]).

-export(
    [ cons/1
    ]).


-type t() ::
    binary().


%% 3.4.1.2.  Base String URI
%%
%%    The scheme, authority, and path of the request resource URI [RFC3986]
%%    are included by constructing an "http" or "https" URI representing
%%    the request resource (without the query or fragment) as follows:
%%
%%    1.  The scheme and host MUST be in lowercase.
%%
%%    2.  The host and port values MUST match the content of the HTTP
%%        request "Host" header field.
%%
%%    3.  The port MUST be included if it is not the default port for the
%%        scheme, and MUST be excluded if it is the default.  Specifically,
%%        the port MUST be excluded when making an HTTP request [RFC2616]
%%        to port 80 or when making an HTTPS request [RFC2818] to port 443.
%%        All other non-default port numbers MUST be included.
%%
%%    For example, the HTTP request:
%%
%%      GET /r%20v/X?id=123 HTTP/1.1
%%      Host: EXAMPLE.COM:80
%%
%%    is represented by the base string URI: "http://example.com/r%20v/X".
%%
%%    In another example, the HTTPS request:
%%
%%      GET /?q=1 HTTP/1.1
%%      Host: www.example.net:8080
%%
%%    is represented by the base string URI:
%%    "https://www.example.net:8080/".
-spec cons(?uri:t()) ->
    t().
cons(URI) ->
    ?uri:to_bin(URI).
