-module(oauth1_signature_base_string).

-include_lib("oauth1_module_abbreviations.hrl").
-include_lib("oauth1_signature_base_string.hrl").

-export_type(
    [ t/0
    ]).

-export(
    [ cons/1
    ]).


-type t() ::
    binary().

-type args_cons() ::
    #oauth1_signature_base_string_args_cons{}.


-define(AMPERSAND, "&").


-spec cons(args_cons()) ->
    t().
cons(#oauth1_signature_base_string_args_cons
    { signature_method = 'HMAC_SHA1'
    , http_req_method  = HttpMeth
    , http_req_host    = _HttpHost
    , resource         = Resource
    , consumer_key     = ConsumerKey
    , timestamp        = Timestamp
    , nonce            = Nonce

    , token_id         = TokenIDOpt
    , verifier         = VerifierOpt
    , callback         = CallbackOpt
    }
) ->
    URI           = ?resource:get_uri(Resource),
    BaseStringURI = ?signature_base_string_uri:cons(URI),
    TokenPair =
        case TokenIDOpt
        of  none                      -> []
        ;   {some, {tmp  , TokenBin}} -> [{<<"oauth_token">>, TokenBin}]
        ;   {some, {token, TokenBin}} -> [{<<"oauth_token">>, TokenBin}]
        end,
    VerifierPair =
        case VerifierOpt
        of  none ->
                []
        ;   {some, Verifier} ->
                VerifierBin = ?verifier:get_value(Verifier),
                [{<<"oauth_verifier">>, VerifierBin}]
        end,
    CallbackPair =
        case CallbackOpt
        of  none ->
                []
        ;   {some, Callback} ->
                CallbackBin = ?signature_base_string_uri:cons(Callback),
                [{<<"oauth_callback">>, CallbackBin}]
        end,
    QueryPairs = ?uri:get_query(URI),
    ParameterPairs =
        [ {<<"oauth_signature_method">> , <<"HMAC-SHA1">>}
        , {<<"oauth_consumer_key">>     , ?credentials:id_to_bin(ConsumerKey)}
        , {<<"oauth_timestamp">>        , ?timestamp:to_bin(Timestamp)}
        , {<<"oauth_nonce">>            , Nonce}
        | QueryPairs
        ]
        ++ TokenPair
        ++ VerifierPair
        ++ CallbackPair,
    ParameterPairsEncoded =
        [{encode(K), encode(V)}|| {K, V} <- ParameterPairs],
    ParameterSortComparator =
        fun ({K , V1}, {K , V2}) -> V1 =< V2
        ;   ({K1,  _}, {K2,  _}) -> K1 =< K2
        end,
    ParameterPairsSorted =
        lists:sort(ParameterSortComparator, ParameterPairsEncoded),
    ParameterAppend =
        fun ({K, V}, Acc) ->
            <<Acc/binary, K/binary, "=", V/binary>>
        end,
    ParametersString = lists:foldl(ParameterAppend, <<>>, ParameterPairsSorted),
    % TODO: ParametersFromHttpEntityBody = ... ,
    %
    << HttpMeth/binary
    ,  ?AMPERSAND
    ,  BaseStringURI/binary
    , ?AMPERSAND
    ,  ParametersString/binary
    >>.


-spec encode(binary()) ->
    binary().
encode(<<String/binary>>) ->
    cow_qs:urlencode(String).


%% 3.4.1.  Signature Base String
%%
%%    - ...
%%    - Parameters included in the request entity-body if they comply with
%%      the strict restrictions defined in Section 3.4.1.3.
%%
%% 3.4.1.3.  Request Parameters
%%
%%    In order to guarantee a consistent and reproducible representation of
%%    the request parameters, the parameters are collected and decoded to
%%    their original decoded form.  They are then sorted and encoded in a
%%    particular manner that is often different from their original
%%    encoding scheme, and concatenated into a single string.
%%
%% 3.4.1.3.1.  Parameter Sources
%%
%%    The parameters from the following sources are collected into a single
%%    list of name/value pairs:
%%
%%    o  The query component of the HTTP request URI as defined by
%%       [RFC3986], Section 3.4.  The query component is parsed into a list
%%       of name/value pairs by treating it as an
%%       "application/x-www-form-urlencoded" string, separating the names
%%       and values and decoding them as defined by
%%       [W3C.REC-html40-19980424], Section 17.13.4.
%%
%%    o  The OAuth HTTP "Authorization" header field (Section 3.5.1) if
%%       present.  The header's content is parsed into a list of name/value
%%       pairs excluding the "realm" parameter if present.  The parameter
%%       values are decoded as defined by Section 3.5.1.
%%
%%    o  The HTTP request entity-body, but only if all of the following
%%       conditions are met:
%%
%%       *  The entity-body is single-part.
%%
%%       *  The entity-body follows the encoding requirements of the
%%          "application/x-www-form-urlencoded" content-type as defined by
%%          [W3C.REC-html40-19980424].
%%
%%       *  The HTTP request entity-header includes the "Content-Type"
%%          header field set to "application/x-www-form-urlencoded".
%%
%%       The entity-body is parsed into a list of decoded name/value pairs
%%       as described in [W3C.REC-html40-19980424], Section 17.13.4.
%%
%%    The "oauth_signature" parameter MUST be excluded from the signature
%%    base string if present.  Parameters not explicitly included in the
%%    request MUST be excluded from the signature base string (e.g., the
%%    "oauth_version" parameter when omitted).
%%
%%    For example, the HTTP request:
%%
%%        POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
%%        Host: example.com
%%        Content-Type: application/x-www-form-urlencoded
%%        Authorization: OAuth realm="Example",
%%                       oauth_consumer_key="9djdj82h48djs9d2",
%%                       oauth_token="kkk9d7dh3k39sjv7",
%%                       oauth_signature_method="HMAC-SHA1",
%%                       oauth_timestamp="137131201",
%%                       oauth_nonce="7d8f3e4a",
%%                       oauth_signature="djosJKDKJSD8743243%2Fjdk33klY%3D"
%%
%%        c2&a3=2+q
%%
%%    contains the following (fully decoded) parameters used in the
%%    signature base sting:
%%
%%                +------------------------+------------------+
%%                |          Name          |       Value      |
%%                +------------------------+------------------+
%%                |           b5           |       =%3D       |
%%                |           a3           |         a        |
%%                |           c@           |                  |
%%                |           a2           |        r b       |
%%                |   oauth_consumer_key   | 9djdj82h48djs9d2 |
%%                |       oauth_token      | kkk9d7dh3k39sjv7 |
%%                | oauth_signature_method |     HMAC-SHA1    |
%%                |     oauth_timestamp    |     137131201    |
%%                |       oauth_nonce      |     7d8f3e4a     |
%%                |           c2           |                  |
%%                |           a3           |        2 q       |
%%                +------------------------+------------------+
%%
%%    Note that the value of "b5" is "=%3D" and not "==".  Both "c@" and
%%    "c2" have empty values.  While the encoding rules specified in this
%%    specification for the purpose of constructing the signature base
%%    string exclude the use of a "+" character (ASCII code 43) to
%%    represent an encoded space character (ASCII code 32), this practice
%%    is widely used in "application/x-www-form-urlencoded" encoded values,
%%    and MUST be properly decoded, as demonstrated by one of the "a3"
%%    parameter instances (the "a3" parameter is used twice in this
%%    request).
%%
%% 3.4.1.3.2.  Parameters Normalization
%%
%%    The parameters collected in Section 3.4.1.3 are normalized into a
%%    single string as follows:
%%
%%    1.  First, the name and value of each parameter are encoded
%%        (Section 3.6).
%%
%%    2.  The parameters are sorted by name, using ascending byte value
%%        ordering.  If two or more parameters share the same name, they
%%        are sorted by their value.
%%
%%    3.  The name of each parameter is concatenated to its corresponding
%%        value using an "=" character (ASCII code 61) as a separator, even
%%        if the value is empty.
%%
%%    4.  The sorted name/value pairs are concatenated together into a
%%        single string by using an "&" character (ASCII code 38) as
%%        separator.
%%
%%    For example, the list of parameters from the previous section would
%%    be normalized as follows:
%%
%%                                  Encoded:
%%
%%                +------------------------+------------------+
%%                |          Name          |       Value      |
%%                +------------------------+------------------+
%%                |           b5           |     %3D%253D     |
%%                |           a3           |         a        |
%%                |          c%40          |                  |
%%                |           a2           |       r%20b      |
%%                |   oauth_consumer_key   | 9djdj82h48djs9d2 |
%%                |       oauth_token      | kkk9d7dh3k39sjv7 |
%%                | oauth_signature_method |     HMAC-SHA1    |
%%                |     oauth_timestamp    |     137131201    |
%%                |       oauth_nonce      |     7d8f3e4a     |
%%                |           c2           |                  |
%%                |           a3           |       2%20q      |
%%                +------------------------+------------------+
%%
%%                                   Sorted:
%%
%%                +------------------------+------------------+
%%                |          Name          |       Value      |
%%                +------------------------+------------------+
%%                |           a2           |       r%20b      |
%%                |           a3           |       2%20q      |
%%                |           a3           |         a        |
%%                |           b5           |     %3D%253D     |
%%                |          c%40          |                  |
%%                |           c2           |                  |
%%                |   oauth_consumer_key   | 9djdj82h48djs9d2 |
%%                |       oauth_nonce      |     7d8f3e4a     |
%%                | oauth_signature_method |     HMAC-SHA1    |
%%                |     oauth_timestamp    |     137131201    |
%%                |       oauth_token      | kkk9d7dh3k39sjv7 |
%%                +------------------------+------------------+
%%
%%                             Concatenated Pairs:
%%
%%                   +-------------------------------------+
%%                   |              Name=Value             |
%%                   +-------------------------------------+
%%                   |               a2=r%20b              |
%%                   |               a3=2%20q              |
%%                   |                 a3=a                |
%%                   |             b5=%3D%253D             |
%%                   |                c%40=                |
%%                   |                 c2=                 |
%%                   | oauth_consumer_key=9djdj82h48djs9d2 |
%%                   |         oauth_nonce=7d8f3e4a        |
%%                   |   oauth_signature_method=HMAC-SHA1  |
%%                   |      oauth_timestamp=137131201      |
%%                   |     oauth_token=kkk9d7dh3k39sjv7    |
%%                   +-------------------------------------+
%%
%%    and concatenated together into a single string (line breaks are for
%%    display purposes only):
%%
%%      a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj
%%      dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1
%%      &oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7
