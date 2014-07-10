-module(oauth1_uri).

-include_lib("oauth1_uri.hrl").

-export_type(
    [ t/0
    , args_cons/0
    ]).

-export(
    [ cons/1
    , get_query/1
    , set_query/2
    , add_query/3
    , to_bin/1
    , of_bin/1
    ]).


-type scheme() ::
      http
    | https
    .

-type query() ::
    [{binary(), binary()}].

-record(t,
    { scheme         :: scheme()
    , user = none    :: hope_option:t(binary())
    , host           :: binary()
    , port           :: integer()
    , path           :: binary()
    , query     = [] :: query()
    }).

-opaque t() ::
    #t{}.

-type args_cons() ::
    #oauth1_uri_args_cons{}.


-spec cons(args_cons()) ->
    t().
cons(#oauth1_uri_args_cons
    { scheme         = Scheme
    , user           = User
    , host           = Host
    , port           = Port
    , path           = Path
    , query          = Query
    }
) ->
    #t
    { scheme         = Scheme
    , user           = User
    , host           = Host
    , port           = Port
    , path           = Path
    , query          = Query
    }.

-spec get_query(t()) ->
    query().
get_query(#t{query=Query}) ->
    Query.

-spec set_query(t(), query()) ->
    t().
set_query(#t{}=T, QueryParams) ->
    T#t{query=QueryParams}.

-spec add_query(t(), Key :: binary(), Value :: binary()) ->
    t().
add_query(#t{query=Query1}=T, <<Key/binary>>, <<Value/binary>>) ->
    Query2 = orddict:store(Key, Value, Query1),
    T#t{query=Query2}.

-spec to_bin(t()) ->
    binary().
to_bin(#t
    { scheme         = Scheme
    , user           = User
    , host           = Host
    , port           = Port
    , path           = Path
    , query          = Query
    }
) ->
    UserOrEmpty =
        case User
        of  {some, UserBin} -> <<UserBin/binary, "@">>
        ;   none            -> <<>>
        end,
    PortOrEmpty =
        case {Scheme, Port}
        of  {http , 80}   -> <<>>
        ;   {https, 443}  -> <<>>
        ;   {_    , Port} ->
                PortBin = integer_to_binary(Port),
                <<":", PortBin/binary>>
        end,
    SchemeBin = scheme_to_bin(Scheme),
    QueryBin  = cow_qs:qs(Query),
    << SchemeBin/binary
    ,  "://"
    ,  UserOrEmpty/binary
    ,  Host/binary
    ,  PortOrEmpty/binary
    ,  Path/binary
    ,  "?"
    ,  QueryBin/binary
    >>.

-spec of_bin(binary()) ->
    hope_result:t(t(), no_scheme).
of_bin(<<URIString/binary>>) ->
    case http_uri:parse(binary_to_list(URIString))
    of  {error, _}=Error ->
            Error
    ;   {ok, {Scheme, UserInfo, Host, Port, Path, Query}}
        when Scheme =:= http orelse Scheme =:= https ->
            UserInfoOpt =
                case UserInfo
                of  []    -> none
                ;   [_|_] -> {some, list_to_binary(UserInfo)}
                end,
            HostBin  = list_to_binary(Host),
            PathBin  = list_to_binary(Path),
            QueryBin = list_to_binary(Query),
            T = #t
                { scheme         = Scheme
                , user           = UserInfoOpt
                , host           = HostBin
                , port           = Port
                , path           = PathBin
                , query          = cow_qs:parse_qs(QueryBin)
                },
            {ok, T}

    end.


-spec scheme_to_bin(scheme()) ->
    binary().
scheme_to_bin(http)  -> <<"http">>;
scheme_to_bin(https) -> <<"https">>.
