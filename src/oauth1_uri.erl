-module(oauth1_uri).

-include_lib("oauth1_uri.hrl").

-export_type(
    [ t/0
    , args_cons/0
    ]).

-export(
    [ cons/1
    , get_path_and_query/1
    , get_query/1
    , to_bin/1
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
    , path_and_query :: binary()
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
    , path_and_query = PathAndQuery
    , query          = Query
    }
) ->
    #t
    { scheme         = Scheme
    , user           = User
    , host           = Host
    , port           = Port
    , path_and_query = PathAndQuery
    , query          = Query
    }.

-spec get_path_and_query(t()) ->
    binary().
get_path_and_query(#t{path_and_query=PathAndQuery}) ->
    PathAndQuery.

-spec get_query(t()) ->
    query().
get_query(#t{query=Query}) ->
    Query.

-spec to_bin(t()) ->
    binary().
to_bin(#t
    { scheme         = Scheme
    , user           = User
    , host           = Host
    , port           = Port
    , path_and_query = PathAndQuery
    , query          = _Query
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
    << SchemeBin/binary
    ,  "://"
    ,  UserOrEmpty/binary
    ,  Host/binary
    ,  PortOrEmpty/binary
    ,  PathAndQuery/binary
    >>.


-spec scheme_to_bin(scheme()) ->
    binary().
scheme_to_bin(http)  -> <<"http">>;
scheme_to_bin(https) -> <<"https">>.
