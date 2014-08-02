#! /bin/bash

set -e


PLT_DST="$HOME/.dialyzer_plt"


die() {
    echo "$1"
    exit 1
}

plt_src() {
    declare -r erl_vsn=$(
        erl \
            -eval 'erlang:display(erlang:system_info(otp_release)), halt().' \
            -noshell \
        | tr -d '\r'
    )
    case "$erl_vsn" in
        '"17"'     ) echo 'plt/dialyzer_plt_17'
    ;;  '"R16B02"' ) echo 'plt/dialyzer_plt_r16b02'
    ;; *           ) die "Unexpected Erlang version: $erl_vsn"
    esac
}

main() {
    plt_src=$(plt_src)
    echo "Selecting PLT file: $plt_src"
    cp "$plt_src" "$PLT_DST"
}

main
