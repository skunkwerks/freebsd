#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2024 SkunkWerks GmbH
#
# This software was developed by Igor Ostapenko <igoro@FreeBSD.org>
# under sponsorship from SkunkWerks GmbH.
#

setup()
{
	# Check if we have enough buffer space for testing
	if [ $(sysctl -n security.jail.meta_maxbufsize) -lt 128 ]; then
		atf_skip "sysctl security.jail.meta_maxbufsize must be 128+ for testing."
	fi

	# Check if chars required for testing are allowed
	allowed="$(sysctl -b security.jail.meta_allowedchars | hexdump -e '1/1 "%02x\n"')"
	# ABCabctv =0-9\t\n
	for b in 41 42 43 61 62 63 74 76 20 30 31 32 33 34 35 36 37 38 39 09 0a
	do
		if ! echo $allowed | grep -q $b; then
			atf_skip "sysctl security.jail.meta_allowedchars is not wide enough for testing"
		fi
	done
}

atf_test_case "jail_create" "cleanup"
jail_create_head()
{
	atf_set descr 'Test that metadata can be set upon jail creation with jail(8)'
	atf_set require.user root
	atf_set execenv jail
}
jail_create_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -jj

	atf_check -s exit:0 \
	    jail -c name=j persist meta="a b c" env="C B A"

	atf_check -s exit:0 -o inline:"a b c\n" \
	    jls -jj meta
	atf_check -s exit:0 -o inline:"C B A\n" \
	    jls -jj env
}
jail_create_cleanup()
{
	jail -r j
	return 0
}

atf_test_case "jail_modify" "cleanup"
jail_modify_head()
{
	atf_set descr 'Test that metadata can be modified after jail creation with jail(8)'
	atf_set require.user root
	atf_set execenv jail
}
jail_modify_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -jj

	atf_check -s exit:0 \
	    jail -c name=j persist meta="a	b	c" env="CAB"

	atf_check -s exit:0 -o inline:"a	b	c\n" \
	    jls -jj meta
	atf_check -s exit:0 -o inline:"CAB\n" \
	    jls -jj env

	atf_check -s exit:0 \
	    jail -m name=j meta="t1=A t2=B" env="CAB2"

	atf_check -s exit:0 -o inline:"t1=A t2=B\n" \
	    jls -jj meta
	atf_check -s exit:0 -o inline:"CAB2\n" \
	    jls -jj env
}
jail_modify_cleanup()
{
	jail -r j
	return 0
}

atf_test_case "jail_add" "cleanup"
jail_add_head()
{
	atf_set descr 'Test that metadata can be added to an existing jail with jail(8)'
	atf_set require.user root
	atf_set execenv jail
}
jail_add_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -jj

	atf_check -s exit:0 \
	    jail -c name=j persist host.hostname=jail1

	atf_check -s exit:0 -o inline:'""\n' \
	    jls -jj meta
	atf_check -s exit:0 -o inline:'""\n' \
	    jls -jj env

	atf_check -s exit:0 \
	    jail -m name=j meta="$(jot 3 1 3)" env="$(jot 2 11 12)"

	atf_check -s exit:0 -o inline:"1\n2\n3\n" \
	    jls -jj meta
	atf_check -s exit:0 -o inline:"11\n12\n" \
	    jls -jj env
}
jail_add_cleanup()
{
	jail -r j
	return 0
}

atf_test_case "jail_reset" "cleanup"
jail_reset_head()
{
	atf_set descr 'Test that metadata can be reset to an empty string with jail(8)'
	atf_set require.user root
	atf_set execenv jail
}
jail_reset_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -jj

	atf_check -s exit:0 \
	    jail -c name=j persist meta="123" env="456"

	atf_check -s exit:0 -o inline:"123\n" \
	    jls -jj meta
	atf_check -s exit:0 -o inline:"456\n" \
	    jls -jj env

	atf_check -s exit:0 \
	    jail -m name=j meta= env=

	atf_check -s exit:0 -o inline:'""\n' \
	    jls -jj meta
	atf_check -s exit:0 -o inline:'""\n' \
	    jls -jj env
}
jail_reset_cleanup()
{
	jail -r j
	return 0
}

atf_test_case "jls_libxo" "cleanup"
jls_libxo_head()
{
	atf_set descr 'Test that metadata can be read with jls(8) using libxo'
	atf_set require.user root
	atf_set execenv jail
}
jls_libxo_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -jj

	atf_check -s exit:0 \
	    jail -c name=j persist meta="a b c" env="1 2 3"

	atf_check -s exit:0 -o inline:'{"__version": "2", "jail-information": {"jail": [{"name":"j","meta":"a b c"}]}}\n' \
	    jls -jj --libxo json name meta
	atf_check -s exit:0 -o inline:'{"__version": "2", "jail-information": {"jail": [{"env":"1 2 3"}]}}\n' \
	    jls -jj --libxo json env
}
jls_libxo_cleanup()
{
	jail -r j
	return 0
}

atf_test_case "flua_create" "cleanup"
flua_create_head()
{
	atf_set descr 'Test that metadata can be set upon jail creation with flua'
	atf_set require.user root
	atf_set execenv jail
}
flua_create_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -jj

	atf_check -s exit:0 \
	    /usr/libexec/flua -ljail -e 'jail.setparams("j", {["meta"]="t1 t2=v2", ["env"]="BAC", ["persist"]="true"}, jail.CREATE)'

	atf_check -s exit:0 -o inline:"t1 t2=v2\n" \
	    /usr/libexec/flua -ljail -e 'jid, res = jail.getparams("j", {"meta"}); print(res["meta"])'
	atf_check -s exit:0 -o inline:"BAC\n" \
	    /usr/libexec/flua -ljail -e 'jid, res = jail.getparams("j", {"env"}); print(res["env"])'
}
flua_create_cleanup()
{
	jail -r j
	return 0
}

atf_test_case "flua_modify" "cleanup"
flua_modify_head()
{
	atf_set descr 'Test that metadata can be changed with flua after jail creation'
	atf_set require.user root
	atf_set execenv jail
}
flua_modify_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -jj

	atf_check -s exit:0 \
	    jail -c name=j persist meta="ABC" env="123"

	atf_check -s exit:0 -o inline:"ABC\n" \
	    jls -jj meta
	atf_check -s exit:0 -o inline:"123\n" \
	    jls -jj env

	atf_check -s exit:0 \
	    /usr/libexec/flua -ljail -e 'jail.setparams("j", {["meta"]="t1 t2=v", ["env"]="4"}, jail.UPDATE)'

	atf_check -s exit:0 -o inline:"t1 t2=v\n" \
	    jls -jj meta
	atf_check -s exit:0 -o inline:"4\n" \
	    jls -jj env
}
flua_modify_cleanup()
{
	jail -r j
	return 0
}

atf_test_case "env_readable_by_jail" "cleanup"
env_readable_by_jail_head()
{
	atf_set descr 'Test that a jail can read its own env parameter via sysctl(8)'
	atf_set require.user root
	atf_set execenv jail
}
env_readable_by_jail_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -jj

	atf_check -s exit:0 \
	    jail -c name=j persist meta="a b c" env="CBA"

	atf_check -s exit:0 -o inline:"a b c\n" \
	    jls -jj meta
	atf_check -s exit:0 -o inline:"CBA\n" \
	    jls -jj env

	atf_check -s exit:0 -o inline:"CBA\n" \
	    jexec j sysctl -n security.jail.env
}
env_readable_by_jail_cleanup()
{
	jail -r j
	return 0
}

atf_test_case "not_inheritable" "cleanup"
not_inheritable_head()
{
	atf_set descr 'Test that a jail does not inherit metadata from its parent jail'
	atf_set require.user root
	atf_set execenv jail
}
not_inheritable_body()
{
	setup

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j parent

	atf_check -s exit:0 \
	    jail -c name=parent children.max=1 persist meta="abc" env="cba"

	jexec parent jail -c name=child persist

	atf_check -s exit:0 -o inline:"abc\n" \
	    jls -j parent meta
	atf_check -s exit:0 -o inline:'""\n' \
	    jls -j parent.child meta

	atf_check -s exit:0 -o inline:"cba\n" \
	    jexec parent sysctl -n security.jail.env
	atf_check -s exit:0 -o inline:"\n" \
	    jexec parent.child sysctl -n security.jail.env
}
not_inheritable_cleanup()
{
	jail -r parent.child
	jail -r parent
	return 0
}

atf_test_case "maxbufsize" "cleanup"
maxbufsize_head()
{
	atf_set descr 'Test that metadata buffer maximum size can be changed'
	atf_set require.user root
	atf_set is.exclusive true
}
maxbufsize_body()
{
	setup

	jn=jailmeta_maxbufsize

	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j $jn

	# the size counts string length and the trailing \0 char
	origmax=$(sysctl -n security.jail.meta_maxbufsize)

	# must be fine with current max
	atf_check -s exit:0 \
	    jail -c name=$jn persist meta="$(printf %$((origmax-1))s)"
	atf_check -s exit:0 -o inline:"${origmax}\n" \
	    jls -j $jn meta | wc -c
	#
	atf_check -s exit:0 \
	    jail -m name=$jn env="$(printf %$((origmax-1))s)"
	atf_check -s exit:0 -o inline:"${origmax}\n" \
	    jls -j $jn env | wc -c

	# should not allow exceeding current max
	atf_check -s not-exit:0 -e match:"too large" \
	    jail -m name=$jn meta="$(printf %${origmax}s)"
	#
	atf_check -s not-exit:0 -e match:"too large" \
	    jail -m name=$jn env="$(printf %${origmax}s)"

	# should allow the same size with increased max
	newmax=$((origmax + 1))
	sysctl security.jail.meta_maxbufsize=$newmax
	atf_check -s exit:0 \
	    jail -m name=$jn meta="$(printf %${origmax}s)"
	atf_check -s exit:0 -o inline:"${origmax}\n" \
	    jls -j $jn meta | wc -c
	#
	atf_check -s exit:0 \
	    jail -m name=$jn env="$(printf %${origmax}s)"
	atf_check -s exit:0 -o inline:"${origmax}\n" \
	    jls -j $jn env | wc -c

	# decrease back to the original max
	sysctl security.jail.meta_maxbufsize=$origmax
	atf_check -s not-exit:0 -e match:"too large" \
	    jail -m name=$jn meta="$(printf %${origmax}s)"
	#
	atf_check -s not-exit:0 -e match:"too large" \
	    jail -m name=$jn env="$(printf %${origmax}s)"

	# the previously set long meta is still readable as is
	# due to the soft limit remains higher than the hard limit
	atf_check_equal '${newmax}' '$(sysctl -n security.jail.param.meta)'
	atf_check_equal '${newmax}' '$(sysctl -n security.jail.param.env)'
	atf_check -s exit:0 -o inline:"${origmax}\n" \
	    jls -j $jn meta | wc -c
	#
	atf_check -s exit:0 -o inline:"${origmax}\n" \
	    jls -j $jn env | wc -c
}
maxbufsize_cleanup()
{
	jail -r jailmeta_maxbufsize
	return 0
}

atf_test_case "allowedchars" "cleanup"
allowedchars_head()
{
	atf_set descr 'Test that the set of allowed chars can be changed'
	atf_set require.user root
	atf_set is.exclusive true
}
allowedchars_body()
{
	setup

	jn=jailmeta_allowedchars
	atf_check -s not-exit:0 -e match:"not found" -o ignore \
	    jls -j $jn
	atf_check -s exit:0 \
	    jail -c name=$jn persist

	# Save the original value
	sysctl -b security.jail.meta_allowedchars > meta_allowedchars.bin

	# All chars
	sysctl security.jail.meta_allowedchars=
	printf $(jot -w '\%o' -s '' -n 127 1 127) > 7bit.bin
	atf_check -s exit:0 \
	    jail -m name=$jn meta="$(cat 7bit.bin)" env="$(cat 7bit.bin)"
	jls -j $jn meta > meta.bin
	jls -j $jn env > env.bin
	printf '\n' >> 7bit.bin # jls adds a newline
	atf_check -s exit:0 diff 7bit.bin meta.bin
	atf_check -s exit:0 diff 7bit.bin env.bin

	# Limited set
	sysctl security.jail.meta_allowedchars="$(printf 'AB\1\2_\3\11C')"
	# should be okay if within the limits
	atf_check -s exit:0 \
	    jail -m name=$jn meta="$(printf 'C\11A\3')" env="$(printf '\1A\2B\3')"
	# should error and not change env
	atf_check -s not-exit:0 -o ignore -e ignore \
	    jail -m name=$jn meta="$(printf 'XC\11A\3')" env="$(printf '_\1A\2B\3')"
	# should error and not change meta
	atf_check -s not-exit:0 -o ignore -e ignore \
	    jail -m name=$jn meta="$(printf '_C\11A\3')" env="$(printf '\1A\2B\3x')"
	# should stay intact after errors
	atf_check -s exit:0 -o inline:"43094103" \
	    jls -j $jn meta | hexdump -e '1/1 "%02x"'
	atf_check -s exit:0 -o inline:"0141024303" \
	    jls -j $jn env | hexdump -e '1/1 "%02x"'

}
allowedchars_cleanup()
{
	# Restore the original value
	test -f meta_allowedchars.bin \
	    && sysctl security.jail.meta_allowedchars="'$(cat meta_allowedchars.bin)'"
	rm *.bin

	jail -r jailmeta_allowedchars
	return 0
}

atf_test_case "keyvalue" "cleanup"
keyvalue_head()
{
	atf_set descr 'Test that metadata can be handled as a set of key=value\n strings using jail(8) and jls(8)'
	atf_set require.user root
	atf_set execenv jail
}
keyvalue_generic()
{
	local meta=$1

	atf_check -sexit:0 -oinline:'""\n'	jls -jj $meta

	# Should be able to extract a key added manually
	atf_check -sexit:0				jail -m name=j $meta="a=1"
	atf_check -sexit:0 -oinline:'a=1\n'		jls -jj $meta
	atf_check -sexit:0 -oinline:'1\n'		jls -jj $meta.a
	atf_check -sexit:0				jail -m name=j $meta="$(printf 'a=2\nb=3')"
	atf_check -sexit:0 -oinline:'a=2\nb=3\n'	jls -jj $meta
	atf_check -sexit:0 -oinline:'2\n'		jls -jj $meta.a
	atf_check -sexit:0 -oinline:'3\n'		jls -jj $meta.b

	# Should provide an empty string for a non-found key
	atf_check -sexit:0 -oinline:'""\n'		jls -jj $meta.c

	# Should be able to lookup multiple keys at once
	atf_check -sexit:0 -oinline:'3 2\n'		jls -jj $meta.b $meta.a

	# Should be able to lookup keys and the whole buffer at once
	atf_check -sexit:0 -oinline:'3 a=2\nb=3 2\n'	jls -jj $meta.b $meta $meta.a

	# Should be able to lookup a key with libxo-based output
	s='{"__version": "2", "jail-information": {"jail": [{"'$meta'.b":"3","'$meta'.c":""}]}}\n'
	atf_check -s exit:0 -o inline:"$s"		jls -jj --libxo json $meta.b $meta.c

	# Should be able to lookup a key with flua
	atf_check -s exit:0 -o inline:"2\n"	\
	    /usr/libexec/flua -ljail -e 'jid, res = jail.getparams("j", {"'$meta'.a"}); print(res["'$meta'.a"])'

	# Should be fine if a buffer is empty
	atf_check -sexit:0				jail -m name=j $meta=
	atf_check -sexit:0 -oinline:'"" "" ""\n'	jls -jj $meta.c $meta $meta.a

	# Should allow adding a new key
	atf_check -sexit:0				jail -m name=j $meta.a=1
	atf_check -sexit:0 -oinline:'1\n'		jls -jj $meta.a
	atf_check -sexit:0 -oinline:'a=1\n'		jls -jj $meta

	# Should allow adding multiple new keys at once
	atf_check -sexit:0				jail -m name=j $meta.c=3 $meta.b=2
	atf_check -sexit:0 -oinline:'3\n'		jls -jj $meta.c
	atf_check -sexit:0 -oinline:'2\n'		jls -jj $meta.b
	atf_check -sexit:0 -oinline:'b=2\nc=3\na=1\n'	jls -jj $meta

	# Should replace existing keys
	atf_check -sexit:0				jail -m name=j $meta.a=A $meta.c=C
	atf_check -sexit:0 -oinline:'A\n'		jls -jj $meta.a
	atf_check -sexit:0 -oinline:'C\n'		jls -jj $meta.c
	atf_check -sexit:0 -oinline:'c=C\na=A\nb=2\n'	jls -jj $meta

	# Should treat empty value correctly
	atf_check -sexit:0				jail -m name=j $meta.b $meta.a=
	atf_check -sexit:0 -oinline:'""\n'		jls -jj $meta.a
	atf_check -sexit:0 -oinline:'""\n'		jls -jj $meta.b
	atf_check -sexit:0 -oinline:'a=\nb=\nc=C\n'	jls -jj $meta

	# Should allow changing the whole buffer and per key at once (order matters)
	atf_check -sexit:0				jail -m name=j $meta.a=1 $meta=ttt $meta.b=2
	atf_check -sexit:0 -oinline:'""\n'		jls -jj $meta.a
	atf_check -sexit:0 -oinline:'2\n'		jls -jj $meta.b
	atf_check -sexit:0 -oinline:'b=2\nttt\n'	jls -jj $meta

	# Should treat only the first equal sign as syntax
	atf_check -sexit:0				jail -m name=j $meta.b==
	atf_check -sexit:0 -oinline:'=\n'		jls -jj $meta.b
	atf_check -sexit:0 -oinline:'b==\nttt\n'	jls -jj $meta

	# Should allow adding or modifying keys with flua
	atf_check -s exit:0 \
	    /usr/libexec/flua -ljail -e 'jail.setparams("j", {["'$meta.b'"]="ttt", ["'$meta'.c"]="C"}, jail.UPDATE)'
	atf_check -sexit:0 -oinline:'ttt\n'		jls -jj $meta.b
	atf_check -sexit:0 -oinline:'C\n'		jls -jj $meta.c
}
keyvalue_body()
{
	setup

	atf_check -s exit:0 \
	    jail -c name=j persist meta env

	keyvalue_generic "meta"
	keyvalue_generic "env"
}
keyvalue_cleanup()
{
	jail -r j
	return 0
}

atf_test_case "keyvalue_contention" "cleanup"
keyvalue_contention_head()
{
	atf_set descr 'Try to stress metadata read/write mechanism with some contention'
	atf_set require.user root
	atf_set execenv jail
	atf_set timeout 30
}
keyvalue_stresser()
{
	local jailname=$1
	local modifier=$2

	while true
	do
		jail -m name=$jailname $modifier
	done
}
keyvalue_contention_body()
{
	setup

	atf_check -s exit:0 jail -c name=j persist meta env

	keyvalue_stresser "j" "meta.a=1" &
	apid=$!
	keyvalue_stresser "j" "meta.b=2" &
	bpid=$!
	keyvalue_stresser "j" "env.c=3" &
	cpid=$!
	keyvalue_stresser "j" "env.d=4" &
	dpid=$!

	for it in $(jot 8)
	do
		jail -m name=j meta='meta=META' env='env=ENV'
		sleep 1
		atf_check -sexit:0 -oinline:'1\n'	jls -jj meta.a
		atf_check -sexit:0 -oinline:'2\n'	jls -jj meta.b
		atf_check -sexit:0 -oinline:'3\n'	jls -jj env.c
		atf_check -sexit:0 -oinline:'4\n'	jls -jj env.d
		atf_check -sexit:0 -oinline:'META\n'	jls -jj meta.meta
		atf_check -sexit:0 -oinline:'ENV\n'	jls -jj env.env
	done

	# TODO: Think of adding a stresser on the kernel side which does
	#       osd_set() w/o allprison lock. It could test the compare
	#       and swap mechanism in jm_osd_method_set().

	kill -9 $apid $bpid $cpid $dpid
}
keyvalue_contention_cleanup()
{
	jail -r j
	return 0
}

atf_init_test_cases()
{
	atf_add_test_case "jail_create"
	atf_add_test_case "jail_modify"
	atf_add_test_case "jail_add"
	atf_add_test_case "jail_reset"

	atf_add_test_case "jls_libxo"

	atf_add_test_case "flua_create"
	atf_add_test_case "flua_modify"

	atf_add_test_case "env_readable_by_jail"
	atf_add_test_case "not_inheritable"

	atf_add_test_case "maxbufsize"
	atf_add_test_case "allowedchars"

	atf_add_test_case "keyvalue"
	atf_add_test_case "keyvalue_contention"
}
