#!/bin/sh

########################################
# twish.sh
#   twitter with only shell
########################################
# This script needs following external commands:
#    sh, curl, md5sum, openssl, sed, dd, date, sort, cat, basename, od, tr, cut, dirname.
# You would have almost all of them, but you might install curl and openssl by yourself.

CONSUMER_KEY="o71FGRBiXFzzSplw26wMRg"
CONSUMER_SECRET="BCwtSqJHEsZOPQaKhUbVvfGFkXtci9dbpggeWZg6E"

CONFDIR="`dirname "$0"`/conf"
CONFFILE="${CONFDIR}/twish.conf"

HTTP_CMD_CONF="curl"

# echo debug info
decho(){
	echo " * ""$@" >&2
}
# echo error info
eecho(){
	echo "** ""$@" >&2
}

# get configuration
# $1 : name
get_conf(){
	sed -e "/^${1}:/!d;s/${1}://" "${CONFFILE}"
}
# set configuration
# $1 : name
# $2 : value
set_conf(){
	remove_conf "$1"
	echo "${1}:${2}" >>"${CONFFILE}"
}
# remove configuration
# $1 : name
remove_conf(){
	sed -i "/^${1}:/d" "${CONFFILE}"
}

url_param_filter(){
	sed "s/.*${1}=\\([^&]*\\).*/\\1/"
}


generateNonce(){
	dd if=/dev/urandom bs=1024 count=1 2>/dev/null | md5sum | cut -c 1-32
}

getTimeStamp(){
	date +%s
}

# replace characters [^-._~0-9a-zA-Z] to "%xx" (xx:hexadecimal).
	ENCODE_URI_SED_SCRIPT="$(for i in `seq 1 127`; do
		echo -e "\\x$(printf '%02x' ${i})"
	done | sed -e '/[^-._~0-9a-zA-Z]/d;/^$/d' | while read LINE; do
		echo "s/`echo -n ${LINE} | od -t x1 -A n | tr a-z A-Z`/${LINE}/g;"
	done)"
encodeURI(){
	echo -n "$@" | od -t x1 -A n | tr a-z A-Z | tr -d '\n' | sed -e "${ENCODE_URI_SED_SCRIPT}" | tr ' ' '%'
}

# generate hash.
# $1 : method (POST, GET)
# $2 : URL
# $3 : parameter
generateHash()
{
	ENCODED_URL="`encodeURI "$2"`"
	# sort parameters
	ENCODED_PARAM="`encodeURI "$(sort_url_params "$3")"`"
	QUERY="${1}&${ENCODED_URL}&${ENCODED_PARAM}"
	HASH="`echo -n "${QUERY}" | openssl sha1 -hmac "${CONSUMER_SECRET}&${ACCESS_SECRET}" -binary | openssl base64`"
	encodeURI "${HASH}"
}

# generates header for OAuth.
generateHeader()
{
	NONCE="`generateNonce`"
	TIMESTAMP="`getTimeStamp`"
	echo -n "oauth_consumer_key=${CONSUMER_KEY}"
	echo -n "${HEADER}&oauth_nonce=${NONCE}"
	echo -n "${HEADER}&oauth_signature_method=HMAC-SHA1"
	echo -n "${HEADER}&oauth_timestamp=${TIMESTAMP}"
	echo -n "${HEADER}&oauth_token=${ACCESS_KEY}"
	echo -n "${HEADER}&oauth_version=1.0"
}


# $1 : method (GET, POST)
# $2 : URL
# $3 : header data
# $4 : request query
connect()
{
	RET=
	METHOD="$1"
	URL="$2"
	HEADER="$3"
	QUERY="$4"
	if [ "x${QUERY}" != "x" ]; then
		QUERY_CONNECT="${QUERY}&"
	fi
	HASH="`generateHash "${METHOD}" "${URL}" "${QUERY_CONNECT}${HEADER}"`"
	AUTHORIZATION_HEADER="Authorization: OAuth `echo -n "${HEADER}" | sed -e 's/\([^=&][^=&]*\)=\([^=&]*\)/\1="\2"/g;s/&/, /g'`, oauth_signature=\"${HASH}\""
	case "${HTTP_CMD_CONF}" in
		curl)
			if [ "${METHOD}" == "GET" ]; then
				#curl --get "${URL}" --header "${AUTHORIZATION_HEADER}" --data "${QUERY}" 2>/dev/null
				curl --get "${URL}" --header "${AUTHORIZATION_HEADER}" --data "${QUERY}" 2>/dev/null
				RET=$?
			else
				#curl --request 'POST' "${URL}" --header "${AUTHORIZATION_HEADER}" --data "${QUERY}" 2>/dev/null
				curl --request 'POST' "${URL}" --header "${AUTHORIZATION_HEADER}" --data "${QUERY}" 2>/dev/null
				RET=$?
			fi
			if [ ${RET} != 0 ]; then
				eecho "error happened..."
				eecho "error code: ${RET}"
			fi
			;;
		*)
			eecho "unsupported function:HTTP_COMMAND = ${HTTP_CMD_CONF}"
			;;
	esac
}

# sort url parameters (param1=val1&param2=val2&...)
# FIXME : i want stream (stdin -> stdout) version.
sort_url_params()
{
	# remove \n at the last of the line by substituting to variable.
	TEMP="`echo -n "$@" | sed -e 's/&/\n/g' | sort -t "=" -k 1,1`"
	#TEMP="`echo -n "${TEMP}" | sed -e ':l;N;$!b l;s/\n/&/g'\"
	echo -n "${TEMP}" | tr '\n' '&'
}


# get request key and request secret for OAuth.
getRequestToken()
{
	URL="http://twitter.com/oauth/request_token"
	HEADER="`generateHeader`"

	REQUEST_TOKEN="`connect "GET" "${URL}" "${HEADER}"`"
	if [ "x${REQUEST_TOKEN}" == "x" ]; then
		eecho "cannot get request token."
		exit 1
	fi
	REQUEST_KEY="`echo "${REQUEST_TOKEN}" | url_param_filter "oauth_token"`"
	REQUEST_SECRET="`echo "${REQUEST_TOKEN}" | url_param_filter "oauth_token_secret"`"

	echo "give me PIN code from this url using your browser." >&2
	echo "http://twitter.com/oauth/authorize?oauth_token=${REQUEST_KEY}" >&2
	echo -n "pin > " >&2
	read PIN_CODE

	echo "${REQUEST_KEY} ${REQUEST_SECRET} ${PIN}"
}

# get access tokens for OAuth and save to config file.
# $1 : request key
# $2 : request secret
# $3 : pin code
getAccessToken()
{
	REQUEST_KEY="$1"
	REQUEST_SECRET="$2"
	PIN_CODE="$3"

	URL="http://twitter.com/oauth/access_token"
	HEADER="`generateHeader`"

	ACCESS_TOKEN="`connect "GET" "${URL}" "${HEADER}"`"
	if [ "x${ACCESS_TOKEN}" == "x" ]; then
		eecho "cannot get access token."
		exit 1
	fi

	ACCESS_KEY="`echo "${ACCESS_TOKEN}" | url_param_filter "oauth_token"`"
	ACCESS_SECRET="`echo "${ACCESS_TOKEN}" | url_param_filter "oauth_token_secret"`"
	set_conf "ACCESS_KEY" "${ACCESS_KEY}"
	set_conf "ACCESS_SECRET" "${ACCESS_SECRET}"
}

# get timeline from twitter.
getTimeLine()
{
	URL="http://api.twitter.com/1.1/statuses/home_timeline.json"
	HEADER="`generateHeader`"

	JSON="`connect "GET" "${URL}" "${HEADER}"`"

	# FIXME : cheap error handling!
	if [ "x${JSON}" == "x" ]; then
		eecho "cannot get TimeLine."
		exit 1
	fi

	# FIXME : the data needs parse and format.
	echo "${JSON}"
}

# post tweet to twitter.
# param : string to tweet.
postTweet()
{
	TWEET="`encodeURI "${@}"`"
	if [ "x${TWEET}" == "x" ]; then
		eecho "cannot encode tweet. check the tweet is not empty."
		exit 1
	fi

	JSON=""
	URL="https://api.twitter.com/1.1/statuses/update.json"
	HEADER="`generateHeader`"

	PARAM="status=${TWEET}"
	#PARAM="${PARAM}&in_reply_to=xxx"

	JSON="`connect "POST" "${URL}" "${HEADER}" "${PARAM}"`"
	if [ "x${JSON}" == "x" ]; then
		eecho "cannot get Mentions."
		exit 1
	fi

	echo "${JSON}"
}

# get mentions timeline from twitter.
getMentions()
{
	JSON=""
	URL="https://api.twitter.com/1.1/statuses/mentions_timeline.json"
	HEADER="`generateHeader`"

	PARAM="count=2"
	PARAM="${PARAM}&since_id=14927799"

	JSON="`connect "GET" "${URL}" "${HEADER}" "${PARAM}"`"
	if [ "x${JSON}" == "x" ]; then
		eecho "cannot get Mentions."
		exit 1
	fi

	echo "${JSON}"
}


# load and initialize config.
init_config()
{
	if [ ! -f "${CONFFILE}" ]; then
		# make config file
		mkdir -p "`dirname "${CONFFILE}"`"
		:>"${CONFFILE}"
		set_conf "HTTP_COMMAND" "curl"
	fi
	ACCESS_KEY="`get_conf "ACCESS_KEY"`"
	ACCESS_SECRET="`get_conf "ACCESS_SECRET"`"
	HTTP_CMD_CONF="`get_conf "HTTP_COMMAND"`"
	case "${HTTP_CMD_CONF}" in
		wget)
			;;
		curl)
			;;
		*)
			HTTP_CMD_CONF="curl"
			# invalid value. change to default value
			set_conf "HTTP_COMMAND" "curl"
			;;
	esac
}

# show usage.
usage()
{
	echo "`basename $0` operation args" >&2
	echo "    operations: timeline, mentions, tweet, reset, config, usage" >&2
}


### main script

# load config
init_config
if [ "x${ACCESS_KEY}" == "x" -o "x${ACCESS_SECRET}" == "x" ]; then
	# if access tokens does not exist, get it and exit.
	REQUEST_TOKEN="`getRequestToken`"
	getAccessToken ${REQUEST_TOKEN}
else
	ARG="$1"
	shift 1
	# operation string is case insensitive.
	case "`echo "${ARG}" | tr A-Z a-z`" in
		reset)
			# reset ONLY access tokens.
			remove_conf "ACCESS_KEY"
			remove_conf "ACCESS_SECRET"
			;;
		tweet|update)
			postTweet "$@"
			;;
		conf|config|setting)
			echo "config file: ${CONFFILE}" >&2
			cat "${CONFFILE}"
			;;
		tl|timeline)
			getTimeLine
			;;
		mention|mentions)
			getMentions
			;;
		*)
			eecho "invalid operation: ${ARG}"
			usage
			;;
	esac
fi


