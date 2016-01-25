#!/bin/sh

RESET="\e[0m"
RED="${RESET}\e[0;31m"
GREEN="${RESET}\e[0;32m"
YELLOW="${RESET}\e[0;33m"
BLUE="${RESET}\e[0;34m"
PINK="${RESET}\e[0;35m"
CYAN="${RESET}\e[0;36m"

MODE=""
SESSION_NAME=""
SIGN_RET=""
USERNAME=""
PASSWORD=""

WORK_DIR=$(cd "$(dirname "$0")" && pwd)
CONFIG_FILE="$WORK_DIR/sign.config.json"
TEMP_FILE="$WORK_DIR/.sign.temp"
USER_AGENT="mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.152 Safari/537.36"

_p() {
    if [ -z "$MODE" ]; then
        printf "$(date '+[%Y-%m-%d %H:%M:%S]') "
    else
        printf "$(date '+[%Y-%m-%d %H:%M:%S]') ($MODE) "
    fi
    printf "$@"
    printf "${RESET}\n"
}

_check() {
    exec=(jq http)
    ret=0
    for var in ${exec[@]};
    do
        type $var >/dev/null 2>/dev/null
        if [ $? -ne 0 ]; then
            _p "${RED}脚本依赖的执行程序${var}不存在，安装参考README.md"
            ret=1
        fi
    done
    parse=$(jq "." $CONFIG_FILE 2>&1)
    if [ $? -ne 0 ]; then
        _p "${RED}解析${CONFIG_FILE}错误${parse}"
        ret=1
    fi
    if [ $ret -ne 0 ]; then
        exit $ret
    fi
}

_zimuzu() {
    host_url="http://www.zimuzu.tv"
    login_url="http://www.zimuzu.tv/user/login"
    login_ajax="http://www.zimuzu.tv/User/Login/ajaxLogin"
    sign_url="http://www.zimuzu.tv/user/sign"
    dosign_url="http://www.zimuzu.tv/user/sign/dosign"
    http --session $SESSION_NAME $login_url >/dev/null
    body=$(http --print b --session $SESSION_NAME -f POST $login_ajax "account=$USERNAME" "password=$PASSWORD" "remember=1" "url_back=$host_url" Referer:$login_url)
    # _p "LOGIN: $body"
    if [ $(echo "$body" | jq '.status') -ne 1 ]; then
        SIGN_RET=$(echo "$body" | jq -r '.info')
        return -1
    fi
    http --session $SESSION_NAME $sign_url Referer:$login_url >/dev/null
    _p "sleep 15s..."
    sleep 15
    body=$(http --print b --session $SESSION_NAME $dosign_url)
    # _p "SIGN: $body"
    if [ $(echo "$body" | jq '.status') -ne 1 ]; then
        # {"status":0,"info":"","data":0}
        # 已经签到
        return 1
    else
        # {"status":1,"info":"","data":"3"}
        SIGN_RET=$(echo "$body" | jq -r '.data')
        return 0
    fi
}

_v2ex() {
    # 登录
    host_url="https://www.v2ex.com"
    v2ex_sign='https://www.v2ex.com/signin'
    http --session $SESSION_NAME $v2ex_sign >$TEMP_FILE
    grep '登出' $TEMP_FILE >/dev/null
    if [ $? -ne 0 ]; then
        once=$(grep 'name="once"' $TEMP_FILE)
        reg_once='value="([0-9]+)" name="once"'
        if [[ $once =~ $reg_once ]]; then
            once=${BASH_REMATCH[1]}
            http --session $SESSION_NAME -f POST $v2ex_sign "u=${USERNAME}" "p=${PASSWORD}" "once=${once}" "next=/" Referer:$v2ex_sign >$TEMP_FILE
            grep '用户名和密码无法匹配' $TEMP_FILE >/dev/null
            if [ $? -eq 0 ]; then
                SIGN_RET="用户名或密码错误"
                return -1
            fi
        else
            SIGN_RET="登录异常"
            return -1
        fi
    fi

    # 签到
    mission_daily="https://www.v2ex.com/mission/daily"
    http --session $SESSION_NAME $host_url >$TEMP_FILE   # 这里需要先访问主页
    http --session $SESSION_NAME $mission_daily "Referer:$host_url" "User-Agent:$USER_AGENT" >$TEMP_FILE
    redeem=$(grep 'mission/daily/redeem' $TEMP_FILE)
    if ! test "$redeem"; then
        # 已经签到
        return 1
    fi
    reg_redeem="/mission/daily/redeem\?once=(.*)'"
    if [[ $redeem =~ $reg_redeem ]]; then
        http --session $SESSION_NAME -f GET "https://www.v2ex.com/mission/daily/redeem?once=${BASH_REMATCH[1]}" "Referer:$mission_daily" "User-Agent:$USER_AGENT" >$TEMP_FILE
        http --session $SESSION_NAME $mission_daily "Referer:$mission_daily" "User-Agent:$USER_AGENT" >$TEMP_FILE
        grep '每日登录奖励已领取' $TEMP_FILE >/dev/null
        if [ $? -eq 0 ]; then
            cont=$(grep '已连续登录' $TEMP_FILE)
            reg_cont="已连续登录[ ]*([0-9]+)[ ]*天"
            if [[ $cont =~ $reg_cont ]]; then
                SIGN_RET="${BASH_REMATCH[1]}"
                # 获取用户信息
                http --session $SESSION_NAME $host_url >$TEMP_FILE
                user_info=$(grep "bigger.*member" $TEMP_FILE)
                reg_user='member.*>(.*)</a>'
                user_name=""
                if [[ $user_info =~ $reg_user ]]; then
                    user_name="${BASH_REMATCH[1]}"
                else
                    SIGN_RET="获取用户信息异常"
                    return -1
                fi
                user_info=$(grep "/notifications" $TEMP_FILE)
                reg_user='balance_area.*>[ ]*([0-9]+)[ ]*<img.*silver.*>[ ]*([0-9]+)[ ]*<img.*/notifications.*>(.+)</a></div>$'
                if [[ $user_info =~ $reg_user ]]; then
                    silver=${BASH_REMATCH[1]}
                    bronze=${BASH_REMATCH[2]}
                    notifi=${BASH_REMATCH[3]}
                    if [[ notifi =~ [1-9] ]]; then
                        notifi="$notifi (https://www.v2ex.com/notifications)"
                    fi
                    _p "($user_name) $silver 银币 $bronze 铜币 $notifi"
                    return 0
                else
                    # 只有银币的情况，一般是新用户
                    reg_user='balance_area.*>[ ]*([0-9]+)[ ]*<img.*silver.*>.*/notifications.*>(.+)</a></div>$'
                    if [[ $user_info =~ $reg_user ]]; then
                        silver=${BASH_REMATCH[1]}
                        notifi=${BASH_REMATCH[2]}
                        if [[ notifi =~ [1-9] ]]; then
                            notifi="$notifi (https://www.v2ex.com/notifications)"
                        fi
                        _p "($user_name) $silver 银币 $notifi"
                        return 0
                    else
                        SIGN_RET="获取用户信息异常"
                        return -1
                    fi
                fi
            fi
        fi
    fi
    SIGN_RET="签到异常"
    return -1
}

_smzdm() {
    zhiyou_url="http://zhiyou.smzdm.com"
    user_url="http://zhiyou.smzdm.com/user"
    login_url="https://zhiyou.smzdm.com/user/login?redirect_to=$user_url"
    login_ajax="http://zhiyou.smzdm.com/user/login/ajax_check"
    sign_url="http://zhiyou.smzdm.com/user/checkin/jsonp_checkin"
    http --session $SESSION_NAME $zhiyou_url "User-Agent:$USER_AGENT" >/dev/null
    http --session $SESSION_NAME $user_url "User-Agent:$USER_AGENT" >/dev/null
    http --session $SESSION_NAME $login_url "User-Agent:$USER_AGENT" >/dev/null
    body=$(http --print b --session $SESSION_NAME -f POST $login_ajax "username=$USERNAME" "password=$PASSWORD" "rememberme=1" "captcha=" "is_third=0" "redirect_to=$user_url" "Referer:$login_url" "User-Agent:$USER_AGENT")
    # [{"error_code":0,"error_msg":"","is_use_captcha":false,"data":[],"redirect_to":"http:\/\/zhiyou.smzdm.com"}]
    # [{"error_code":111103,"error_msg":"\u60a8\u8f93\u5165\u7684\u8d26\u53f7\/\u5bc6\u7801\u65e0\u6548\uff0c\u8bf7\u91cd\u65b0\u8f93\u5165","is_use_captcha":false,"data":[],"redirect_to":"http:\/\/zhiyou.smzdm.com\/user"}]
    if [ $(echo "$body" | jq '.error_code') -ne 0 ]; then
        SIGN_RET=$(echo "$body" | jq -r '.error_msg')
        return -1
    fi
    http --session $SESSION_NAME $user_url >$TEMP_FILE
    grep "登录" $TEMP_FILE >/dev/null
    if [ $? -eq 0 ]; then
        SIGN_RET="登录异常"
        return -1
    fi
    # _p "登录成功"
    body=$(http --session $SESSION_NAME $sign_url "User-Agent:$USER_AGENT")
    error_code=$(echo "$body" | jq '.error_code')
    if [ $error_code -ne 0 ]; then
        SIGN_RET="签到异常"
        return -1;
    fi
    # {"error_code":0,"error_msg":"","data":{"add_point":10,"checkin_num":1,"point":30,"exp":30,"gold":0,"prestige":"0","rank":0,"slogan":"<div class="signIn_data">\u4eca\u65e5\u5df2\u9886<span class="red">10<\/span>\u79ef\u5206\uff0c\u518d\u7b7e\u5230<span class="red">2<\/span>\u5929\u53ef\u9886<span class="red">12<\/span>\u79ef\u5206<\/div>"}}
    # {"error_code":0,"error_msg":"\u5df2\u7b7e\u5230","data":{"add_point":0,"checkin_num":"1","point":30,"exp":30,"gold":0,"prestige":"0","rank":0,"slogan":"<div class="signIn_data">\u4eca\u65e5\u5df2\u9886<span class="red">10<\/span>\u79ef\u5206\uff0c\u518d\u7b7e\u5230<span class="red">2<\/span>\u5929\u53ef\u9886<span class="red">12<\/span>\u79ef\u5206<\/div>"}}
    checkin_num=$(echo "$body" | jq -r ".data.checkin_num")
    point=$(echo "$body" | jq ".data.point")
    exp=$(echo "$body" | jq ".data.exp")
    gold=$(echo "$body" | jq ".data.gold")
    rank=$(echo "$body" | jq ".data.rank")
    _p "point:${point}, exp:${exp}, gold:${gold}, rank:${rank}"
    add_point=$(echo "$body" | jq '.data.add_point')
    if [ $add_point -eq 0 ]; then
        # 已经签到
        return 1
    fi
    SIGN_RET=${checkin_num}
    return 0
}

_v2dn() {
    host_url="http://www.v2dn.com/"
    login_url="http://www.v2dn.com/login.php"
    login_post="http://www.v2dn.com/loginUpdate.php"
    checkin_url="http://www.v2dn.com/checkIn.php"
    point_url="http://www.v2dn.com/mypoints.php"
    http --session $SESSION_NAME $login_url "User-Agent:$USER_AGENT" >$TEMP_FILE
    md5_match=$(grep 'md5' $TEMP_FILE)
    if [ $? -ne 0 ]; then
        SIGN_RET="签到异常"
        return -1
    fi
    reg_md5='md5.*value="(.+)">'
    if [[ $md5_match =~ $reg_md5 ]]; then
        md5str=${BASH_REMATCH[1]}
        body=$(http --session $SESSION_NAME -f POST $login_post "email=$USERNAME" "password=$PASSWORD" "md5=$md5str" "button= 登 录" "User-Agent:$USER_AGENT" "Referer:$login_url")
        http --session $SESSION_NAME $host_url >/dev/null
        http --session $SESSION_NAME $checkin_url >/dev/null
        http --session $SESSION_NAME $point_url >$TEMP_FILE
        point_match=$(grep 'balance_area' $TEMP_FILE)
        reg_point='([0-9]+)</div>'
        if [[ $point_match =~ $reg_point ]]; then
            point=${BASH_REMATCH[1]}
            _p "point:$point"
        fi
    else
        SIGN_RET="签到异常"
        return -1
    fi
}

i=1
while true
do
    _check
    if [ $# -gt 0 ]; then
        if [ "$1"x = "all"x ]; then
            op=$(jq -r "keys[$(($i-1))]" $CONFIG_FILE)
        else
            op=${!i}
        fi
        i=$(($i+1))
        if [ -z $op ] || [ "$op" = "null" ]; then
            break
        fi
    else
        printf "> "
        read data
        if [ -z "$data" ]; then
            continue
        fi
        op=$(echo $data | cut -d " " -f 1)
    fi
    MODE=""
    SESSION_NAME=""
    case "$op" in
        q | quit)
            break
            ;;
        *)
            type "_$op" >/dev/null 2>/dev/null
            if [ $? -eq 0 ]; then
                MODE=$op
                _p "sign..."
                SIGN_RET=""
                USERNAME=$(jq -r ".$op.u" $CONFIG_FILE)
                PASSWORD=$(jq -r ".$op.p" $CONFIG_FILE)
                # 部分用户名可能带特殊符号，所以这里做了编码处理
                base64_u=$(echo "$USERNAME" | base64 | sed 's/=//g')
                SESSION_NAME="${op}_${base64_u}"
                if [ "$USERNAME" = "null" ] || [ "$PASSWORD" = "null" ]; then
                    _p "${RED}用户名[.$op.u]或密码[.$op.p]不存在"
                    continue
                fi
                if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
                    _p "${RED}用户名[.$op.u]或密码[.$op.p]为空"
                    continue
                fi
                _$op
                retcode=$?
                if [ $retcode -eq 0 ]; then
                    if [ -z $SIGN_RET ]; then
                        _p "${GREEN}签到成功"
                    else
                        _p "${GREEN}签到成功, 已连续签到${SIGN_RET}天"
                    fi
                elif [ $retcode -eq 1 ]; then
                    _p "${YELLOW}今天已经签到"
                else
                    if [ -z $SIGN_RET ]; then
                        _p "${RED}签到失败"
                    else
                        _p "${RED}签到失败 [$SIGN_RET]"
                    fi
                fi
            else
                _p "$op not exists"
                break
            fi
            ;;
    esac
done
rm -f $TEMP_FILE >/dev/null 2>&1
