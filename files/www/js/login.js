/*==================================================
 Login的动作
 将预定义的用户名和密码提交给后台
 ==================================================*/
define(["avalon"], function (avalon) {

    //获取XHR对象
    var getXHR = function () {
        return new (window.XMLHttpRequest || ActiveXObject)("Microsoft.XMLHTTP") // jshint ignore:line
    }

    var _action_req_post = function (post_url, query_str, fn) {
       
        var xhr = getXHR();
        
         //发送AJAX请求后的回调处理
        xhr.onreadystatechange = function () {
       // alert("xhr.readyState:"+xhr.readyState);
            if (xhr.readyState === 4) {
                 
                if (xhr.status === 200) {
                    var text = xhr.responseText
                    fn(text)
                } else {
                    alert("Request return " + " " + xhr.status + " " + post_url)
                    return false
                }
            }
        }

    //发送get请求
        xhr.open('GET',post_url+'?'+query_str,true);
        xhr.send();
        //发送POST请求
        // xhr.open("POST", post_url, true)
        // xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded")
        // xhr.send(query_str)
    }
   

    window.LOGIN = {};
    
    // LOGIN.action_req_post = {};
    LOGIN.action_req_post = _action_req_post;
})

