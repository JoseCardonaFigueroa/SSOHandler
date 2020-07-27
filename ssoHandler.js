/**
 * This allows the to follow the SSO Authentication Flow with PKCE
 */
function SSOHandler( client_id, idp_id, redirect_uri, token_endpoint, authorize_endpoint, cti_gw) {
    this.client_id = client_id;
    this.idp_id = idp_id;
    this.redirect_uri = encodeURI(redirect_uri);
    this.token_endpoint = token_endpoint;
    this.authorize_endpoint = authorize_endpoint;
    this.code_challenge = '';
    this.code_verifier = '';
    this.cti_gw = cti_gw;
    /**
     * Allow to generate a URL safe code_verifier which is a requirement of the PKCE
     */
    this.generateCodeVerifier = function () {
        return this.generateRandomString(128);
    };
    this.generateCodeChallenge = function (code_verifier) {
        return code_challenge = this.base64URL(CryptoJS.SHA256(code_verifier))
    }
    /**
    * Generates a random string with valid characters
    * @param {*} length
    */
    this.generateRandomString = function(length){
       var text = "";
       var possible =
       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
       for (var i = 0; i < length; i++) {
       text += possible.charAt(Math.floor(Math.random() * possible.length));
       }
       return text;
   };
   /**
     * Redirects the page to the/authorize endpoint and with the d
     */
    this.submit = function () {
        
        this.code_verifier = this.generateCodeVerifier();
        this.code_challenge = this.generateCodeChallenge(this.code_verifier);

        localStorage.setItem("code_verifier", this.code_verifier);
        
        var url =
        this.authorize_endpoint+"?client_id="+this.client_id+"&response_type=code&scope=openid&redirect_uri="+this.redirect_uri+"&state=state-aplsdfjoqjwdosjafñljaslñdfjaslñdfjlaksdfklasjdfklñasjfdlñasdflñk&code_verifier=" +
        this.code_verifier +
        "&code_challenge=" +
        this.code_challenge +
        "&idp="+this.idp_id+"&code_challenge_method=S256";
        window.location.href = url;
    };
    /**
     * This method encodes a string into base 64 url safe
     * It has a dependency to CryptoJS
     * @param {*} string 
     */
    this.base64URL = function (string) {
        return string
        .toString(CryptoJS.enc.Base64)
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
    };

    /**
     * Method that retrieves the JWT after /authorize code is retrieved. 
     */
    this.getToken = function (code) {
        debugger;
        console.log("Code: " + this.code);

        this.code_verifier = localStorage.getItem("code_verifier");
        const Http = new XMLHttpRequest();
        var url =this.token_endpoint;

        var params ="grant_type=authorization_code&client_id="+this.client_id+"&redirect_uri=" +
        this.redirect_uri +
        "&code=" +
        code +
        "&code_verifier=" +
        this.code_verifier;

        // Http.open("POST", url);
        $.ajax({
            method: 'POST',
            url : url+'?'+params,
            cache: false,
            context : this,
            data: params,
            headers: {
                'accepts': 'application/json',
                'cache-control' : 'no-cache',
                'content-type' : 'application/x-www-form-urlencoded'
            },
            success : function (data, textStatus, jqXHR) {
                this.bwAuth(data.access_token);
                console.log(data.access_token);

            },
            error: function (jqXHR, textStatus, errorThrown) {
                console.log(errorThrown);
                console.log(textStatus);
                console.log(jqXHR.responseJSON);
                if(jqXHR.status == 400){
                    this.submit();
                }
            },
            async: false
        });
    }

    /**
     * 
     * Helper method that allows to get the URL params
     * 
     */
    this.getUrlVars = function () {
        var vars = {};
        var parts = window.location.href.replace(
        /[?&]+([^=&]+)=([^&]*)/gi,
        function(m, key, value) {
            vars[key] = value;
        });
        return vars;
    };
    this.authUser = function () {
        
        var code = this.getUrlVars()["code"];
        var state = this.getUrlVars()["state"];
        var jwtSsoStr = localStorage.getItem('jwtTokenSso');
        if(jwtSsoStr != ''){
            var jwtSso = JSON.parse(jwtSsoStr);
        }
        
        console.log(jwtSso);

        //setTimeout(function(){
            if (code == undefined) {
                localStorage.setItem('jwtTokenSso', '');
                debugger;
                this.submit();
            } else if(jwtSso == '' || jwtSso == undefined) {

                this.getToken(code);

            } 
        //},5000);

    };

    /**
     * TODO: Once the JWT is retrieved, it should be sent to BW
     */
    this.bwAuth = function(jwtSso){
        debugger;
        nextiva_username = this.parseJwt(jwtSso)["com.nextiva.ident.voice.pid"] +"@nextiva.com";
        //this.callLoginValidation('adjflasjd','añlksdfjsaldfjsa',jwtSso);
        var authHeader = 'Bearer '+jwtSso;
        var body = '{\"communicatorName\":\"SFDCWebSock\",\"httpContact\":\"http://192.168.1.128:9991/EventListner\",\"applicationId\":\"Salesforce.com\"}';
        $.ajax({
            method: 'POST',
            url: this.cti_gw + '/event/login',
            contentType: 'application/json',
            data: body,
            cache: false,
            async: false,
            header: {
                'Authorization' : authHeader,
                'accepts': 'application/json',
                'cache-control' : 'no-cache',
                'content-type' : 'application/json'
            },
            beforeSend: function (xhr) {
                /* Authorization header */
                xhr.setRequestHeader("Authorization", authHeader);
                xhr.setRequestHeader("X-Mobile", "false");
            },
            success: function (result, status, xhr) {
                debugger;
                var phoneState = new SoftPhoneState();
                console.log("clearing localStorage");
                phoneState.putOnHook();
                phoneState.write();
                console.log(result);
                debugger;
                if(result.code == 1){
                    console.error("User not able to auth in CTI", result.msg)
                }
                nextiva_token = result.authToken;
                //nextiva_username = result.nextivaUserName;
                nextiva_password = result.nextivaUserPwd;

                localStorage.setItem("userName", nextiva_username);
                localStorage.setItem("authToken", nextiva_token);
                localStorage.setItem("userPwd", nextiva_password);
                localStorage.setItem("nextivaUserId", result.nextivaUserName);
                localStorage.setItem("isUserLoggedIn", true);
                phoneState.isUserLoggedIn = true;
                document.cookie = "nextivaUserToken="+result.authToken;
                $('#sso-sing-in').attr('disabled', 'false');
                debugger;
                phoneState.write();
                loginUser(nextiva_username, nextiva_password, function(result, event){
                    saveCredentials(nextiva_username, nextiva_password, true, function(result, event) {
                        debugger;
                        console.debug('save credentials called'); 
                    });
                });
                showDialer(true);
            },
            error: function (xhr, status, error) {
                console.error(error);
                console.error(status);
                $(".text-error").text(error).show();
                console.log(result.errorMsg);
                $('#sso-sing-in').attr('disabled', 'false');
            }
        });
    };
    this.parseJwt = function (token) {
        var base64Url = token.split('.')[1];
        var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        var jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));

        return JSON.parse(jsonPayload);
    };
    this.callLoginValidation = function(username, pwd, oktaToken){
        $(document).ready(function () {
            // Calls controller method userLogin
            debugger;
            loginUserSso('añldfjaslñdfj','añldsfjlasf',oktaToken,function (result,event) {
                console.log(result);
                debugger; 
                if(JSON.parse(result.status)) {
                    nextiva_token = result.nextivaUserToken;
                    nextiva_username = result.nextivaUserName;
                    nextiva_password = result.nextivaUserPwd;

                     localStorage.setItem("userName", nextiva_username);
                     localStorage.setItem("authToken", nextiva_token);
                    localStorage.setItem("userPwd", nextiva_password);
                    localStorage.setItem("nextivaUserId", result.nextivaUserName);
                document.cookie = "nextivaUserToken="+result.nextivaUserToken;
                saveCredentials(nextiva_username, nextiva_password, true, function(result, event) {
                    debugger;
                            console.debug('save credentials called'); 
                            });
                showDialer(true);
                // var popupWindow = window.open('https://productintegrations-dev-dev-ed--nextiva.visualforce.com/apex/TestWebSocketConnection','popUpWindow','height=300,width=700,left=50,top=50,resizable=yes,scrollbars=yes,toolbar=yes,menubar=no,location=no,directories=no, status=yes');
                } else {
                $(".text-error").text(result.errorMsg).show();
                console.log(result.errorMsg);

                }
                $('#sso-sing-in').attr('disabled', 'false');
            });
    });

    }
}
