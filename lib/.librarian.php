<?php //251121
########################################################################################################################
#region
    /* 
                                               EPX-PLEX-LIBRARIAN
    PROVIDER : KLUDE PTY LTD
    PACKAGE  : EPX-PLEX
    AUTHOR   : BRIAN PINTO
    RELEASED : 2025-11-27
    
    Copyright (c) 2017-2025 Klude Pty Ltd. https://klude.com.au

    The MIT License

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    */
#endregion
# ######################################################################################################################
# i'd like to be a tree - pilu (._.) // please keep this line in all versions - BP
# ######################################################################################################################
namespace {  \defined('_\MSTART') OR \define('_\MSTART', \microtime(true)); }
namespace { (new class extends \stdClass implements \ArrayAccess {
# ######################################################################################################################
#region START
public readonly array $SRV;
private array $_ = [];
function __construct(){
    
    $this->SRV = $_SERVER;
    $this->_ = [];
    $_SERVER = $this;
    $this->dx();
    \define('_\KEY', \md5($_SERVER['SCRIPT_FILENAME']));
    \define('_\START_FILE', \str_replace('\\','/', __FILE__));
    \define('_\START_DIR', \dirname(\_\START_FILE));
    \define('_\IS_CLI', empty($_SERVER['HTTP_HOST']));
    \define('_\OB_OUT', \ob_get_level());
    !empty($_SERVER['HTTP_HOST']) AND \ob_start();
    \define('_\OB_TOP', \ob_get_level());
    \define('_\PHP_TSP_DEFAULTS',[
        'handler' => 'spl_autoload',
        'extensions' => \spl_autoload_extensions(),
        'path' =>  \get_include_path(),
    ]);
    $this->PLEX_DIR = $_SERVER['_']['PLEX_DIR'] ?? null ?: \dirname(\_\START_DIR, 2);
    $this->PLIB_DIR = $_SERVER['_']['PLIB_DIR'] ?? null ?: \_\START_DIR;
    $this->_['site_dir'] = (\_\IS_CLI
        ? \str_replace('\\','/',\realpath($_SERVER['.']['site_dir'] ?? \getcwd()))
        : \str_replace('\\','/',\realpath(\dirname($_SERVER['SCRIPT_FILENAME'])))
    );
    $this->_['data_dir'] = $this->_['site_dir'].'/.local-data';
    $this->_['root_dir'] = (function() use(&$root_dir, &$root_url){
        if(!\_\IS_CLI){
            $root_url = (function(){
                return (($_SERVER["REQUEST_SCHEME"] 
                    ?? ((\strtolower(($_SERVER['HTTPS'] ?? 'off') ?: 'off') === 'off') ? 'http' : 'https'))
                ).'://'.$_SERVER["HTTP_HOST"];
            })();
            $root_dir = \str_replace('\\','/', \realpath($_SERVER['DOCUMENT_ROOT']));
            if(\is_file($f = "{$root_dir}/.http-root.php")){
                include $f;
            }
        } else {
            for (
                $i=0, $dx=\getcwd(); 
                $dx && $i < 20 ; 
                $i++, $dx = (\strchr($dx, DIRECTORY_SEPARATOR) != DIRECTORY_SEPARATOR) ? \dirname($dx) : null
            ){ 
                if(\is_file($f = "{$dx}/.http-root.php")){
                    include $f;
                    break;
                }
            }
            if(!$root_dir){
                $root_dir = $_SERVER['.']['site_dir'];
                $root_url = "";
            }
        }
        return $root_dir;
    })();
    $this->_['site_urp'] = $site_urp = (function()use($root_dir, $root_url){
        if(\_\IS_CLI){
            if($root_url){
                if(\str_starts_with($_SERVER['.']['site_dir'], $root_dir)){
                    return \substr($_SERVER['.']['site_dir'], \strlen($root_dir));
                } else {
                    return false;
                }
            }
        } else if((\php_sapi_name() == 'cli-server')){
            return '';
        } else {
            $p = \strtok($_SERVER['REQUEST_URI'],'?');
            if((\str_starts_with($p, $n = $_SERVER['SCRIPT_NAME']))){
                return \substr($p, 0, \strlen($_SERVER['SCRIPT_NAME']));
            } else if((($d = \dirname($n = $_SERVER['SCRIPT_NAME'])) == DIRECTORY_SEPARATOR)){
                return '';
            } else {
                return \substr($p, 0, \strlen($d));
            }
        }
    })();
    $this->_['rurp'] = (function(){
        if(\_\IS_CLI){
            if(!\str_starts_with(($s = $_SERVER['argv'][1] ?? ''),'-')){
                $parsed = \parse_url('/'.\ltrim($s,'/'));
                !empty($parsed['query']) AND \parse_str($parsed['query'], $_GET);
                return $parsed['path'];
            } else {
                return '/';
            }
        } else {
            $p = \strtok($_SERVER['REQUEST_URI'],'?');;
            if((\php_sapi_name() == 'cli-server')){
                return $p;
            } else {
                if((\str_starts_with($p, $n = $_SERVER['SCRIPT_NAME']))){
                    return \substr($p,\strlen($n));
                } else if((($d = \dirname($n = $_SERVER['SCRIPT_NAME'])) == DIRECTORY_SEPARATOR)){
                    return $p;
                } else {
                    return \substr($p,\strlen($d));
                }
            }
        }
    })();
    $this->_['root_url'] = $root_url;
    $this->_['site_url'] = $site_url = ($root_url  ? \rtrim($root_url.$site_urp,'/') : "");
    $this->_['base_url'] = $base_url = rtrim($site_url."/"
        .(
            ($this->_['portal'] ?? null ?: '')
            .'.'.($this->_['role'] ?? null ?: '')
        )
        , 
        '/.'
    );
    //$this->_['ctlr_url'] = \rtrim($base_url."/{$this->_['npath']}",'/');
    if(!\_\IS_CLI){
        $this->_['url'] = $url = $root_url.$_SERVER['REQUEST_URI'];
        $this->_ += \parse_url($url);
        $this->_['method'] = $method = $_SERVER['REQUEST_METHOD'] ?? '';
        # ----------------------------------------------------------------------
        $this->_['is_get'] = $is_get = !\in_array($method, ['POST','PUT','PATCH','DELETE']);
        $this->_['action'] = $action = $_REQUEST['--action'] ?? null;
        $this->_['is_action'] = $is_action = ($action || !$is_get) ? true : false;
        $this->_['is_view'] = !$is_action;
        $this->_['referer'] = ($j = $_SERVER['HTTP_REFERER'] ?? null) ? \parse_url($j) : [];
        $this->_['is_top'] = (($dest = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? ($j ? 'document' : null)) === 'document');
        $this->_['is_frame'] = ($dest == 'iframe');
        $this->_['is_mine'] = !$j || \str_starts_with($j, $url);
        $this->_['is_html'] = (\str_contains(($_SERVER['HTTP_ACCEPT'] ?? ''),'text/html'));
        $this->_['is_xhr'] = ('xmlhttprequest' == \strtolower( $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '' ));
        $this->_['headers'] = \iterator_to_array((function(){
            foreach(\getallheaders() as $k => $v){
                yield $k => $v;
            }
        })());
        $this->_['headers']['Accept'] = \explode(',', $this->_['headers']['Accept'] ?? '');
        $this->_['agent'] = $agent = (function(){
            if(!\is_null($agent = $this->_['headers']['Epx-Agent'] ?? null)){
                return $agent;
            } else if('xmlhttprequest' == \strtolower( $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '' )) {
                return 'xhr';
            } else {
                return 'page';
            }
        })();
    }
    
    \is_file($file = $this->PLEX_DIR."/.local-http-root.php") OR \file_put_contents($file, <<<PHP
    <?php
    //return;
    \$root_dir ??= "{$this->_['root_dir']}";
    \$root_url ??= "{$this->_['root_url']}";
    \$_ENV["DB_HOSTNAME"] ??= "localhost"; 
    \$_ENV["DB_USERNAME"] ??= "root"; 
    \$_ENV["DB_PASSWORD"] ??= "pass"; 
    PHP);
    
    $app_dir = $this->PLIB_DIR.'/app';
    $my_dir = $this->PLIB_DIR;
    \is_file($file = $this->PLEX_DIR."/.local-start.php") OR \file_put_contents($file, <<<PHP
    <?php
    namespace {
        \defined('_\PLEX_DIR') OR \define('_\PLEX_DIR', \str_replace('\\\\','/',__DIR__));
        if(\is_file(\$f = (\$_SERVER['FW__SITE_DIR'] ??= (empty(\$_SERVER['HTTP_HOST'])
            ? \str_replace('\\\\','/',\\realpath(\$_SERVER['FW__SITE_DIR'] ?? \getcwd()))
            : \str_replace('\\\\','/',\\realpath(\dirname(\$_SERVER['SCRIPT_FILENAME'])))
        )).'/.cache-start.php')){
            return include \$f;
        } else {
            return include '{$app_dir}/.start.php';
        }
    }
    PHP);
    
    \is_file($file = $this->PLEX_DIR."/.local-config.php") OR \file_put_contents($file, <<<PHP
    <?php
    1 AND \$_[\_\api::class]['github.com']['token'] = '';
    1 AND \$_['USERS']['admin'] = [
        'display_name' => 'Admin',
        'password' => \md5('pass'),
    ];
    PHP);    

    $site_dir = $this->_['site_dir'];
    (function() use($site_dir){
        global $_;
        (isset($_) && \is_array($_)) OR $_ = [];
        if(\is_file($cfg__f = "{$site_dir}/.local-config.php")){
            include $cfg__f;
        }
        $_ENV = $_ + $_ENV;
    })->bindTo(null,null)(); 
}

function offsetSet($n, $v):void {
    throw new \Exception('Set is not supported');
}

function offsetExists($n):bool {
    return isset($this->_[$n]) || isset($this->SRV[$n]);
}

function offsetUnset($n):void {
    throw new \Exception('Unset is not supported');
}

function offsetGet($n):mixed {
    return $this->_[$n] ?? $this->SRV[$n] ?? null;
}

#endregion
# ######################################################################################################################
#region DX
function dx(){
    1 AND \ini_set('display_errors', 0);
    1 AND \ini_set('display_startup_errors', 1);
    1 AND \ini_set('error_reporting', E_ALL);
    0 AND \error_reporting(E_ALL);
    $fault__fn = function($ex = null){
        if($ex instanceof \_\fault\exception){
            echo (string) $ex;
        } else {
            $intfc = $_SERVER['.']['intfc']
                ?? (\_\IS_CLI 
                ? 'cli'
                : $_SERVER['HTTP_X_REQUEST_INTERFACE'] ?? 'web'
                )
            ;
            switch($intfc){
                case 'cli':{
                    echo "\033[91m\n"
                        .$ex::class.": {$ex->getMessage()}\n"
                        ."File: {$ex->getFile()}\n"
                        ."Line: {$ex->getLine()}\n"
                        ."\033[31m{$ex}\033[0m\n"
                    ;
                    exit(1);
                } break;
                case 'web':{
                    \http_response_code(500);
                    while(\ob_get_level() > \_\OB_OUT){ @\ob_end_clean(); }
                    \defined('_\SIG_ABORT') OR \define('_\SIG_ABORT', -1);
                    if (preg_match('#^application/json\b#i', $_SERVER['CONTENT_TYPE'] ?? '')) {
                        // It's JSON
                        \header('Content-Type: application/json');
                        echo \json_encode([
                            'status' => "error",
                            'message' => $ex->getMessage(),
                        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES); 
                    } else {
                        echo <<<HTML
                            <style>
                                body{ background-color: #121212; color: #e0e0e0; font-family: sans-serif; margin: 0; padding: 20px;}
                                pre{ overflow:auto; color:red;border:1px solid red;padding:5px; background-color: #1e1e1e; max-height: calc(100vh-25px); }
                                /* Scrollbar styles for WebKit (Chrome, Edge, Safari) */
                                ::-webkit-scrollbar { width: 12px; height: 12px;}
                                ::-webkit-scrollbar-track { background: #1e1e1e; }
                                ::-webkit-scrollbar-thumb { background-color: #555; border-radius: 6px; border: 2px solid #1e1e1e; }
                                ::-webkit-scrollbar-thumb:hover { background-color: #777; }
                                /* Firefox scrollbar (limited support) */
                                * { scrollbar-width: thin; scrollbar-color: #555 #1e1e1e;}
                            </style>
                            <pre>{$ex}</pre>
                            HTML;
                    }
                    exit(1);
                } break;
                default:{
                    \http_response_code(500);
                    while(\ob_get_level() > \_\OB_OUT){ @\ob_end_clean(); }
                    \defined('_\SIG_ABORT') OR \define('_\SIG_ABORT', -1);
                    \header('Content-Type: application/json');
                    echo \json_encode([
                        'status' => "error",
                        'message' => $ex->getMessage(),
                    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES); 
                    exit(1);
                } break;
            }
    }
    };
    \set_exception_handler(function($ex) use($fault__fn){
        $fault__fn($ex);
    });
    \set_error_handler(function($severity, $message, $file, $line) use($fault__fn){
        if(($x = $_SERVER['FW__ON_ERROR'] ?? 'throw') == 'throw'){
            throw new \ErrorException(
                $message, 
                0,
                $severity, 
                $file, 
                $line
            );
        } else if($x == 'fault'){
            try{
                throw new \ErrorException(
                    $message, 
                    0,
                    $severity, 
                    $file, 
                    $line
                );
            } catch(\Throwable $ex) {
                $fault__fn($ex);
            }
        }
    });
    \register_shutdown_function(function() use($fault__fn){ 
        try {
            if(\defined('_\SIG_END')){
                throw new \Exception("Invalid SIG_END setting or Duplicate call to Root Finalizer");
            } else {
                \define('_\SIG_END', \microtime(true));
            
            };
            
            if($error = \error_get_last()){ 
                \error_clear_last();
                try {
                    throw new \ErrorException(
                        $error['message'], 
                        0,
                        $error["type"], 
                        $error["file"], 
                        $error["line"]
                    );
                } catch(\Throwable $ex) {
                    $fault__fn($ex);
                }
            }
            
            $exit = null;
            // response is used only if loaded
            if (\is_null($response = $GLOBALS['--RESPONSE'] ?? null)) {
                $exit = null;
            } else if($response instanceof \SplFileInfo){
                $exit = (object)[];
                if(\is_file($file = $response)){
                    $mime_type = match($ext = \strtolower(\pathinfo($file, PATHINFO_EXTENSION))){
                        'html' => null,
                        'css'  => 'text/css',
                        'js'   => 'application/javascript',
                        'json' => 'application/json',
                        'jpg'  => 'image/jpeg',
                        'png'  => 'image/png',
                        'gif'  => 'image/gif',
                        'html' => 'text/html',
                        'txt'  => 'text/plain',
                        default => \mime_content_type((string) $file) ?: 'application/octet-stream',
                    };
                    if(empty($mime_type)) {
                        $exit->code = 404;
                        $exit->content = '404: Not Found: Unknown Mime Type';
                    } else {
                        // Set appropriate headers
                        $exit->headers[] = 'Content-Type: ' . $mime_type;
                        $exit->headers[] = 'Cache-Control: public, max-age=86400'; // Cache for 1 day
                        $exit->headers[] = 'Expires: ' . \gmdate('D, d M Y H:i:s', \time() + 86400) . ' GMT'; // 1 day in the future
                        $exit->headers[] = 'Last-Modified: ' . \gmdate('D, d M Y H:i:s', \filemtime($file)) . ' GMT';
                        // Check for If-Modified-Since header
                        if (isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) &&
                            \strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) >= \filemtime($file)) {
                            $exit->code = 304; // Not Modified
                            $exit->content = null;
                        } else {
                            // Output the file content
                            $exit->content = new \SplFileInfo((string) $file);
                        }
                    }
                } else {
                    $exit->code = 404;
                    $exit->content = '404: Not Found';
                }
            } else if(\is_scalar($response)){
                $exit = (object)[
                    'content' => $response,
                ];
            } else if($response instanceof \Throwable) {
                ($fault__fn)($response, "Fault [E0.4]");
            } else if(\is_array($response)) {
                $exit = (object)[
                    'headers' => [
                        'Content-Type: application/json'
                    ],
                    'content' => $response,
                ];
            } else if(\is_object($response)) {
                $exit = $response;
            } else {
                $exit = null;
            }
            
        } catch (\Throwable $ex) {
            ($fault__fn)($response, "Fault [E0.5]");
        }
        
        \define('_\SIG_EXIT', \microtime(true));
        
        if($exit){
            try {
                if(\_\IS_CLI){
                    if(\is_null($content = $exit->content ?? null)){ 
                        return; 
                    } else if($content instanceof \SplFileInfo){
                        echo $content;
                    } else if(\is_scalar($content)) {
                        echo $content;
                    } else {
                        echo \json_encode($content ?? [], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    }
                    if(\is_numeric($code = $exit->code ?? null) &&  $code >= 400){
                        \defined('_\SIG_ABORT') OR \define('_\SIG_ABORT', 1);
                    }
                } else {
                    while(\ob_get_level() > \_\OB_OUT){ @\ob_end_clean(); }
                    if(\is_numeric($code = $exit->code ?? null)){
                        \http_response_code($code ?: 200);
                    } 
                    if(\is_array($exit->headers ?? null)){
                        foreach($exit->headers ?? [] as $k => $v){
                            if(\is_string($v)){
                                if(\is_numeric($k)){
                                    \header($v);    
                                } else {
                                    \header("{$k}: {$v}");
                                }
                            }
                        }
                    }
                    if(\is_null($content = $exit->content ?? null)){ 
                        return; 
                    } else if($content instanceof \SplFileInfo){
                        \readfile($content);
                    } else if(\is_scalar($content)) {
                        echo $content;
                    } else {
                        \header('Content-Type: application/json');
                        echo \json_encode($content ?? [],JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    }
                    if(\is_numeric($code) && $code >= 400){
                        \defined('_\SIG_ABORT') OR \define('_\SIG_ABORT', 1);
                    }
                }
            } catch (\Throwable $ex) {
                ($this->fn->report_fault)($ex);
            }
        }
    });        
}
function abort__ffn(int $code, string $message){
    return function() use($code, $message){
        while(\ob_get_level() > \_\OB_OUT){ @\ob_end_clean(); }
        \defined('_\SIG_ABORT') OR \define('_\SIG_ABORT', 1);
        \http_response_code($code);
        echo $message;
        exit();
    };
}
#endregion
# ######################################################################################################################
#region WEB / REDIRECTOR
function redirect__ffn($goto){
    return function() use($goto){
        $GLOBALS['--RESPONSE'] = (object)[
            //* note: by default the redirect is 302 i.e. temporary
            'type' => 'redirect',
            'headers' => ["Location: ". $goto],
        ];            
    };
}
#endregion
# ######################################################################################################################
#region SESSION
function session(){
    if(!\_\IS_CLI){
        if(\session_status() == PHP_SESSION_NONE) {
            //* if the primary starter did the session it would have managed the auth
            //* this part will be scipped
            \session_name(\_\KEY); 
            \session_start();
        }
        isset($_SESSION['--CSRF']) OR $_SESSION['--CSRF'] = \md5(uniqid('csrf-'));
        \define('_\CSRF', $_SESSION['--CSRF']);
        $this->_['flash_in'] = $_SESSION['--FLASH'] ?? [];
        $_SESSION['--FLASH'] = [];
        if($_ENV['CSRF_PROTECT'] ?? true){
            $token = $_REQUEST['--csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
            if(
                \in_array($_SERVER['REQUEST_METHOD'], ['POST','PUT','PATCH','DELETE'])
                && ($token) != ($_SESSION['--CSRF'] ?? null)
            ){
                while(\ob_get_level() > \_\OB_OUT){ @\ob_end_clean(); }
                \http_response_code(406);
                exit('406: Not Acceptable');
            }
        }
    }
}
#endregion
# ######################################################################################################################
#region AUTH
function auth(){
    global $_;
    
    if(($_ENV['AUTH']['EN'] ?? true)){
        if(($_SESSION['--AUTH']['en'] ?? false) !== true){
            if(!($_SESSION['--AUTH']['login_in_progress'] ?? false)){
                $_SESSION['--AUTH'] = [];
                $_SESSION['--AUTH']['login_in_progress'] = 1;
                \header("Location: ". \strtok($_SERVER['REQUEST_URI'],'?'));
                exit();
            }
        }
        if(
            isset($_GET['--logout'])
            || isset($_GET['--signout'])
        ){
            $_SESSION['--AUTH'] = [];
            \header("Location: ". \strtok($_SERVER['REQUEST_URI'],'?'));
            exit();
        }
    }    
    
    if($_SESSION['--AUTH']['login_in_progress'] ?? null){
        if($this->_['is_action']){
            if($this->_['action'] == 'login'){
                global $_;
                if($username = $_POST['username'] ?? false){
                    $password = $_POST['password'] ?? '';
                    if($user = \function_exists(\_\d::class) ? \_\d('users')[$username] : null){
                        $user = $user;
                    } else {
                        $user = ($_ENV['USERS'] ?? [
                            'admin' => [
                                'password' => '`pass'
                            ]
                        ])[$username] ?? [];
                    }
                    if($user){
                        $pass = (($p = ($user['password'] ?? null) ?: "`")[0] == "`") 
                            ? \md5(\substr($p, 1))
                            : $p
                        ;
                        $streq__fn = function ($a, $b) {
                            //credits: https://blog.ircmaxell.com/2014/11/its-all-about-time.html
                            $ret = false;
                            if (($aL = \strlen($a)) == ($bL = \strlen($b))) {
                                $r = 0;
                                for ($i = 0; $i < $aL; $i++) {
                                    $r |= (\ord($a[$i]) ^ \ord($b[$i]));
                                }
                                $ret = ($r === 0);
                            }
                            return $ret;
                        };
                        if((empty($pass) && !$password) || ($streq__fn)($pass, \md5($password ?? ''))){
                            $_SESSION['--AUTH'] = [
                                'en' => true,
                                'username' => $username,
                                'name' => $user['name'] ?? $username ?? 'No Name',
                                'roles' => $user['roles'] ?? [],
                                'panels' => $user['panels'] ?? [],
                            ];
                            $_SESSION['--FLASH']['toasts'][] = 'You have Logged in Successfully';
                        } else {
                            $_SESSION['--FLASH']['toasts'][] =  'Invalid login credentials';
                        }
                    } else {
                        $_SESSION['--FLASH']['toasts'][] = 'Invalid login credentials';    
                    }
                } else {
                    $_SESSION['--FLASH']['toasts'][] = 'Invalid login credentials';
                } 
            } else {
                $_SESSION['--FLASH']['toasts'][] = 'Invalid login action';
            }
            return $this->redirect__ffn(\strtok($_SERVER['REQUEST_URI'],'?'));
        } else {
            return function(){ $this->canvas_01__v(function(){
                \http_response_code(403);
                $title = $_SERVER['HTTP_HOST']." | Login";
                $csrf = \_\CSRF;
                $site_url = $this->_['site_url'];
                $toasts = \json_encode($this->_['flash_in']['toasts'] ?? []);
                ?>
                <div class="container min-vh-100 d-flex align-items-center justify-content-center">
                        <div class="mx-auto" style="max-width: 500px;">
                            <div class="text-center mb-3">
                                <h1 class="h4 mb-1">User Login</h1>
                                <p class="font-monospace mb-0"><?=$site_url?></p>
                            </div>

                            <form id="form-auth" class="x-validate x-show-page-spinner" method="POST" novalidate>
                                <input type="hidden" name="--action" value="login">
                                <input type="hidden" name="--auth" value="login">
                                <input type="hidden" name="--csrf" value="<?=$csrf?>">

                                <div class="mb-3">
                                    <label for="id-username" class="form-label">Username</label>
                                    <input
                                        type="text"
                                        class="form-control"
                                        id="id-username"
                                        name="username"
                                        required
                                    >
                                    <div class="invalid-feedback">
                                        Please enter your username.
                                    </div>
                                </div>

                                <div class="mb-3">
                                    <label for="id-password" class="form-label">Password</label>
                                    <input
                                        type="password"
                                        class="form-control"
                                        id="id-password"
                                        name="password"
                                        autocomplete="new-password"
                                        required
                                    >
                                    <div class="invalid-feedback">
                                        Please enter your password.
                                    </div>
                                </div>

                                <div class="text-end">
                                    <button type="submit" id="btn-login" class="btn btn-outline-primary">
                                        <span id="btn-login-spinner" class="spinner-border spinner-border-sm me-2 d-none" role="status" aria-hidden="true"></span>
                                        <span id="btn-login-text">Login</span>
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>                
                <?php 
            }); };
        }
    } else if($dispatch = (function(){
        if(!($auth = $_SESSION['--AUTH']['en'] ?? false)){
            $panels = $_SESSION['--AUTH']['panels'] ?? [];
            $panel = \trim($this->_['panel'],'-');
                
            if(\in_array('*', $panels)){
                return;
            }
            
            if(!\in_array($panel, $panels)){
                return $this->abort__ffn(403, '403: Not Allowed');
            }            
            if(\in_array('*', $roles)){
                return;
            }
            
            if(\in_array($role, $roles)){
                if(
                    \is_file(\_\DATA['dir']."/0/".($j = "_/xui/auth/roles/{$role}-$.php"))
                    || ($f = \_::f($j))
                ){
                    foreach((include $f)['permits'] ?? [] as $k => $v){
                        if(\fnmatch($k, $uri)){
                            if($v){
                                return;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
            
            if($this->_['is_supply']){
                return $this->abort__ffn(403, '403: Not Allowed');
            } else {
                return $this->abort__ffn(403, '403: Not Allowed');
            }            
        }
    })()){
        return $dispatch;
    } else if($auth_options = ($_GET['--auth'] ?? null)){
        if($view_f = ($this->fn->resolve_file)("_/xui/auth/{$auth_options}/-v.php")){
            return function() use($view_f){
                include $view_f;
            };
        } else {
            return $this->abort__ffn(503, "503: Not Available: '{$auth_options}'' interface is not supported");
        }
    }
}
#endregion
# ######################################################################################################################
#region CANVAS_01
function canvas_01__v($__INSET__){ 
?><!DOCTYPE html>
<html lang="en" data-bs-theme="light">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title><?=$this->vars['ui/page/tab/title'] ?? 'Untitled'?></title>

    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

    <link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />
    <script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.full.min.js"></script>
    
    <script>
        const X_CSRF = <?=json_encode($_SESSION['--CSRF']); ?>;
        if (typeof window.xui === 'undefined') {
            window.xui = {
                url: {
                    root: '<?=$_SERVER['root_url'] ?? ''?>',
                    site: '<?=$_SERVER['site_url'] ?? ''?>',
                    base: '<?=$_SERVER['base_url'] ?? ''?>',
                    ctlr: '<?=$_SERVER['ctlr_url'] ?? ''?>',
                },
                ds: { 
                  //datasources  
                },
                i: [],
                init(f = null) {
                    if (f) {
                        this.i.push(f);
                    }
                    return this;
                },
                _init_() {
                    this.i.forEach(function(f) {
                        f();
                    });
                },
                extend(a1, a2 = null) {
                    if (typeof a1 === 'string') {
                        if (typeof this[a1] === 'undefined') {
                            this[a1] = {};
                        }
                        if (a2) {
                            Object.assign(this[a1], a2);
                        }
                    } else if (a1 instanceof Object) {
                        Object.assign(this, a1);
                    }
                    return this;
                },
                event: {
                    _list: [],
                    add(name, delegate) {
                        if (this._list[name]) {
                            this._list[name].push(delegate);
                        } else {
                            this._list[name] = [delegate];
                        }
                    },
                    trigger(name, data) {
                        this._list[name]?.forEach(delegate => {
                            delegate(data);
                        });
                    }
                },
            };
        }
        
        if (typeof xui.TRACE === 'undefined') {
            xui.TRACE = 6;
            xui.TRACE_1 = ((xui.TRACE ?? 0) >= 1);
            xui.TRACE_2 = ((xui.TRACE ?? 0) >= 2);
            xui.TRACE_3 = ((xui.TRACE ?? 0) >= 3);
            xui.TRACE_4 = ((xui.TRACE ?? 0) >= 4);
            xui.TRACE_5 = ((xui.TRACE ?? 0) >= 5);
            xui.TRACE_6 = ((xui.TRACE ?? 0) >= 6);
            xui.TRACE_7 = ((xui.TRACE ?? 0) >= 7);
            xui.TRACE_8 = ((xui.TRACE ?? 0) >= 8);
            xui.TRACE_9 = ((xui.TRACE ?? 0) >= 9);
            (xui.TRACE_1) && console.log({
                xui
            });
        }
        
        window.onload = (event) => {
            xui._init_();
        };
                    
    </script>    

    <style>
        /* RESET & HEIGHT CONTROL -------------------------------- */
        html,
        body {
            height: 100%;
        }
        
        body {
            display: flex;
            flex-direction: column;
        }

        .xui-page-content {
            flex: 1 1 auto;
            min-height: 0;
        }

        /* allow internal overflow without body scroll */
        #xui-shell {
            min-height: 0;
        }

        /* Header styling */
        .xui-page-header {
            border-bottom: 1px solid rgba(0, 0, 0, .1);
            background: #fff;
        }
        
    </style>

    <style>
        .select2-container .select2-selection--single {
            height: 38px;
        }

        .select2-container--default .select2-selection--single .select2-selection__rendered {
            line-height: 36px;
        }

        .select2-container--default .select2-selection--single .select2-selection__arrow {
            height: 36px;
        }


        /* ==== Select2 fix when inside .input-group ==== */
        .input-group>.select2-container {
            flex: 1 1 auto !important;
            width: 1% !important;
            min-width: 0;
        }

        /* Ensure height + alignment match Bootstrap input size */
        .input-group-sm>.select2-container .select2-selection--single {
            height: calc(1.65rem + 2px) !important;
            line-height: 1.5rem !important;
            padding: 0 .375rem;
            border-color: var(--bs-border-color);
            border-radius: 0 .25rem .25rem 0;
        }

        /* Match border radius for left/right sides when adjacent to text addons */
        .input-group>.select2-container:first-child .select2-selection--single {
            border-top-right-radius: 0;
            border-bottom-right-radius: 0;
        }

        .input-group>.select2-container:last-child .select2-selection--single {
            border-top-left-radius: 0;
            border-bottom-left-radius: 0;
        }

        /* Keep select2 dropdown below other elements correctly */
        .select2-container {
            z-index: 1055;
            /* above .dropdown-menu (1000) */
        }

        /* Apply dark mode styles when Bootstrap is in dark theme */
        [data-bs-theme="dark"] .select2-container .select2-selection {
            background-color: var(--bs-body-bg) !important;
            color: var(--bs-body-color) !important;
            border-color: var(--bs-border-color) !important;
        }

        [data-bs-theme="dark"] .select2-container .select2-selection__rendered {
            color: var(--bs-body-color) !important;
        }

        [data-bs-theme="dark"] .select2-container .select2-selection__arrow b {
            border-color: var(--bs-body-color) transparent transparent transparent !important;
        }

        /* Dropdown menu */
        [data-bs-theme="dark"] .select2-dropdown {
            background-color: var(--bs-body-bg) !important;
            color: var(--bs-body-color) !important;
            border-color: var(--bs-border-color) !important;
        }

        [data-bs-theme="dark"] .select2-results__option--highlighted {
            background-color: var(--bs-primary-bg-subtle) !important;
            color: var(--bs-primary-text) !important;
        }

        [data-bs-theme="dark"] .select2-container--default .select2-results__option--selected {
            background-color: var(--bs-primary-bg) !important;
            color: var(--bs-primary-text-emphasis, var(--bs-body-color)) !important;
        }
    </style>
    
    
    <script>
        const XUI_CTLR_STORE = (() => {
            const baseKey = (location.origin + location.pathname).toLowerCase();
            return new Proxy({}, {
                get(_, prop) {
                    if (typeof prop === "string") {
                        // For convenience, allow dotted or camelCase keys: activeTab, sidebarWidth, etc.
                        return `${baseKey}::xui.${prop}`;
                    }
                    return undefined;
                }
            });
        })();
        const XUI_SITE_STORE = (() => {
            const baseKey = (window.xui.url.site).toLowerCase();
            return new Proxy({}, {
                get(_, prop) {
                    if (typeof prop === "string") {
                        // For convenience, allow dotted or camelCase keys: activeTab, sidebarWidth, etc.
                        return `${baseKey}::xui.${prop}`;
                    }
                    return undefined;
                }
            });
        })();        
    </script>    
    
</head>

<body>
    
    <?php ($__INSET__)($this) ?>
    
    <!-- ################################################################################################### -->
    <!-- Dark mode toggle -->
    <style>
        .theme-toggle-btn {
            position: fixed;
            bottom: 1rem;
            right: 1rem;
            z-index: 2100;
        }
        
        .theme-toggle-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 .5rem 1rem rgba(0, 0, 0, .35);
        }        
    </style>
    
    <button type="button" id="theme-toggle" class="btn btn-primary btn-sm rounded-circle theme-toggle-btn" aria-label="Toggle dark mode">
        <i class="bi bi-moon-stars" id="themeToggleIcon"></i>
    </button>
    
    <script>
        // Theme init (Bootstrap 5.3 data-bs-theme)
        (function () {
            const storedTheme = sessionStorage.getItem(XUI_SITE_STORE.xui_dark_mode);
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const theme = storedTheme || (prefersDark ? 'dark' : 'light');
            document.documentElement.setAttribute('data-bs-theme', theme);
        })();        
        $('#theme-toggle').on('click', function () {
            var current = document.documentElement.getAttribute('data-bs-theme') || 'light';
            var next = current === 'light' ? 'dark' : 'light';
            // swap icon
            const icon = document.getElementById('themeToggleIcon');
            if (next === 'dark') {
                icon.classList.remove('bi-moon-stars');
                icon.classList.add('bi-sun');
            } else {
                icon.classList.remove('bi-sun');
                icon.classList.add('bi-moon-stars');
            }
            document.documentElement.setAttribute('data-bs-theme', next);
            sessionStorage.setItem(XUI_SITE_STORE.xui_dark_mode, next);
        });        
    </script>

    <!-- ################################################################################################### -->
    <!-- Toast -->
    <style>
        #toast-container { position: fixed; top: 20px; right: 20px; z-index: 1000; display: none; }
        .toast { display: flex; align-items: center; background-color: #333; color: #fff; padding: 12px 20px; margin-bottom: 10px; }
        .toast { border-radius: 5px; opacity: 0; transition: opacity 0.5s ease, transform 0.5s ease; transform: translateY(-20px); }
        .toast.show { opacity: 1; transform: translateY(0); }
        .toast.hide { opacity: 0; transform: translateY(-20px); }                            
    </style>
    <div id="toast-container"></div>
    <script>
        <?php $toasts = \json_encode($this->_['flash_in']['toasts'] ?? []); ?>
        $(() => {
            var toasts = <?=$toasts?>;
            if (toasts) {
                // Make the toast container visible
                const toastContainer = document.getElementById('toast-container');
                toastContainer.style.display = 'block';

                toasts.forEach((message) => {
                    if (message) {
                        // Create a new toast element
                        const toast = document.createElement('div');
                        toast.classList.add('toast');
                        toast.textContent = message;

                        // Append to the toast container
                        toastContainer.appendChild(toast);

                        // Show the toast with animation
                        setTimeout(() => toast.classList.add('show'), 100);

                        // Hide the toast and container after 3 seconds
                        setTimeout(() => {
                            toast.classList.add('hide');
                            toast.addEventListener('transitionend', () => {
                                toast.remove();
                                if (toastContainer.children.length === 0) {
                                    toastContainer.style.display = 'none';
                                }
                            });
                        }, 3000);
                    }
                });
            }
        });
    </script>
    
    <!-- ################################################################################################### -->
    <!-- Page Spinner -->
    <style>
        /* Spinner */
        .xui-page-spinner-overlay {
            position: absolute;
            inset: 0;
            display: none;
            align-items: center;
            justify-content: center;
            background: rgba(255, 255, 255, .8);
            z-index: 2
        }

        .xui-page-spinner-border {
            width: 2.75rem;
            height: 2.75rem
        }
    </style>
    <div class="xui-page-spinner-overlay spinner-overlay" id="xui-page-spinner">
        <div class="xui-page-spinner-border spinner-border" role="status" aria-label="Loading…"></div>
    </div>
    <script>
        window.xui__page_spinner = {
            show(){
                $('#xui-page-spinner')[0].style.display = 'flex';
            },
            hide(){ 
                $('#xui-page-spinner')[0].style.display = 'none';
            },
        };
    </script>
    
    <!-- ################################################################################################### -->
    <!-- Generic Prompt Modal -->
    <div class="modal fade" id="xuiPromptModal" tabindex="-1" aria-hidden="true" aria-labelledby="xuiPromptTitle">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="xuiPromptTitle">Prompt</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body" id="xuiPromptMessage">
                    <!-- message gets injected here -->
                </div>
                <div class="modal-footer" id="xuiPromptButtons">
                    <!-- buttons get injected here -->
                </div>
            </div>
        </div>
    </div>    
    <script>
        window.xui = window.xui || {};
        window.xui.modal = window.xui.modal || {};
        (function () {
            const modalEl   = document.getElementById('xuiPromptModal');
            const titleEl   = document.getElementById('xuiPromptTitle');
            const msgEl     = document.getElementById('xuiPromptMessage');
            const buttonsEl = document.getElementById('xuiPromptButtons');

            const bsPromptModal = new bootstrap.Modal(modalEl, {
            backdrop: 'static', // click-outside doesn't auto-confirm
            keyboard: true
            });

            let currentCallback = null;
            let hasClickedButton = false;

            function finish(choice) {
            if (!currentCallback) return;
            const cb = currentCallback;
            currentCallback = null;
            cb(choice);
            }

            // When modal fully hides (Esc / close button / backdrop)
            modalEl.addEventListener('hidden.bs.modal', function () {
            if (!hasClickedButton) {
                // closed without choosing a button
                finish(null);
            }
            hasClickedButton = false;
            });

            window.xui.modal.prompt = function (message, title, buttons, callback) {
            titleEl.textContent = title || 'Confirm';
            msgEl.textContent   = message || '';

            // Default buttons if none supplied
            const btnLabels = (Array.isArray(buttons) && buttons.length) ? buttons : ['OK'];

            // Clear previous buttons
            buttonsEl.innerHTML = '';
            currentCallback = (typeof callback === 'function') ? callback : null;

            btnLabels.forEach((label, idx) => {
                const btn = document.createElement('button');
                btn.type = 'button';
                // First button primary, others outline-secondary by default
                btn.className = 'btn ' + (idx === 0 ? 'btn-danger' : 'btn-outline-secondary');
                btn.textContent = label;

                btn.addEventListener('click', function () {
                hasClickedButton = true;
                bsPromptModal.hide();
                finish(label); // pass the label to the callback, e.g. "Yes" / "No"
                }, { once: true });

                buttonsEl.appendChild(btn);
            });

            bsPromptModal.show();
            };
        })();
    </script>    
    
    <script>
        $(function () {
            
            var FIELD = '--csrf';
            var token = $('meta[name="csrf-token"]').attr('content') || (window.__CSRF_TOKEN__ || '<?=$_SESSION['--CSRF'] ?? ''?>');
            $('form').each(function () {
                var $f = $(this), $h = $f.find('input[type="hidden"][name="' + FIELD + '"]');
                if ($h.length) $h.val(token);
                else $('<input>', { type: 'hidden', name: FIELD, value: token }).prependTo($f);
            });
            
            $('form').on('submit', function (e) {
                if($(this).hasClass('.x-validate')){
                    if (!this.checkValidity()) {
                        e.preventDefault();
                        e.stopPropagation();
                        $(this).addClass('was-validated');
                        return;
                    }
                    $(this).addClass('was-validated');
                } 
                
                if($(this).hasClass('x-show-page-spinner')){
                    window.xui__page_spinner.show();
                }
            });            
        });
    </script>
    <?php if(\is_callable($fn = $this->vars['xui/html/tail'] ?? null)){$fn();}elseif(\is_array($fn)){foreach($fn as $fnv){if(\is_callable($fnv)){$fnv();}}} ?>
</body>
</html><?php 
}
public function main_window__v(){ $this->canvas_01__v(function(){ 
?>
    <!-- CONTENT (fills remaining viewport; only main scrolls) -->
    <main class="xui-page-content d-flex flex-column">
        <div class="d-flex flex-fill" id="xui-shell">
            <!-- ################################################################################################### -->
            <!-- Floating collapse tab -->
            <style>
                /* COLLAPSE TAB (90° rotated trapezoid) */
                .xui-sidebar-toggle {
                    position: fixed;
                    left: 0;
                    top: 50%;
                    transform: translateY(-50%);
                    width: 15px;
                    height: 40px;
                    padding: 0;
                    border: none;
                    outline: none;
                    cursor: pointer;
                    background: rgba(180, 180, 180, 0.25);
                    backdrop-filter: blur(4px);
                    box-shadow: 0 2px 6px rgba(0, 0, 0, .15);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    clip-path: polygon(0 0, 100% 15%, 100% 85%, 0 100%);
                    color: rgba(0, 0, 0, 0.55);
                    transition: background .2s ease, color .2s ease;
                    z-index: 1040;
                }

                .xui-sidebar-toggle:hover {
                    background: rgba(108, 117, 125, .92);
                    color: #fff;
                }

                .xui-sidebar-toggle .bi {
                    display: inline-block;
                }

                /* Collapsed state */
                .xui-collapsed .xui-page-sidebar,
                .xui-collapsed .xui-drag-handle {
                    display: none !important;
                }

                .xui-collapsed .xui-page-main {
                    width: 100% !important;
                }
            </style>
            <button class="xui-sidebar-toggle btn btn-sm text-white border-0" id="xuiCollapseBtn" type="button" title="Toggle sidebar">
                <i class="bi bi-chevron-left" id="xuiCollapseIcon"></i>
            </button>
            <script>
                $(() => {
                    (function xui__sidebar_toggle() {
                        const btn = document.getElementById("xuiCollapseBtn");
                        const icon = document.getElementById("xuiCollapseIcon");
                        const root = document.body;

                        const restore = sessionStorage.getItem(XUI_SITE_STORE.xui__sidebar_toggle) === "1";
                        if (restore) root.classList.add("xui-collapsed");
                        icon.className = root.classList.contains("xui-collapsed") ? "bi bi-chevron-right" : "bi bi-chevron-left";

                        btn.addEventListener("click", () => {
                            root.classList.toggle("xui-collapsed");
                            const collapsed = root.classList.contains("xui-collapsed");
                            icon.className = collapsed ? "bi bi-chevron-right" : "bi bi-chevron-left";
                            sessionStorage.setItem(XUI_SITE_STORE.xui__sidebar_toggle, collapsed ? "1" : "0");
                        });
                    })();
                })
            </script>
            
            
            <!-- ################################################################################################### -->
            <!-- Sidebar -->
            <style>
                :root {
                    --xui-sidebar-w: 260px; /* default */
                }        
                
                /* ONLY main scrolls */
                .xui-page-sidebar {
                    min-width: 160px;
                    width: var(--xui-sidebar-w, 260px);
                    max-width: 60vw;
                    overflow: hidden;
                    /* background: #f8f9fa; */
                    border-right: 1px solid rgba(0, 0, 0, .1);
                }

                /* Sidebar inner scroll (thin left scrollbar) */
                /* LEFT scrollbar without layout shifts */
                .xui-sidebar-scroll {
                    height: 100%;
                    overflow-y: auto;

                    /* keep layout stable even when the scrollbar shows/hides */
                    scrollbar-gutter: stable;

                    /* reserve exact scrollbar width we detect via JS below */
                    padding-inline-start: var(--xui-sbw, 0px);

                    /* your existing cosmetics (optional) */
                    padding: .1rem;
                    scrollbar-width: thin;
                    /* Firefox */
                    /* scrollbar-color: #bbb transparent; */
                }

                /* Force sidebar scroll to appear on the left side */
                .xui-sidebar-scroll {
                    direction: rtl;
                    /* scrollbar on the left */
                    text-align: left;
                    /* restore left-aligned content */
                }

                .xui-sidebar-scroll>* {
                    /* restore normal content direction */
                    direction: ltr;
                }

                .xui-sidebar-scroll::-webkit-scrollbar {
                    width: 6px;
                }

                .xui-sidebar-scroll::-webkit-scrollbar-thumb {
                    /* background-color: #bbb; */
                    border-radius: 3px;
                }

                .xui-page-sidebar .search {
                    padding: .5rem .2rem;
                    /* border-bottom: 1px solid #4e5b63ff */
                }

                .xui-page-sidebar .packages {
                    overflow: auto;
                    /* padding: .75rem; */
                    gap: .75rem;
                    display: flex;
                    flex-direction: column
                }

                .xui-sidenav-item-card {
                    /* border: 1px solid #e3e6ea; */
                    /* background: #fff; */
                    border-radius: .75rem;
                    padding: .5rem .75rem;
                    cursor: pointer;
                    transition: border-color .15s, box-shadow .15s, background .15s
                }

                .xui-sidenav-item-card:hover {
                    border-color: #cfd4da;
                    box-shadow: 0 1px 8px rgba(0, 0, 0, .05)
                }

                .xui-sidenav-item-card.active {
                    border-color: #0d6efd;
                    box-shadow: 0 0 0 .15rem rgba(13, 110, 253, .15)
                }
                

                [data-bs-theme="dark"] .xui-sidenav-item-card.active {
                    background-color: var(--bs-primary-bg) !important;
                    color: var(--bs-primary-text) !important;
                }
                
                .xui-sidenav-title {
                    font-weight: 600;
                    font-size: .95rem;
                    margin: 0;
                    /* word-break: break-all; */
                    overflow: hidden;
                    white-space: nowrap;
                    text-overflow: ellipsis;
                }

                .xui-sidenav-desc {
                    color: #6c757d;
                    font-size: .84rem;
                    margin: .25rem 0 0;
                    overflow: hidden;
                    white-space: nowrap;
                    text-overflow: ellipsis
                }
                
                /* Drag handle */
                .xui-drag-handle {
                    width: 6px;
                    cursor: col-resize;
                    background: transparent;
                    border-right: 1px solid rgba(0, 0, 0, .1);
                }

                .xui-drag-handle:hover {
                    background: rgba(0, 0, 0, .05);
                }

                .xui-drag-shield {
                    position: fixed;
                    inset: 0;
                    cursor: col-resize;
                    z-index: 1040;
                    display: none;
                }
            </style>
            <!-- Resizer Prefill (!!!! MUST COME BEFORE SIDEBAR !!!!)-->
            <script>
                (function () {
                    try {
                        const w = sessionStorage.getItem(XUI_SITE_STORE.xui__sidebar_resizer);
                        if (w) {
                            document.documentElement.style.setProperty('--xui-sidebar-w', w + "px");
                        }
                    } catch (e) {
                        // localStorage might be blocked; just ignore
                    }
                })();
            </script>
            <!-- RESIZE LOGIC -->
            <script>
                $(() => {
                    (function xui__sidebar_resizer() {
                        const handle = document.getElementById("xuiDragHandle");
                        const shield = document.getElementById("xuiDragShield");
                        const sidebar = document.querySelector(".xui-page-sidebar");
                        if (!handle || !shield || !sidebar) return;

                        const savedW = sessionStorage.getItem(XUI_SITE_STORE.xui__sidebar_resizer);
                        if (savedW) document.documentElement.style.setProperty("--xui-sidebar-w", savedW + "px");

                        let startX = 0, startW = 0, dragging = false;

                        const startDrag = (ev) => {
                            dragging = true;
                            startX = (ev.touches ? ev.touches[0].clientX : ev.clientX);
                            startW = sidebar.getBoundingClientRect().width;
                            shield.style.display = "block";
                            document.body.classList.add("user-select-none");
                        };
                        const onDrag = (ev) => {
                            if (!dragging) return;
                            const clientX = (ev.touches ? ev.touches[0].clientX : ev.clientX);
                            let newW = startW + (clientX - startX);
                            newW = Math.max(160, Math.min(newW, window.innerWidth * 0.6));
                            document.documentElement.style.setProperty("--xui-sidebar-w", newW + "px");
                        };
                        const endDrag = () => {
                            if (!dragging) return;
                            dragging = false;
                            shield.style.display = "none";
                            document.body.classList.remove("user-select-none");
                            const finalW = sidebar.getBoundingClientRect().width | 0;
                            sessionStorage.setItem(XUI_SITE_STORE.xui__sidebar_resizer, String(finalW));
                        };

                        handle.addEventListener("mousedown", startDrag);
                        handle.addEventListener("touchstart", startDrag, { passive: true });
                        window.addEventListener("mousemove", onDrag);
                        window.addEventListener("touchmove", onDrag, { passive: false });
                        window.addEventListener("mouseup", endDrag);
                        window.addEventListener("touchend", endDrag);
                        window.addEventListener("touchcancel", endDrag);
                    })();
                })
            </script>
            <aside class="xui-page-sidebar d-flex flex-column">
                <?php if(\is_callable($fn = $this->vars['xui/sidebar_header/content'] ?? null)): ?>
                <div class="p-2 border-bottom d-flex align-items-center justify-content-between">
                    <?php $fn() ?>
                </div>
                <?php endif ?>
                <div class="search border-bottom">
                    <input id="filter" type="search" class="form-control form-control-sm" placeholder="Filter packages… (Ctrl+/)">
                </div>
                <div class="xui-sidebar-scroll flex-fill packages" id="xui-sidenav-list">
                    <?php if(\is_callable($fn = $this->vars['xui/sidebar_nav/content'] ?? null)): ?>
                    <?php $fn() ?>
                    <?php endif ?>
                </div>
                <div class="flex-shrink p-2 d-flex">
                    <a class="btn btn-outline-primary w-100" href="?--logout">Logout</a>
                </div>
            </aside>
            <div class="xui-drag-handle" id="xuiDragHandle" title="Drag to resize"></div>
            <div class="xui-drag-shield" id="xuiDragShield"></div>
            <script>
                $(() => {
                    $('#filter').on('input', () => {
                        const term = $('#filter').val().toLowerCase();
                        $('.xui-sidenav-item-card').each((i, c) => {
                            c.style.display = c.textContent.toLowerCase().includes(term) ? '' : 'none';
                        });
                    });
                    $(document).on('keydown', function (e) {
                        if (e.ctrlKey && e.key === '/') {
                            e.preventDefault();
                            $('#filter').focus().select();
                        }
                    });
                })    
            </script>



            <!-- ################################################################################################### -->
            <!-- Main (only this scrolls) -->
            <style>
                /* important for Firefox/Chrome to let children overflow */
                .xui-page-main {
                    overflow: auto;
                    min-width: 0;
                }

                /* Tab bodies */
                .xui-page-tabbody {
                    display: none;
                }

                .xui-page-tabbody.active {
                    display: block;
                }

            </style>
            <main id="main" class="xui-page-main d-flex flex-fill">
                <?php if(\is_callable($fn = $this->vars['xui/main/content'] ?? null)): ?>
                <?php $fn() ?>
                <?php endif ?>
            </main>
            <script>
                
            </script>
        </div>
    </main>
<?php 
}); }

#endregion
# ######################################################################################################################
#region HELPERS
function clear(){
    while(\ob_get_level() > \_\OB_OUT){ 
        @\ob_end_clean(); 
    }
    \ob_start();
}

function sanitize_variant_name(string $name): string { return preg_replace('/[^A-Za-z0-9._-]/', '', $name); }

function is_valid_pkg_dir(string $path): bool { return is_dir($path) && is_readable($path); }

function is_dot_prefixed(string $name): bool { return isset($name[0]) && $name[0] === '.'; }

function json_response(bool $ok, array $data = [], int $code = 200): void {
    $this->clear();
    \http_response_code($code);
    \header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => $ok] + $data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}    

function pkg_info(){
    if(is_file($f = "{$this->PKG_DIR}/.info.txt")){
        try {
            $handle = fopen($f, 'r');
            if ($handle) {
                $line = fgets($handle);  // reads one line (up to newline or EOF)
                return \trim($line);
            }
        } finally {
            empty($handle) OR fclose($handle);
        }
    }
}

function pkg_state($state = null){
    $file = "{$this->PKG_DIR}/.state.json";
    if(\func_num_args()){
        $state['updated_at'] = date(DATE_ATOM);
        \is_dir($d = \dirname($file)) OR \mkdir($d, 0777, true);
        \file_put_contents($file, \json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    } else if(\is_file($file)){
        return \json_decode(\file_get_contents($file), true);
    } else {
        $state = [
            'pkg_name'  => $this->PKG_NAME,
            'repo'     => $this->GH_REPO_URL ?? trim((string)($_REQUEST['repo'] ?? '')),
            'updated_at' => date(DATE_ATOM),
        ];
        $this->fs_ensure_parent($file);
        \file_put_contents($file, \json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        return \json_decode(\file_get_contents($file), true);
    }
}

function fs_ensure_dir($d){
    \is_dir($d)
        ? true
        : \mkdir($d, 0777, true)
    ;
}

function fs_ensure_parent($path){
    \is_dir($d = \dirname($path))
        ? true
        : \mkdir($d, 0777, true)
    ;
}

function fs_delete($d){
    if(\is_dir($d)){
        foreach(new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($d, \RecursiveDirectoryIterator::SKIP_DOTS)
            , \RecursiveIteratorIterator::CHILD_FIRST
        ) as $f) {
            if ($f->isDir()){
                \rmdir($f->getRealPath());
            } else {
                unlink($f->getRealPath());
            }
        }
        \rmdir($d);
    }
}

function fs_rename($from, $to){
    if(!\file_exists($from)){
        throw new \Exception("Rename: the FROM path does not exist: '{$from}'");
    }
    if(\file_exists($to)){
        throw new \Exception("Rename: the TO path already exist: '{$to}'");
    }
    $this->fs_ensure_parent($to);
    return \rename($from, $to);
}

function fs_dir_is_empty($dir) {
    if (!is_readable($dir)) return null; // or false
    return count(scandir($dir)) === 2;  // only "." and ".."
}

function fs_iterator($d){
    return new \RecursiveIteratorIterator(
        new \RecursiveDirectoryIterator(
            $d, 
            \FilesystemIterator::SKIP_DOTS
        )
    );
}

function fs_create_link(string $target_abs, string $link)
{
    // Normalize paths
    if(!($target = realpath(rtrim($target_abs, DIRECTORY_SEPARATOR)))){
        throw new Exception("Target path doesn't exist: $target_abs");
    }
    $link = rtrim($link, DIRECTORY_SEPARATOR);
    // Remove existing link if it exists
    if (file_exists($link) || is_link($link)) {
        if (is_dir($link) && !is_link($link)) {
            throw new Exception("Link path exists as a real directory: $link");
        }
        unlink($link);
    }
    $this->fs_ensure_parent($link);

    // WINDOWS → create a junction
    if (strncasecmp(PHP_OS_FAMILY, 'Windows', 7) === 0) {

        // mklink requires cmd.exe syntax
        $cmd = sprintf(
            'mklink /J "%s" "%s"',
            $link,
            $target
        );

        // run silently
        exec($cmd, $out, $result);

        if ($result !== 0) {
            throw new Exception("Failed to create junction. Command: $cmd");
        }

    } else {
        // LINUX / MAC → normal symlink
        if (!symlink($target, $link)) {
            throw new Exception("Failed to create symlink from $link to $target");
        }
    }

    return true;
}

function gh__parse_segments(string $url): array {
    if (preg_match('~github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?(?:/|$)~i', $url, $m)){
        return [$m[1], $m[2]];
    } else {
        return ['', ''];
    }
}

function gh__api_url($subpath, $query = []){
    $x = "https://api.github.com/repos/{$this->GH_OWNER}/{$this->GH_REPO}"
        .(($subpath)
            ? (($subpath[0] == '.' || $subpath[0] == '/')
                ? $subpath
                : "/{$subpath}"
            )
            : ""
        ).(($query)
            ? "?".http_build_query($query)
            : ""
        )
    ;
    return $x;
}

function curl__set_token($token){
    $this->CURL_HEADERS['Accept'] = 'Accept: application/vnd.github+json';
    if(!empty($token)){
        $this->CURL_HEADERS['Authorization'] = 'Authorization: Bearer ' . $token;
    } else {
        unset($this->CURL_HEADERS['Authorization']);
    }
}

function curl__json_response(bool $ok, array $data = null, int $code = 200){
    $data ??= [];
    if($this->CURL_RESP_HEADERS ?? null){
        $data['dx']["x-ratelimit-limit"] = $this->CURL_RESP_HEADERS["x-ratelimit-limit"] ?? '';
        $data['dx']["x-ratelimit-used"] = $this->CURL_RESP_HEADERS["x-ratelimit-used"] ?? '';
        $data['dx']["x-ratelimit-remaining"] = $this->CURL_RESP_HEADERS["x-ratelimit-remaining"] ?? '';
        $data['dx']["x-ratelimit-reset"] = $this->CURL_RESP_HEADERS["x-ratelimit-reset"] ?? '';
    }
    return $this->json_response($ok, $data, $code);
}

function curl__set_timeout($timeout){
    $this->CURL_TIMEOUT = $timeout;
    return $this;
}

function curl_head($url, $token = null) {
    try {
        $this->CURL_HEADERS ??= [];
        $token && $this->curl__set_token($token);
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'PHP Installer');
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        if($headers = \array_values($this->CURL_HEADERS)){
            \curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }
        
        curl_exec($ch);

        if (curl_errno($ch)) {
            return [false, 0];
        }

        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return [($status === 200), $status];

    } catch (\Throwable $e) {
        return [false, 0];
    }
}

function curl($url, $file = null){
    try{
        $this->CURL_CONNECTTIMEOUT ??= 20;
        $this->CURL_TIMEOUT ??= 20;
        $this->CURL_VERBOSE = ($_REQUEST['--verbose'] ?? null) ? true : false;
        $this->CURL_HEADERS ??= [];

        if($this->CURL_VERBOSE){
            echo "Remote: {$url}\n";
        }

        if(!($ch = \curl_init($url))){
            throw new \Exception("Failed: Unable to initialze curl");
        }

        // ---------------------------------------------
        // Capture response headers into a buffer
        // ---------------------------------------------
        $respHeaders = [];
        \curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($ch, $header) use (&$respHeaders) {
            $len = strlen($header);
            $header = trim($header);
            if ($header !== '') {
                $respHeaders[] = $header;
            }
            return $len;
        });
        \curl_setopt($ch, CURLINFO_HEADER_OUT, true);
        // ---------------------------------------------

        \curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        \curl_setopt($ch, CURLOPT_USERAGENT, 'PHP Installer');
        \curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->CURL_CONNECTTIMEOUT);
        \curl_setopt($ch, CURLOPT_TIMEOUT, $this->CURL_TIMEOUT);
        \curl_setopt($ch, CURLOPT_VERBOSE, $this->CURL_VERBOSE);
        \curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        \curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        if($headers = \array_values($this->CURL_HEADERS)){
            \curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        // ========================= FILE MODE =========================
        if($file){
            if(!($fp = \fopen($file, 'w'))){
                throw new \Exception("Failed: Unable to open tempfile for writing");
            }
            \curl_setopt($ch, CURLOPT_RETURNTRANSFER, false);
            \curl_setopt($ch, CURLOPT_FILE, $fp);

            \curl_exec($ch);

            if (\curl_errno($ch)) {
                throw new \Exception("Failed: cURL Error: " .\curl_error($ch));
            }

            $code = \curl_getinfo($ch, CURLINFO_HTTP_CODE);

            if($code != 200){
                \is_file($file) AND unlink($file);

                // Include headers in error message
                $hdr = implode("\n", $respHeaders);
                throw new \Exception("Failed: Server responded with {$code}\n\nHeaders:\n{$hdr}");
            }

            return [\is_file($file), $file, ''];
        }

        // ====================== NON-FILE MODE ========================
        \curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = \curl_exec($ch);

        $this->CURL_RESP_HEADERS = array_reduce($respHeaders, function($carry, $line) {
            if (\strpos($line, ':') !== false) {
                [$k, $v] = array_map('trim', explode(':', $line, 2));
                $carry[$k] = $v;
            }
            return $carry;
        }, []);;
        
        if (\curl_errno($ch)) {
            throw new \Exception("Failed: cURL Error: " .\curl_error($ch));
        }

        $code = \curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if($code != 200){
            $hdr = implode("\n", $respHeaders);
            throw new \Exception(
                \str_replace("\n","\n ", "Failed: Server responded with {$code}\n\nHeaders:\n{$hdr}\n\nBody:\n{$response}")
            );
        }

        $result = \json_decode($response, true);

        if (\json_last_error() === JSON_ERROR_NONE) {
            if (\is_array($result)) {
                return [true, $result, ''];
            } else {
                return [false, null, 'Invalid JSON'];
            }
        } else {
            throw new \Exception(
                "Json Error Code:(".\json_last_error()."): ".\json_last_error_msg()
            );
        }

    } catch (\Throwable $ex) {
        if($file && \is_file($file)){
            \unlink($file);
        }
        throw $ex;

    } finally {
        empty($fp) OR \fclose($fp);
        empty($ch) OR \curl_close($ch);
    }
}

function fs_put_indexphp($s_dir, $content){
    \is_dir($s_dir) OR \mkdir($s_dir, 0777, true);
    \file_put_contents("{$s_dir}/index.php",$content);    
}

function fs_put_htaccess($s_dir){
    \is_dir($s_dir) OR \mkdir($s_dir, 0777, true);
    \file_put_contents("{$s_dir}/.htaccess", <<<HTACCESS
    <IfModule mod_rewrite.c>
    RewriteEngine On
    #-------------------------------------------------------------------------------
    #* note: for auto https
    # RewriteCond %{HTTPS} off 
    # RewriteCond %{SERVER_PORT} 80
    # RewriteRule (.*) https://%{SERVER_NAME}%{REQUEST_URI} [L]
    #-------------------------------------------------------------------------------
    #* note: if you need www
    # RewriteCond %{HTTP_HOST} !^www\. [NC]
    # RewriteRule ^(.*)$ https://www.%{HTTP_HOST}/$1 [R=301,L]
    #-------------------------------------------------------------------------------
    #* note: for basic http authorization
    RewriteCond %{HTTP:Authorization} ^(.+)$
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
    #-------------------------------------------------------------------------------
    #* note: for content type 
    # RewriteRule .* - [E=HTTP_CONTENT_TYPE:%{HTTP:Content-Type},L]
    #-------------------------------------------------------------------------------
    #* note: for pax legacy routing
    RewriteCond %{REQUEST_URI} !(favicon.ico)|(/.*\-pub[\.\/].*)|(/.*\-asset[\.\/].*)
    RewriteRule . index.php [L,QSA]
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule . index.php [L,QSA]
    </IfModule>
    HTACCESS);
}

function pkg__access_type(){
    return $this->I__PKG_ACCESS_TYPE ??  $this->I__PKG_ACCESS_TYPE = (\is_file("{$this->PKG_DIR}/index.php")
        ? (\is_file("{$this->PKG_DIR}/.htaccess")
            ? 'direct-access'
            : 'relay-access'
        )
        : 'no-access'
    );
}

function task__install_access(){
    $start_file = $this->PLIB_DIR.'/applet/launch.php';
    $app_file = $this->PKG_DIR.'/lib/app/.app-$$.php';
    $inst_dir = $this->PKG_DIR;
    $indexphp__content = <<<PHP
    <?php 
    \$_SERVER['_']['PLEX_DIR'] ??= '{$this->PLEX_DIR}';
    \$_SERVER['_']['APP_FILE'] ??= '{$app_file}';
    include '{$start_file}';
    PHP;
    switch($_REQUEST['access_type'] ?? ''){
        case 'no-access' : {
            \is_file($f = "{$this->PKG_DIR}/.htaccess") AND unlink($f);
            \is_file($f = "{$this->PKG_DIR}/index.php") AND unlink($f);
        } break;
        case 'relay-access':{
            \is_file($f = "{$this->PKG_DIR}/.htaccess") AND unlink($f);
            $this->fs_put_indexphp($this->PKG_DIR,$indexphp__content);
        } break;
        case 'direct-access':{
            $this->fs_put_htaccess($this->PKG_DIR);
            $this->fs_put_indexphp($this->PKG_DIR,$indexphp__content);
        } break;
    }
    $this->json_response(true, ['note' => "Done"]);
}

function task__install_start($s_dir, $start_file){
    $this->fs_put_htaccess($s_dir);
    $this->fs_put_indexphp($s_dir,<<<PHP
    <?php 
    \$_SERVER['_']['PLEX_DIR'] ??= '{$this->PLEX_DIR}';
    \is_callable(\$x = (include "{$start_file}")) AND \$x();
    PHP);
}

function task__install_app($s_dir, $app_file){
    $start_file = $this->PLIB_DIR.'/applet/launch.php';
    $this->fs_put_htaccess($s_dir);
    $this->fs_put_indexphp($s_dir,<<<PHP
    <?php 
    \$_SERVER['_']['PLEX_DIR'] ??= '{$this->PLEX_DIR}';
    \$_SERVER['_']['APP_FILE'] ??= '{$app_file}';
    include '{$start_file}';
    PHP);
}

function get_pkg_list(){
    return $this->PKG_LIST ?? $this->PKG_LIST = \iterator_to_array((function(){
        foreach(\glob("{$this->PLEX_DIR}/*", GLOB_ONLYDIR) as $d){
            $d = \str_replace('\\','/', $d);
            $pkey = \basename($d);
            if(\preg_match('#^pkg~([\w\-\.]+)~([\w\-\.]+)(?:~(.+))?$#', $pkey, $m)){
                $owner = $m[1];
                $repo = $m[2];
                $variant = $m[3] ?? null;
                
                $desc = "{$owner}/{$repo}";
                if(is_file($f = "{$d}/lib/.info.txt")){
                    try {
                        $handle = fopen($f, 'r');
                        if ($handle) {
                            $line = fgets($handle);  // reads one line (up to newline or EOF)
                            $desc = \trim($line);
                        }
                    } finally {
                        empty($handle) OR fclose($handle);
                    }
                }
                if(
                    \is_file("{$d}/index.php")
                    && \is_file("{$d}/.htaccess")
                ){
                    $go_url = "{$this->_['base_url']}/{$pkey}";
                } else {
                    $go_url = false;
                }
                if(
                    \is_file("{$d}/lib/index.php")
                    && \is_file("{$d}/lib/.htaccess")
                ){
                    $lib_tools_url = "{$this->_['base_url']}/{$pkey}/lib";
                } else {
                    $lib_tools_url = false;
                }
                yield $pkey => [
                    'owner' => $owner,
                    'repo' => $repo,
                    'path' => $path = "{$owner}/{$repo}".($variant ? "/{$variant}" : ''),
                    'name' => $variant ? "{$repo} ({$variant})" : "{$repo}",
                    'disp' => $variant ? "{$repo} ({$variant})" : "{$repo}",
                    'desc' => $desc,
                    'dir' => $d,
                    'lib_dir' => "{$d}/lib",
                    'gh_url' => ($owner != 'synth') ? "https://github.com/{$owner}/{$repo}" : null,
                    'pkg_manage_url' => "{$this->_['base_url']}/package/{$path}",
                    'lib_tools_url' => $lib_tools_url,
                    'go_url' => $go_url,
                ];
            }
        }
    })());
}

#endregion
# ######################################################################################################################
#region INDEX
function index__c(){
    $this->GH_TOKEN = trim((string)($_REQUEST['token'] ?? null ?: $_ENV[\_\api::class]['github.com']['token'] ?? ''));
    $this->PKG_VARIANT = null;
    $this->GH_REPO = null;
    $this->GH_OWNER = null;    
    $rurp = $this->_['rurp'];
    if($rurp == '/'){
        $this->vars['xui/main/content'] = function(){ ?>
            <div class="container d-flex flex-column justify-content-center align-items-center text-center min-vh-100">
                <div>
                    <h1 class="fw-semibold text-secondary mb-2">No Package Selected</h1>
                    <p class="text-muted fs-6">
                    Select a package from the sidebar or add a new one using the <strong>New</strong> button.
                    </p>
                </div>
            </div>
        <?php };
    } else if($rurp == '/manage_access'){
        $access_file = $this->PLEX_DIR.'/.local-access_list-$.json';
        $this->ACCESS_LIST = \is_file($access_file) ? \json_decode(\file_get_contents($access_file), true) : [];
        if($this->_['is_action']){
            if(($action = $this->_['action']) === 'save'){
                $r_dir = \dirname("{$this->_['site_dir']}");
                $r_url = \dirname("{$this->_['site_url']}");
                $data = [];
                $pathlist = [];
                foreach($_REQUEST['ff']['linelist'] ?? [] as $k => $v){
                    if(($v['state'] ?? null) === '-1'){
                        if($path = $this->ACCESS_LIST['linelist'][$k]['path'] ?? null){
                            $path = '/'.\trim($path,'/');
                            $path = ($path == '/') ? '' : $path;
                            if(\is_file($file = "{$r_dir}{$path}/.htaccess")){
                                unlink($file);
                            }
                            if(\is_file($file = "{$r_dir}{$path}/index.php")){
                                unlink($file);
                            }
                            if($this->fs_dir_is_empty($d = "{$r_dir}{$path}")){
                                rmdir($d);
                            }
                        }
                    } else if(
                        ($path = ($v['path'] ?? ''))
                        && !\str_starts_with($path,\basename($this->PLEX_DIR))
                        && empty($pathlist[$path]) 
                        && ($start_at = $v['start_at'] ?? "") 
                    ){
                        $pathlist[$path] = true;
                        $path = '/'.\trim($path,'/');
                        $path = ($path == '/') ? '' : $path;
                        $data['linelist'][$k] = $v;
                        $data['linelist'][$k]['url'] = $s_url = "{$r_url}{$path}";
                        $data['linelist'][$k]['dir'] = $s_dir = "{$r_dir}{$path}";
                        if(
                            \str_starts_with($bn = \basename($start_at),'.app')
                            && \str_ends_with($bn,'-$$.php')
                        ){
                            $data['linelist'][$k]['app_file'] = $app_file = $start_at;
                            $data['linelist'][$k]['inst_dir'] = $inst_dir = \dirname($start_at,3);
                            $this->task__install_app($s_dir, $app_file);
                        } else {
                            $start_file = \str_replace('\\','/', $start_at);
                            $data['linelist'][$k]['start_file'] = $start_file;
                            $this->task__install_start($s_dir, $start_file);
                        }
                    }
                }
                \file_put_contents($access_file, \json_encode($data, JSON_PRETTY_PRINT  | JSON_UNESCAPED_SLASHES));
            }
            \header("Location: {$_SERVER['REQUEST_URI']}");
            exit();
        }
        
        $this->vars['xui/main/content'] ??= function(){ ?>
            <div class="container-fluid mt-5">
                <!-- Editable List Card -->
                <form id="lineListForm" method="post">
                    <input hidden name="--action" value="save">
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                        <h6 class="mb-0">Access List</h6>
                        <button type="submit" class="btn btn-sm btn-primary">
                            Save
                        </button>
                        </div>

                        <div class="card-body">
                        <div id="lineListContainer">
                            <!-- Rows will be injected here -->
                        </div>

                        <div class="d-flex justify-content-end mt-3">
                            <button type="button" class="btn btn-outline-primary btn-sm" id="btnAddLine">
                            + Add
                            </button>
                        </div>
                        </div>
                    </div>
                </form>
            </div>
            <script>
                window.xui.ds.access_list = <?=\json_encode((function(){ 
                    return $this->ACCESS_LIST['linelist'] ?? [];
                })())?> 
                
                $(function () {
                    const container = document.getElementById('lineListContainer');
                    const btnAdd = document.getElementById('btnAddLine');

                    // Generate a reasonably unique key (timestamp + random)
                    function makeKey() {
                        const ts = Date.now().toString(36);
                        const rnd = Math.random().toString(36).slice(2, 6);
                        return ts + rnd;
                    }

                    function createRow(kkey = null, value = {path:'',lib:''}) {
                        const key = kkey ?? makeKey();
                        const path = value.path;
                        const start_at = value.start_at ?? '';
                        const url = value.url ?? 'javascript:void()';

                        const row = document.createElement('div');
                        row.className = 'input-group mb-2';
                        row.dataset.key = key;

                        row.innerHTML = `
                            <a class="btn btn-outline-secondary btn-sm" type="button" data-role="go" href="${url}">Go</a>
                            <a class="btn btn-outline-secondary btn-sm" type="button" data-role="go" href="${url}/--@">@</a>
                            <input 
                            type="text" 
                            class="form-control form-control-sm" 
                            name="ff[linelist][${key}][path]" 
                            value="${path.replace(/"/g, '&quot;')}"
                            placeholder="Enter value"
                            ${path ? 'readonly' : ''}
                            >
                            <select 
                            class="form-select form-select-sm xui-select2" 
                            name="ff[linelist][${key}][start_at]" 
                            value="${start_at.replace(/"/g, '&quot;')}"
                            >
                            </select>
                            <button class="btn btn-outline-danger btn-sm" type="button" data-role="remove">
                            &times;
                            </button>
                        `;

                        // Attach events
                        const btnGo = row.querySelector('[data-role="go"]');
                        const btnRemove = row.querySelector('[data-role="remove"]');

                        // btnGo.addEventListener('click', function () {
                        //     const input = row.querySelector('input');
                        //     // TODO: implement your "Go" logic here:
                        //     // e.g., window.location.href = input.value;
                        //     console.log('Go clicked with value:', input.value);
                        // });

                        btnRemove.addEventListener('click', function () {
                            $(row).closest('form').append(`<input hidden name="ff[linelist][${key}][state]" value="-1">`);
                            row.remove();
                        });

                        container.appendChild(row);
                        // Initializing the Select2 dropdown
                        var select$ = $(row).find('.xui-select2');
                        select$.select2({
                            data: window.xui.ds.start_options || [],
                            // width: '140px'
                        });
                        select$.val(select$.attr('value')).trigger('change');
                    }

                    // Add button
                    btnAdd.addEventListener('click', function () {
                        createRow();
                    });

                    var list = window.xui.ds.access_list;
                    Object.keys(list).forEach(key => {
                        console.log({key, value: list[key]});
                        createRow(key, list[key]);
                    });
                    
                    
                    // Start with one empty row
                    //createRow();

                    // Optional: prevent default submit for now
                    // document.getElementById('lineListForm').addEventListener('submit', function (e) {
                    //   e.preventDefault();
                    //   const data = new FormData(this);
                    //   // handle save...
                    //   console.log('saving...', Array.from(data.entries()));
                    // });
                });
            </script>
        <?php };
        
        $this->vars['xui/html/tail'][] = function(){ ?>
            <script>
                window.xui.ds.start_options = <?=\json_encode((function(){ 
                    $starts = [];
                    foreach($this->PKG_LIST as $k => $v){
                        $vr = $v['path'];
                        $dl = "{$v['dir']}/lib";
                        foreach(\glob("{$dl}/{*/,}{.start}{-*,}.php", GLOB_BRACE) as $f){
                            //Todo: simplify using preg_match
                            $m = (($dx = \dirname($f)) == $dl) ? '[L]' : \basename($dx);
                            $starts[$f] = 'START | '.((($n = \basename($f)) == '.start.php')
                                ? $m.' | '.$vr
                                : $m.' ('.\substr($n,7,-4).') | '.$vr
                            );
                        }
                        foreach(\glob("{$dl}/*/{.app}{-*,}-$$.php", GLOB_BRACE) as $f){
                            //Todo: simplify using preg_match
                            $m = (($dx = \dirname($f)) == $dl) ? '[L]' : \basename($dx);
                            $starts[$f] = 'APP | '.((($n = \basename($f)) == '.app-$$.php')
                                ? $m.' | '.$vr
                                : $m.' ('.\substr($n,5,-7).') | '.$vr
                            );
                        }
                    }
                    $list = [
                        ['id' => '', 'text'=>'--Select Start--']
                    ];
                    foreach ($starts as $k => $v){
                        $list[] = ['id' => $k, 'text'=>$v];
                    }
                    return $list;
                })())?>
            </script>
        <?php };
        
        
    } else if($rurp == '/new_library'){
        if($this->_['is_action']){
            if(($action = $this->_['action']) === 'new'){
                [$this->GH_OWNER, $this->GH_REPO] = $this->gh__parse_segments($_REQUEST['url']);
                if(!$this->GH_OWNER || !$this->GH_REPO){
                    $_SESSION['--FLASH']['toasts'][] =  'Invalid URL';
                } else if(
                    ([$ok, $status] = $this->curl_head("https://github.com/{$this->GH_OWNER}/{$this->GH_REPO}", $this->GH_TOKEN))
                    && (!$ok || $status !== 200)
                ){
                    $_SESSION['--FLASH']['toasts'][] =  "Invalid Repository, GitHub Response - {$status}";
                } else if(\is_dir($d = "{$this->PLEX_DIR}/pkg~{$this->GH_OWNER}~{$this->GH_REPO}")){
                    $_SESSION['--FLASH']['toasts'][] =  "Library already exists";
                } else if(!\mkdir($d, 0777,true)){
                    $_SESSION['--FLASH']['toasts'][] =  "Unable to create directory - System Error";
                } else {
                    \header("Location: {$this->_['site_url']}/package/{$this->GH_OWNER}/{$this->GH_REPO}");
                    exit();
                }
            }
            \header("Location: {$_SERVER['REQUEST_URI']}");
            exit();
        }
        $this->vars['xui/main/content'] ??= function(){ ?>
            <div class="container d-flex flex-column justify-content-center align-items-center text-center min-vh-100">
                <div style="max-width: 420px; width: 100%;">
                    <h1 class="fw-semibold text-secondary mb-3">Add a Library</h1>
                    <p class="text-muted fs-6 mb-4">
                    Enter a public GitHub repository URL below to get started.
                    </p>
                    <form method="POST" class="w-100">
                        <input type="hidden" name="--csrf" value="<?= htmlspecialchars(\_\CSRF) ?>">
                        <input type="hidden" name="--action" value="new">
                        <div class="input-group input-group-lg">
                            <input 
                            type="url" 
                            name="url"
                            class="form-control" 
                            placeholder="https://example.com/" 
                            aria-label="Package URL"
                            required
                            >
                            <button class="btn btn-primary" type="submit">Add</button>
                        </div>
                    </form>
                </div>
            </div>
        <?php };
    } else if($rurp == '/new_variant'){
        if($this->_['is_action']){
            if(($action = $this->_['action']) === 'new'){
                [$this->GH_OWNER, $this->GH_REPO] = $this->gh__parse_segments($_REQUEST['url']);
                if(!$this->GH_OWNER || !$this->GH_REPO){
                    $_SESSION['--FLASH']['toasts'][] =  'Invalid URL';
                } else if(
                    ([$ok, $status] = $this->curl_head("https://github.com/{$this->GH_OWNER}/{$this->GH_REPO}", $this->GH_TOKEN))
                    && (!$ok || $status !== 200)
                ){
                    $_SESSION['--FLASH']['toasts'][] =  "Invalid Repository, GitHub Response - {$status}";
                } else if(!($this->PKG_VARIANT = $this->sanitize_variant_name($_REQUEST['variant_name']))){
                    $_SESSION['--FLASH']['toasts'][] =  'Invalid Variant Name';
                } else if(\is_dir($d = "{$this->PLEX_DIR}/pkg~{$this->GH_OWNER}~{$this->GH_REPO}~{$this->PKG_VARIANT}")){
                    $_SESSION['--FLASH']['toasts'][] =  "Variant already exists";
                } else if(!\mkdir($d, 0777,true)){
                    $_SESSION['--FLASH']['toasts'][] =  "Unable to create directory - System Error";
                } else {
                    \header("Location: {$this->_['site_url']}/package/{$this->GH_OWNER}/{$this->GH_REPO}/{$this->PKG_VARIANT}");
                    exit();
                }
            }
            \header("Location: {$_SERVER['REQUEST_URI']}");
            exit();
        }
        $this->vars['xui/main/content'] ??= function(){ ?>
            <div class="container-fluid d-flex flex-column justify-content-center align-items-center text-center min-vh-100">
                <div style="max-width: 500px; width: 100%;">
                    <h1 class="fw-semibold text-secondary mb-3">Add a New Variant</h1>
                    <p class="text-muted fs-6 mb-4">
                    Enter a name for your variant
                    </p>
                    <form method="POST" class="w-100">
                        <input type="hidden" name="--csrf" value="<?= htmlspecialchars(\_\CSRF) ?>">
                        <input type="hidden" name="--action" value="new">
                        <div class="input-group input-group-lg">
                            <input 
                            type="url" 
                            name="url"
                            class="form-control" 
                            placeholder="https://example.com/" 
                            aria-label="Package URL"
                            required
                            >
                            <input 
                            type="text" 
                            name="variant_name"
                            class="form-control" 
                            placeholder="variant" 
                            aria-label="Variant Name"
                            required
                            >
                            <button class="btn btn-primary" type="submit">Add</button>
                        </div>
                    </form>
                </div>
            </div>
        <?php };
    } else if($rurp == '/new_synth'){
        if($this->_['is_action']){
            if(($action = $this->_['action']) === 'new'){
                if(!\is_dir($path = $_REQUEST['path'])){
                    $_SESSION['--FLASH']['toasts'][] =  "Invalid Directory - {$path}";
                } else if(!$_REQUEST['synth_name']){
                    $_SESSION['--FLASH']['toasts'][] =  "Name not specified";
                } else if(\is_dir($synth_dir = ("{$this->PLEX_DIR}/".($synth_name = "pkg~synth~{$_REQUEST['synth_name']}")."/lib"))){
                    $_SESSION['--FLASH']['toasts'][] =  "Library synth by that name already exists";
                } else if(!$this->fs_create_link($path, $synth_dir)){
                    $_SESSION['--FLASH']['toasts'][] =  "System error couldn't create the link";
                } else {
                    $j = \str_replace('~','/',\substr($synth_name,4));
                    \header("Location: {$this->_['site_url']}/package/{$j}");
                    exit();
                }
            }
            \header("Location: {$_SERVER['REQUEST_URI']}");
            exit();
        }
        $this->vars['xui/main/content'] ??= function(){ ?>
            <div class="container-fluid d-flex flex-column justify-content-center align-items-center text-center min-vh-100">
                <div style="max-width: 90vh; width: 100%;">
                    <h1 class="fw-semibold text-secondary mb-3">Add a New Synth</h1>
                    <p class="text-muted fs-6 mb-4">
                    Enter the absolute path of the target Library
                    </p>
                    <form method="POST" class="w-100">
                        <input type="hidden" name="--csrf" value="<?= htmlspecialchars(\_\CSRF) ?>">
                        <input type="hidden" name="--action" value="new">
                        <div class="input-group input-group-lg">

                            <!-- LEFT DROPDOWN -->
                            <div class="input-group-text p-0">
                                <div class="dropdown">
                                    <button class="btn btn-outline-secondary dropdown-toggle h-100 border-0 rounded-0" 
                                            type="button" 
                                            data-bs-toggle="dropdown" 
                                            aria-expanded="false">
                                        Paths
                                    </button>
                                    <ul class="dropdown-menu">
                                        <?php foreach ($this->get_pkg_list() ?? [] as $k => $v): if(\is_dir($v['lib_dir'])): ?>
                                            <li>
                                                <a class="dropdown-item xui-path-option" 
                                                href="#"
                                                data-value="<?= htmlspecialchars($v['lib_dir']) ?>">
                                                <?= htmlspecialchars($v['path']) ?>
                                                </a>
                                            </li>
                                        <?php endif; endforeach; ?>
                                    </ul>
                                </div>
                            </div>

                            <!-- EXISTING INPUTS -->
                            <input 
                                type="text"
                                name="path"
                                id="pathInput"
                                class="form-control"
                                placeholder="/abs/path/to/pkg/lib_dir"
                                aria-label="Library Path"
                                required
                            >
                            <input 
                                type="text"
                                name="synth_name"
                                class="form-control"
                                placeholder="name"
                                aria-label="Synth Name"
                                required
                            >
                            <button class="btn btn-primary" type="submit">Add</button>
                        </div>

                    </form>
                </div>
            </div>
            <script>
                document.addEventListener("DOMContentLoaded", function () {
                    document.querySelectorAll(".xui-path-option").forEach(item => {
                        item.addEventListener("click", function (e) {
                            e.preventDefault();
                            const val = this.dataset.value;
                            document.getElementById("pathInput").value = val;
                        });
                    });
                });
            </script>
        <?php };
    } else if(\str_starts_with($rurp, '/package')){
        \strtok($rurp,'/');
        $rurp = \strtok('');
        if(
            ([$this->GH_OWNER, $this->GH_REPO, $this->PKG_VARIANT] = [\strtok($rurp,'/'), \strtok('/'), \strtok('/')])
            && !\is_dir($this->PKG_DIR = "{$this->PLEX_DIR}/pkg~{$this->GH_OWNER}~{$this->GH_REPO}".($this->PKG_VARIANT ? "~{$this->PKG_VARIANT}" : ''))
        ){
            $this->vars['xui/main/content'] ??= function(){ ?>
                <div class="container d-flex flex-column justify-content-center align-items-center text-center min-vh-100">
                    <div>
                        <h1 class="fw-semibold  mb-2"><i class="bi bi-exclamation-triangle-fill text-danger fs-2 mb-3"></i> Package Not Found</h1>
                        <p class="text-muted fs-6">
                        The package you’re trying to access doesn’t exist or may have been removed.<br>
                        Please select a valid package from the sidebar or create a new one.
                        </p>
                    </div>
                </div>
            <?php };
        } else if($this->GH_OWNER == 'synth') {
            if($action = $this->_['action']){
                if($action === 'delete') {
                    $this->PKG_STUB = "{$this->GH_OWNER}~{$this->GH_REPO}".($this->PKG_VARIANT ? "~{$this->PKG_VARIANT}" : '');
                    $this->PKG_NAME = $this->PKG_STUB;
                    $pkg_dir = $this->PKG_DIR;
                    $pkg_name = $this->PKG_NAME;
                    $backup_dir = $this->PLEX_DIR."/.local/".($backup_name = "pkg~{$pkg_name}-[deleted-".\date('Y-md-Hi-s')."][".uniqid()."]");
                    if(\is_dir($d = $pkg_dir) && !$this->fs_rename($d, $backup_dir)){
                        throw new \Exception("Failed: Unable to modify the '{$pkg_name}' directory - it might be in use!!!");
                    }
                    $this->json_response(true, ['note' => "Backedup at '{$backup_dir}'"]);
                }
                
                if ($action === 'change_access'){
                    $this->task__install_access();
                }
                
                \header("Location: {$_SERVER['REQUEST_URI']}");
                exit();
            }
            
            $this->vars['xui/main/content'] ??= function(){ ?>
                <div class="container d-flex flex-column justify-content-center align-items-center text-center min-vh-100">
                    <div>
                        <h1 class="fw-semibold  mb-2"><i class="bi bi-exclamation-triangle-fill text-danger fs-2 mb-3"></i> Synth</h1>
                        <p class="text-muted fs-6">
                        The package you’re trying to access is a synth and must be managed manually.<br>
                        If  you need to remove the synth you can do so by clicking the 'Remove' button.
                        </p>
                    </div>
                    <div class="row">
                        <?php if(\is_file($this->PKG_DIR.'/lib/app/.app-$$.php')): ?>
                        <div class="col">
                            <select class="form-control" id="selectPackageAccess">
                                <option value="<?=$x='no-access'?>" <?=$this->pkg__access_type() == $x ? 'selected' : ''?>>None</option>
                                <option value="<?=$x='relay-access'?>" <?=$this->pkg__access_type() == $x ? 'selected' : ''?>>Relay</option>
                                <option value="<?=$x='direct-access'?>" <?=$this->pkg__access_type() == $x ? 'selected' : ''?>>Direct</option>
                            </select>
                        </div>
                        <?php endif ?>
                        <div class="col">
                            <button type="button" class="btn btn-outline-danger" id="btnDeletePackage">
                                Remove
                            </button>
                        </div>
                    </div>
                </div>
            <?php };
        } else if(
            ([$ok, $status] = $this->curl_head($this->GH_URL = "https://github.com/{$this->GH_OWNER}/{$this->GH_REPO}", $this->GH_TOKEN))
            && (!$ok || $status !== 200)
        ){
            $this->vars['xui/main/content'] ??= function(){ ?>
                <div class="container d-flex flex-column justify-content-center align-items-center text-center min-vh-100">
                <div>
                    <h1 class="fw-semibold  mb-2"><i class="bi bi-exclamation-triangle-fill text-danger fs-2 mb-3"></i> Github Error</h1>
                    <p class="text-muted fs-6">
                    The package you’re trying to access doesn’t exist on github or may have been removed.<br>
                    Please select a valid package from the sidebar or create a new one.
                    </p>
                </div>
                </div>
            <?php };
        } else {
            $this->GH_REPO_URL = "https://github.com/{$this->GH_OWNER}/{$this->GH_REPO}.git";
            $this->PKG_STUB = "{$this->GH_OWNER}~{$this->GH_REPO}".($this->PKG_VARIANT ? "~{$this->PKG_VARIANT}" : '');
            $this->PKG_NAME = $this->PKG_STUB;
            $this->PKG_INFO = $this->pkg_info();
            $this->PKG_STATE = $this->pkg_state();
            if($this->_['is_action']){
                try {
                    empty($this->PKG_NAME) 
                        AND $this->json_response(false, ['error' => 'Missing Package.'], 400)
                    ;
                    if(($action = $this->_['action']) !== '') {
                        if ($action === 'delete') {
                            $pkg_dir = $this->PKG_DIR;
                            $pkg_name = $this->PKG_NAME;
                            $backup_dir = $this->PLEX_DIR."/.local/".($backup_name = "pkg~{$pkg_name}-[deleted-".\date('Y-md-Hi-s')."][".uniqid()."]");
                            if(\is_dir($d = $pkg_dir) && !\rename($d, $backup_dir)){
                                throw new \Exception("Failed: Unable to modify the '{$pkg_name}' directory - it might be in use!!!");
                            }
                            $this->json_response(true, ['note' => "Backedup at '{$backup_dir}'"]);
                        } 
                        
                        if ($action === 'change_access'){
                            $this->task__install_access();
                        }
                        
                        extension_loaded('curl') 
                            OR $this->json_response(false, ['error' => 'PHP cURL extension is required.'], 500)
                        ;
                        class_exists('ZipArchive')
                            OR $this->json_response(false, ['error' => 'PHP ZipArchive extension is required.'], 500)
                        ;
                        $this->GH_REPO_URL  = trim((string)($_REQUEST['repo'] ?? ''));
                        (empty($this->GH_REPO_URL)) 
                            AND $this->json_response(false, ['error' => 'Invalid GitHub URL.'], 400)
                        ;
                        [$this->GH_OWNER, $this->GH_REPO] = $this->gh__parse_segments($this->GH_REPO_URL);
                        
                        (empty($this->GH_REPO_URL) || empty($this->GH_OWNER) || empty($this->GH_REPO)) 
                            AND $this->json_response(false, ['error' => 'Invalid GitHub URL.'], 400)
                        ;
                        if ($action === 'list_refs') {
                            if($_REQUEST['is_initial'] ?? null){
                                if(!($this->PKG_STATE['ref'] ?? null)){
                                    $this->json_response(true, ['tags' => [], 'branches' => []]);
                                } else if(($this->PKG_STATE['ref_type'] ?? null) === 'tag'){
                                    $this->json_response(true, ['tags' => [$this->PKG_STATE['ref']], 'branches' => []]);   
                                } else if(($this->PKG_STATE['ref_type'] ?? null) === 'branch') {
                                    $this->json_response(true, ['tags' => [], 'branches' => [$this->PKG_STATE['ref']]]);
                                } else {
                                    $this->json_response(true, ['tags' => [], 'branches' => []]);
                                }
                            } else { 
                                $this->curl__set_token($this->GH_TOKEN);
                                $this->curl__set_timeout(25);
                                // Tags
                                [$okTags, $tagsJson, $errTags] = $this->curl($this->gh__api_url('tags',['per_page' => 100]));
                                $tags = $okTags && is_array($tagsJson) ? array_values(array_unique(array_map(fn($t)=>$t['name'] ?? '', $tagsJson))) : [];
                                
                                // Branches
                                [$okBr, $brJson, $errBr] = $this->curl($this->gh__api_url('branches',['per_page' => 100]));
                                $branches = $okBr && is_array($brJson) 
                                    ? array_values(array_unique(array_map(fn($b)=>$b['name'] ?? '', $brJson))) 
                                    : []
                                ;
                                
                                if (!$okTags && !$okBr){
                                    $this->curl__json_response(false, ['error' => "Failed to fetch refs: $errTags; $errBr"], 502);                                
                                }
                                $this->curl__json_response(true, ['tags' => $tags, 'branches' => $branches]);
                            }

                        } else if ($action === 'update') {
                            $r_version = trim((string)($_REQUEST['ref'] ?? ''));
                            $r_type = $_REQUEST['ref_type'] ?? '';
                            if ($r_version === '' || !in_array($r_type, ['tag','branch'], true)) {
                                $this->json_response(false, ['error' => 'Select a reference (tag or branch).'], 400);
                            }
                            $r_owner = $this->GH_OWNER;
                            $r_repo = $this->GH_REPO;
                            $pkg_name = $this->PKG_NAME;
                            $pkg_dir = $this->PKG_DIR;
                            $lib_dir = "{$pkg_dir}/lib";
                            $local_dir = $this->PLEX_DIR.'/.local';
                            $zip_dir = "{$local_dir}/".
                                ($zip_name = "pkg-download-".(\str_replace('/','][',"[github/{$r_owner}/{$r_repo}/{$r_type}/{$r_version}]")))
                            ;
                            $zip_code_file = "{$zip_dir}/code.zip";
                            $extract_dir = "{$zip_dir}/extract";
                            $backup_dir = $this->PLEX_DIR."/.local/".($backup_name = "lib-stash-[{$pkg_name}][".\date('Y-md-Hi-s')."][".uniqid()."]");
                            $meta_json = "{$lib_dir}/.lib.json";
                            $meta_data = [
                                'installed_on' => \date('Y-m-d H:i:s'),
                                'type' => 'lib',
                                'from' => $r_type,
                                'source' => "github/{$r_owner}/{$r_repo}",
                                'version' => $r_version,
                                'backuup' => \is_dir($pkg_dir) ? $backup_name : 'none',
                                'zip' => $zip_name,
                            ];
                            \is_dir($d = $zip_dir) OR \mkdir($d, 0777, true) OR (function($d){ 
                                throw new \Exception("Failed: Unable to create directory: $d");
                            })($d);
                            if(!\is_file($zip_code_file)){
                                [$ok, $gson, $err] = $this->curl($this->gh__api_url("zipball/".rawurlencode($r_version)), $zip_code_file);
                                if(!$ok){
                                    $this->curl__json_response(false, ['error' => "Library couldn't be dowloaded: $err"], 502);
                                }
                            }
                            try {
                                if (($zip = new \ZipArchive)->open($zip_code_file) !== true) {
                                    throw new \Exception("Failed: Unable to open ZIP file");
                                }
                                $sub_folder = \substr($s = $zip->getNameIndex(0), 0, \strpos($s, '/'));
                                $zip->extractTo($extract_dir);
                                if(\is_dir($d = $lib_dir) && !\rename($d, $backup_dir)){
                                    throw new \Exception("Failed: Unable to modify the '{$pkg_name}' directory - it might be in use!!!");
                                }
                                $src_lib_subpath = 'lib'; //'--epx/pkg/lib'
                                $transfer_to = $lib_dir;
                                if(\is_dir($transfer_from = "{$extract_dir}/{$sub_folder}/{$src_lib_subpath}")){
                                    if(!\rename($transfer_from, $transfer_to)){
                                        throw new \Exception("Failed: Unable to include: {$src_lib_subpath}");
                                    }
                                    \file_put_contents($meta_json,\json_encode(
                                        $meta_data,
                                        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
                                    ));
                                } else {
                                    
                                }
                            } finally {
                                $zip->close();
                            }
                            //keep this outside the finally if we need debugging
                            $this->fs_delete($zip_dir);
                            
                            $state = [
                                'pkg_name'  => $this->PKG_NAME,
                                'repo'     => $this->GH_REPO_URL,
                                'ref'      => $r_version,
                                'ref_type' => $r_type,
                            ];
                
                            $this->pkg_state($state);
                            
                            if(is_dir($transfer_to)){
                                $this->curl__json_response(true, ['note' => "Updated '{$this->PKG_NAME}' to {$r_type} '{$r_version}'.", 'backup' => $backup_name]);
                            } else {
                                $this->curl__json_response(true, ['note' => "Warning '{$src_lib_subpath}' doesn't exist! Updated '{$this->PKG_NAME}' to {$r_type} '{$r_version}'.", 'backup' => $backup_name]);    
                            }
                        }
                        $this->json_response(false, ['error' => "Unknown action '{$action}'"], 404);
                    } else {
                        $this->json_response(false, ['error' => 'No action specified'], 404);
                    }
                } catch (\Throwable $ex) {
                    $this->json_response(false, ['error' => $ex->getMessage()], 500);
                }
            }
        }
    } else {
        $this->vars['xui/main/content'] ??= function(){ ?>
            <div class="container d-flex flex-column justify-content-center align-items-center text-center min-vh-100">
            <div>
                <h1 class="fw-semibold  mb-2"><i class="bi bi-exclamation-triangle-fill text-danger fs-2 mb-3"></i> Not Found</h1>
                <p class="text-muted fs-6">
                The package you’re trying to access doesn’t exist or may have been removed.<br>
                Please select a valid package from the sidebar or create a new one.
                </p>
            </div>
            </div>
        <?php };
    }
    
    $this->get_pkg_list();
    
    $this->vars['ui/page/tab/title'] = $this->PKG_NAME ?? '';
    $this->vars['ui/page/title'] = $this->PKG_VARIANT ? "{$this->GH_REPO} ({$this->PKG_VARIANT})" : "{$this->GH_REPO}";
    $this->vars['ui/page/subtitle'] = $this->PKG_INFO ?? '';
    $this->vars['xui/sidebar_header/content'] = function(){ ?>
        <div class="d-flex align-items-center gap-2">
            <span class="fw-semibold">Packages</span>
            <span class="text-secondary small">(<?=count($this->PKG_LIST); ?>)</span>
        </div>
        <div class="btn-group">
            <a class="btn btn-sm btn-outline-primary" href="<?=$this->_['base_url']?>/manage_access">Access</a>
            <button type="button" class="btn btn-sm btn-outline-primary dropdown-toggle dropdown-toggle-split" data-bs-toggle="dropdown" aria-expanded="false">
                <span class="visually-hidden">Toggle Dropdown</span>
            </button>
            <ul class="dropdown-menu">
                <li><a class="dropdown-item" href="<?=$this->_['base_url']?>/new_library">Add Library</a></li>
                <li><a class="dropdown-item" href="<?=$this->_['base_url']?>/new_variant">Add Variant</a></li>
                <li><a class="dropdown-item" href="<?=$this->_['base_url']?>/new_synth">Add Synth</a></li>
                <li><a class="dropdown-item" href="<?=$this->_['base_url']?>/manage_access">Manage Access</a></li>
            </ul>
        </div>        
        
        
        <?php 
    };
    $this->vars['xui/html/tail'][] = function(){ ?>
        <script>
            window.xui.ds.lib_options = <?=\json_encode((function(){ 
                $list = [
                    ['id' => '', 'text'=>'--Select Library--']
                ];
                foreach ($this->PKG_LIST as $k => $v){
                    $list[] = ['id' => $k, 'text'=>$v['name']];
                }
                return $list;
            })())?>        
        </script>          
    <?php };
    
    $this->vars['xui/html/tail'][] = function(){ ?>
        <script>
            $(() => {
                async function transact(action, extra = {}) {
                    const fd = new FormData();
                    for (const [k, v] of Object.entries(extra)) fd.set(k, v);
                    fd.set('--csrf', "<?=htmlspecialchars($_SESSION['--CSRF'])?>")
                    console.log(fd);
                    const res = await fetch(`?--action=${encodeURIComponent(action)}`, { method: 'POST', body: fd });
                    return res.json();
                }
                
                // Example wiring: delete button
                document.getElementById('btnDeletePackage')?.addEventListener('click', function () {
                    window.xui.modal.prompt(
                        'Are you sure you want to delete this package?',
                        'Delete Confirmation',
                        ['Yes', 'No'],
                        async function (choice) {
                            switch (choice) {
                            case 'Yes':
                                console.log('Delete confirmed – do delete here.');
                                await transact('delete');
                                window.location.replace(window.xui.url.site); // so that go-back doesn't work
                                break;
                            case 'No':
                            case null: // closed without explicit choice
                            default:
                                console.log('Delete cancelled.');
                                break;
                            }
                        }
                    );
                });

                // Example wiring: delete button
                $('#selectPackageAccess').on('change', async function () {
                    await transact('change_access',{access_type:$(this).val()});
                    //window.location.reload();
                });
                
                
            });
        </script>
    <?php };     
    
    $this->vars['xui/sidebar_nav/content'] = function(){ ?>
        <style>
            .xui-sidenav-item-card a {
                text-decoration: none;
            }
        </style>
        <?php foreach ($this->PKG_LIST as $k => $v): ?>
            <div class="xui-sidenav-item-card border position-relative p-2">

                <?php if (!empty($v['go_url']) || !empty($v['lib_tools_url'])): ?>
                    <div class="dropdown position-absolute top-0 end-0 mt-1 me-1">
                        <button class="btn btn-link btn-sm p-0 text-muted"
                                type="button"
                                data-bs-toggle="dropdown"
                                aria-expanded="false">
                            <i class="bi bi-three-dots-vertical"></i>
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <?php if (!empty($v['go_url'])): ?>
                                <li>
                                    <a class="dropdown-item"
                                    href="<?= htmlspecialchars($v['go_url']) ?>">
                                        Go
                                    </a>
                                </li>
                            <?php endif; ?>
                            <?php if (!empty($v['lib_tools_url'])): ?>
                                <li>
                                    <a class="dropdown-item"
                                    href="<?= htmlspecialchars($v['lib_tools_url']) ?>">
                                        Library tools
                                    </a>
                                </li>
                            <?php endif; ?>
                        </ul>
                    </div>
                <?php endif; ?>

                <a href="<?= $v['pkg_manage_url'] ?>" class="d-block text-decoration-none pe-4">
                    <p class="xui-sidenav-title mb-0">
                        <?= htmlspecialchars($v['disp']); ?>
                    </p>
                    <p class="xui-sidenav-desc mb-0"
                    title="<?= htmlspecialchars($v['desc'] ?? '', ENT_QUOTES); ?>">
                        <?= htmlspecialchars($v['desc'] ?? ''); ?>
                    </p>
                </a>

            </div>
        <?php endforeach; ?>
        <script>
            $(function () {
                const current = window.location.href;
                $(".xui-sidenav-item-card a").each(function () {
                    if (this.href === current) {
                        $(this).closest(".xui-sidenav-item-card").addClass("active");
                    }
                });
            });
        </script>
        <?php 
    };
    $this->vars['xui/main/content'] ??= function(){ ?>
        <style>
            /* Split layout */
            #splitWrapper {
                display: flex;
                flex-direction: column;
                /* Adjust as needed; this makes the split area fill most of the viewport */
                min-height: 400px;
                height: calc(100vh - 140px);
            }

            #formPane {
                flex: 0 0 auto;
            }

            #activityPane {
                flex: 1 1 auto;
                min-height: 120px;
                display: flex;
                flex-direction: column;
            }

            /* The draggable horizontal bar */
            #activityResizer {
                height: 6px;
                margin: .75rem 0;
                cursor: row-resize;
                background: var(--bs-border-color);
                border-radius: 999px;
            }

            /* Activity panel */
            #activity {
                white-space: pre-wrap;
                background: #0d1117;
                color: #c9d1d9;
                border-radius: .5rem;
                padding: 1rem;
                flex: 1 1 auto;
                overflow: auto;
                font-family: var(--bs-font-monospace, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace);
            }
        </style>

        <div class="container-fluid m-2">
            <div class="d-flex flex-column">
                <h1 class="fw-semibold mb-1"><?=$this->vars['ui/page/title']?></h1>
                <p class="text-muted fs-6 mb-0"><?=$this->vars['ui/page/subtitle']?></p>
            </div>

            <!-- Split wrapper: form (top) + resizer + activity (bottom) -->
            <div id="splitWrapper" class="mt-3">
                <!-- Top: form pane -->
                <div id="formPane">
                    <form id="f" class="g-3" autocomplete="off">
                        <input type="hidden" name="--csrf" value="<?= htmlspecialchars($_SESSION['--CSRF']) ?>">
                        <div class="row">
                            <div class="col-md-12 mb-2">
                                <label class="form-label">GitHub URL</label>
                                <input name="repo" id="repo" class="form-control" placeholder="https://github.com/owner/repo(.git)" required value="<?= htmlspecialchars($this->GH_REPO_URL ?? '', ENT_QUOTES) ?>" autocomplete="new-password" autocorrect="off" autocapitalize="none" spellcheck="false" <?=($this->GH_REPO_URL ?? null) ? 'readonly' : '' ?>>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-12 mb-2">
                                <label class="form-label">API Key (optional, for private repos)</label>
                                <input name="token" id="gh_token" type="password" class="form-control" placeholder="GitHub PAT" value="" autocomplete="new-password" autocorrect="off" autocapitalize="none" spellcheck="false">
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-12 mb-2">
                                <label class="form-label">Reference</label>
                                <div class="input-group mb-3">
                                    <button class="btn btn-secondary" type="button" id="btnLoad">
                                        <span class="spinner-border spinner-border-sm d-none"></span>
                                        Load Tags &amp; Branches
                                    </button>
                                    <select id="ref" class="form-select"></select>
                                    <input type="hidden" id="ref_type" name="ref_type">
                                    <button class="btn btn-primary" type="button" id="btnUpdate">
                                        <span class="spinner-border spinner-border-sm d-none"></span>
                                        Update
                                    </button>
                                </div>
                            </div>
                        </div>
                        <?php if(\is_file($this->PKG_DIR.'/lib/app/.app-$$.php')): ?>
                        <div class="row">
                            <div class="col mb-2">
                                <label class="form-label">Access</label>
                                <select class="form-control" id="selectPackageAccess">
                                    <option value="<?=$x='no-access'?>" <?=$this->pkg__access_type() == $x ? 'selected' : ''?>>None</option>
                                    <option value="<?=$x='relay-access'?>" <?=$this->pkg__access_type() == $x ? 'selected' : ''?>>Relay</option>
                                    <option value="<?=$x='direct-access'?>" <?=$this->pkg__access_type() == $x ? 'selected' : ''?>>Direct</option>
                                </select>
                            </div>
                        </div>
                        <?php endif ?>
                        <div class="row">
                            <div class="col"></div>
                            <div class="col-auto">
                                <button type="button" class="btn btn-outline-danger" id="btnDeletePackage">
                                    Remove
                                </button>
                            </div>
                        </div>
                    </form>
                </div>

                <!-- Resizable bar -->
                <div id="activityResizer" class="bg-body-tertiary"></div>

                <!-- Bottom: activity pane -->
                <div id="activityPane">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <h2 class="h6 mb-0">Activity</h2>
                    </div>
                    <div id="activity"></div>
                </div>
            </div>
        </div>

        <script>
            (function () {
                const formPane = document.getElementById('formPane');
                const resizer = document.getElementById('activityResizer');

                if (!formPane || !resizer) return;

                let startY = 0;
                let startHeight = 0;

                function onMouseDown(e) {
                    e.preventDefault();
                    startY = e.clientY;
                    startHeight = formPane.getBoundingClientRect().height;

                    document.addEventListener('mousemove', onMouseMove);
                    document.addEventListener('mouseup', onMouseUp);
                }

                function onMouseMove(e) {
                    const dy = e.clientY - startY;
                    const newHeight = Math.max(120, startHeight + dy); // minimum form height

                    formPane.style.height = newHeight + 'px';
                    formPane.style.flex = '0 0 ' + newHeight + 'px';
                }

                function onMouseUp() {
                    document.removeEventListener('mousemove', onMouseMove);
                    document.removeEventListener('mouseup', onMouseUp);
                }

                resizer.addEventListener('mousedown', onMouseDown);
            })();
        </script>
        <script>
            const GH_OWNER = '<?=$this->GH_OWNER?>';
            const GH_REPO = '<?=$this->GH_REPO?>';
            $(() => {
                const $ref = $('#ref').select2({
                    placeholder: 'Select a tag or branch',
                    allowClear: false,
                    width: '100%'
                });
                const act = document.getElementById('activity');
                const btnLoad = document.getElementById('btnLoad');
                const btnUpdate = document.getElementById('btnUpdate');
                const form = document.getElementById('f');
                const prefill = <?= json_encode($this->PKG_STATE ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>;

                function log(msg, err = false) {
                    const t = new Date().toLocaleTimeString();
                    act.textContent += `[${t}] ${msg}\n`;
                    act.scrollTop = act.scrollHeight;
                    if (err) console.error(msg);
                }
                function spin(btn, on) {
                    const sp = btn.querySelector('.spinner-border');
                    if (!sp) return;
                    if (on) { sp.classList.remove('d-none'); btn.setAttribute('disabled', 'disabled'); }
                    else { sp.classList.add('d-none'); btn.removeAttribute('disabled'); }
                }
                async function post(action, extra = {}) {
                    const fd = new FormData(form);
                    for (const [k, v] of Object.entries(extra)) fd.set(k, v);
                    const res = await fetch(`?--action=${encodeURIComponent(action)}`, { method: 'POST', body: fd });
                    return res.json();
                }
                
                function getGhToken() {
                    const el = document.getElementById('gh_token');
                    console.log(el);
                    return el ? el.value.trim() : '';
                }
                
                function list_refs(initial = 0){
                    if(0){
                        return list_refs__here();
                    } else {
                        return list_refs__backend(initial);
                    }
                }
                
                async function fetchGithubRefs() {
                    const token = getGhToken();
                    const headers = {
                        'Accept': 'application/vnd.github+json'
                    };
                    // Attach token only if user provided it
                    if (token) {
                        headers['Authorization'] = 'Bearer ' + token; // or 'token ' + token
                        console.log('using token : '+token);
                    }
                    
                    const tagsUrl     = `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/tags?per_page=100`;
                    const branchesUrl = `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/branches?per_page=100`;
                    const fetchOpts = { headers };
                    
                    console.log({fetchOpts});
                    
                    var res1, res2;
                    
                    const [tagsRes, branchesRes] = await Promise.all([
                        fetch(tagsUrl, fetchOpts),
                        fetch(branchesUrl, fetchOpts)
                    ]);
                    
                    console.group("Tags Headers");
                    for (const [key, value] of tagsRes.headers.entries()) { console.log(key, value); }
                    console.groupEnd();
                    console.group("Branches Headers");                    
                    for (const [key, value] of branchesRes.headers.entries()) { console.log(key, value); }
                    console.groupEnd();
                    
                    // If both failed, surface a clear message
                    if (!tagsRes.ok && !branchesRes.ok) {
                        let msg = `Failed to fetch refs. tags=${tagsRes.status}, branches=${branchesRes.status}`;
                        if (tagsRes.status === 401 || tagsRes.status === 403 ||
                            branchesRes.status === 401 || branchesRes.status === 403) {
                            msg += ' (Check your GitHub token / permissions)';
                        }
                        throw new Error(msg);
                    }
                    const tagsJson     = tagsRes.ok ? await tagsRes.json()     : [];
                    const branchesJson = branchesRes.ok ? await branchesRes.json() : [];
                    const tags = Array.from(new Set(
                        (tagsJson || [])
                            .map(t => (t && t.name) ? t.name : '')
                            .filter(Boolean)
                    ));
                    const branches = Array.from(new Set(
                        (branchesJson || [])
                            .map(b => (b && b.name) ? b.name : '')
                            .filter(Boolean)
                    ));
                    return { tags, branches };
                }
                
                async function list_refs__here(is_initial = false) {
                    spin(btnLoad, true);
                    try {
                        // Handle the initial state purely on the client
                        if (is_initial && prefill.ref) {
                            const selRef  = prefill.ref || null;
                            const selType = prefill.ref_type || null;
                            const tags    = selType === 'tag'    ? [selRef] : [];
                            const branches= selType === 'branch' ? [selRef] : [];
                            populateRefs(tags, branches, selRef, selType);
                            return;
                        }

                        // Otherwise, fetch from GitHub directly
                        const { tags, branches } = await fetchGithubRefs();

                        const selRef  = prefill.ref || null;
                        const selType = prefill.ref_type || null;
                        populateRefs(tags, branches, selRef, selType);

                        if (!is_initial) {
                            log(`Loaded ${tags.length} tags and ${branches.length} branches.`);
                        }
                    } catch (e) {
                        log('Error loading refs: ' + e.message, true);
                        console.error(e);
                    } finally {
                        spin(btnLoad, false);
                    }
                }
                
                function populateRefs(tags = [], branches = [], selectedRef = null, selectedType = null) {
                    $ref.empty();
                    const optTags = $('<optgroup label="Tags"></optgroup>');
                    const optBranches = $('<optgroup label="Branches"></optgroup>');
                    (tags || []).forEach(t => optTags.append(new Option(t, t, false, false)));
                    (branches || []).forEach(b => optBranches.append(new Option(b, b, false, false)));
                    $ref.append(optTags).append(optBranches);
                    if (selectedRef) {
                        $ref.val(selectedRef).trigger('change');
                        document.getElementById('ref_type').value = selectedType || '';
                    } else {
                        $ref.val(null).trigger('change');
                        document.getElementById('ref_type').value = '';
                    }
                }
                $ref.on('select2:select', function (e) {
                    const val = e.params.data.id;
                    const el = $ref.find('option[value="' + CSS.escape(val) + '"]')[0];
                    let type = '';
                    if (el && el.parentElement && el.parentElement.label) {
                        type = (el.parentElement.label.toLowerCase().includes('tag')) ? 'tag' : 'branch';
                    }
                    document.getElementById('ref_type').value = type;
                });
                $ref.on('select2:clear', function () { document.getElementById('ref_type').value = ''; });
                
                async function list_refs__backend(is_initial = false){
                    spin(btnLoad, true);
                    try {
                        const res = await post('list_refs',{is_initial: is_initial ? 1 : ''});
                        if(res.dx){
                            console.log({diagnostics: res.dx});
                        }
                        if (!res.ok) { log('Failed to load refs: ' + (res.error || ''), true); return; }
                        const selRef = prefill.ref || null;
                        const selType = prefill.ref_type || null;
                        populateRefs(res.tags || [], res.branches || [], selRef, selType);
                        if(!is_initial){
                            log(`Loaded ${(res.tags || []).length} tags and ${(res.branches || []).length} branches.`);
                        }
                    } catch (e) { log('Error: ' + e, true); }
                    finally { spin(btnLoad, false); }
                }

                btnLoad.addEventListener('click', async () => {
                    list_refs();
                });

                btnUpdate.addEventListener('click', async () => {
                    const ref = $ref.val();
                    const refType = document.getElementById('ref_type').value;
                    if (!ref || !refType) { log('Select a tag or branch first.', true); return; }
                    spin(btnUpdate, true);
                    try {
                        const res = await post('update', { ref, ref_type: refType });
                        if(res.dx){
                            console.log({diagnostics: res.dx});
                        }
                        if (!res.ok) { log('Update failed: ' + (res.error || ''), true); return; }
                        if (res.backup) log('Previous contents moved to: ' + res.backup);
                        log(res.note || 'Update complete.');
                    } catch (e) { log('Error: ' + e, true); }
                    finally { spin(btnUpdate, false); }
                });

                // Auto-load refs if repo already filled (from state)
                if (document.getElementById('repo').value.trim() !== '') {
                    list_refs(true);
                }
            });
        </script>
        <?php
    };
    $this->main_window__v();
}
#endregion
# ######################################################################################################################
#region INVOKE
function __invoke(){
    
    foreach((function(){
        yield $this->session();
        yield $this->auth();
    })() as $v){
        if($v){
            return $v;
        }
    }
    
    return function(){ $this->index__c(); };

}
#endregion
# ######################################################################################################################
  
})()(); }