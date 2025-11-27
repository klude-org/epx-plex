<?php 

include (function(){
    
    try{
        
        global $_;
        (isset($_) && \is_array($_)) OR $_ = [];
        
        if($app_file = $_SERVER['_']['APP_FILE'] ?? null){
            \define('_\PHP_TSP_DEFAULTS', [
                'handler' => 'spl_autoload',
                'extensions' => \spl_autoload_extensions(),
                'path' =>  \get_include_path(),
            ]);
            $_SERVER['_']['PLEX_DIR'] ??= \str_replace('\\','/', \dirname(__DIR__,2));
            $_SERVER['_']['SITE_DIR'] ??= (empty($_SERVER['HTTP_HOST'])
                ? \str_replace('\\','/',\realpath($_SERVER['FW__SITE_DIR'] ?? \getcwd()))
                : \str_replace('\\','/',\realpath(\dirname($_SERVER['SCRIPT_FILENAME'])))
            );
            $_SERVER['_']['INTFC'] ??= $_SERVER['FW__INTFC']
                ?? (empty($_SERVER['HTTP_HOST']) 
                    ? 'cli'
                    : $_SERVER['HTTP_X_REQUEST_INTERFACE'] ?? 'web'
                )
            ;
            $_SERVER['_']['INST_DIR'] = $inst_dir = \dirname($app_file,3);
            $_SERVER['_']['APP_DIR'] = $app_dir = \dirname($app_file);
            $intfc = $_SERVER['_']['INTFC'];
            $lcl__ft = \is_file($f = $lcl__f = "{$inst_dir}/.local/.app-cache-{$intfc}.php") ? \filemtime($f) : 0;
            $acc__ft = \is_file($f = $acc__f = $app_file) ? \filemtime($f) : 0;
            $aic__ft = \is_file($f = $aic__f = "{$app_dir}/.app-{$intfc}.php") ? \filemtime($f) : 0;
            if(
                1
                || $lcl__ft <= $acc__ft
                || $lcl__ft <= $aic__ft
                || $lcl__ft <= \filemtime(__FILE__)
                || $lcl__ft <= \filemtime($_SERVER['SCRIPT_FILENAME'])
            ){
                include 'build.php';
            }
            
            try{
                // prevents race when testing and you have ton of simultaneous requests
                $handle = fopen($lcl__f, 'r');
                if (flock($handle, LOCK_SH)) {
                    try {
                        include $lcl__f;
                    } finally {
                        \flock($handle, LOCK_UN);
                    }
                } else {
                    throw new \Exception("Cache error");
                }
            } finally {
                fclose($handle);
            }
    
            \set_include_path($_ENV['TSP']['PATH']);
            \spl_autoload_extensions("-#{$intfc}.php,/-#{$intfc}.php,-#.php,/-#.php");
            \spl_autoload_register();
        }
        
        return \stream_resolve_include_path('.start.php') ?: \dirname(__DIR__).'/app/.start.php';
        
    
    } catch(\Throwable $ex) {
        switch($_SERVER['_']['INTFC']){
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
                //while(\ob_get_level() > \_\OB_OUT){ @\ob_end_clean(); }
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
    
    
})();
