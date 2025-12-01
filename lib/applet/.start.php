<?php 

namespace { 
    \defined('_\MSTART') OR \define('_\MSTART', \microtime(true));
    \define('_\OB_OUT', \ob_get_level());
    !empty($_SERVER['HTTP_HOST']) AND \ob_start();
    \define('_\OB_TOP', \ob_get_level());
    const _ = '_'; 
}
namespace { return ( function(){
    try {
        $this->abort__fn = function($code, $message){
            if($this->is_cli){
                return function() use($message){
                    echo "\033[91m{$message}\033[0m\n";
                };
            } else {
                return function() use($code, $message){
                    \http_response_code($code);
                    echo $message;
                };
            }
        };
        $this->is_cli = empty($_SERVER['HTTP_HOST']);
        $this->intfc = $intfc = $_SERVER['FW__INTFC']
            ?? (empty($_SERVER['HTTP_HOST']) 
                ? 'cli'
                : $_SERVER['HTTP_X_REQUEST_INTERFACE'] ?? 'web'
            )
        ;        
        $this->php_tsp_defaults = \defined('_\PHP_TSP_DEFAULTS') ? _\PHP_TSP_DEFAULTS : [
            'handler' => 'spl_autoload',
            'extensions' => \spl_autoload_extensions(),
            'path' =>  \get_include_path(),
        ];
        $this->start_file =  \str_replace('\\','/', __FILE__);
        $this->start_dir =  \str_replace('\\','/', __DIR__);
        $this->site_dir = ($this->is_cli
            ? \str_replace('\\','/',\realpath($_SERVER['.']['site_dir'] ?? \getcwd()))
            : \str_replace('\\','/',\realpath(\dirname($_SERVER['SCRIPT_FILENAME'])))
        );
        $this->tsp_path = $_ENV['TSP']['PATH'] ?? null;
        $this->tsp_list = $_ENV['TSP']['LIST'] ?? null;
        \set_include_path($this->tsp_path ?? $this->tsp_path = \implode(
            PATH_SEPARATOR, 
            \array_keys($this->tsp_list ?? $this->tsp_list = (\iterator_to_array((function(){
                yield $this->site_dir => true;
                foreach(\explode(PATH_SEPARATOR, $this->php_tsp_defaults['path']) as $dir){
                    if(\is_dir($dir)){
                        yield \str_replace('\\','/', $dir) => 1;
                    }
                }
            })())))
        ));
        \spl_autoload_extensions("-#{$this->intfc}.php,/-#{$this->intfc}.php,-#.php,/-#.php");
        \spl_autoload_register();
        $this->rurp = (function(){
            if($this->is_cli){
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
        $this->asset = $_GET['--asset'] ?? null;
        if(!\preg_match(
            "#^/"
                ."(?:"
                    ."(?:"
                        ."(?<facet>"
                            ."(?<portal>(?:__|--)[^/\.]*)"
                            ."(?:\.(?<role>[^/]*))?"
                        .")/?"
                    .")?"
                    ."(?<npath>.*)"
                .")?"
            . "$#",
            $this->rurp,
            $m
        )){
            return $this->abort__fn(404, "404: Not Found: Invalid request path format");
        } else {
            foreach(\array_filter($m, fn($k) => !is_numeric($k), \ARRAY_FILTER_USE_KEY) as $k => $v){
                $this->$k = $v;
            }
        }
        $this->panel = \trim(\str_replace('-','_', $this->portal ?? null ?: '__'),'/');
        $this->fpath = implode('/',\array_map(fn($k) => \trim($k,'/'), \array_filter([
            $this->panel,
            $this->npath,
            $this->asset,
        ])));
        $this->ctlr_file = (function($path, $sfx){
            $suffixes = \is_array($sfx) ? $sfx : [$sfx];
            foreach($suffixes as $suffix){
                if($f = (($suffix)
                    ? \stream_resolve_include_path($r[] = "{$path}/{$suffix}") 
                        ?: (\stream_resolve_include_path($r[] = "{$path}{$suffix}")
                    )
                    : \stream_resolve_include_path($r[] = "{$path}")
                )){
                    return new \SplFileInfo($f);
                }
            }
        })($this->fpath, $this->asset ? null : ["-@{$this->intfc}.php", "-@.php", "-@.html"]);
        if($file = $this->ctlr_file){
            if($this->asset){
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
                    return ($this->abort__fn)(404, '404: Not Found: Unknown Mime Type');
                } else {
                    if($this->is_cli){
                        return function() use($file){
                            echo "\n{$file}";    
                        };
                    } else {
                        // Set appropriate headers
                        $exit = (object)[];
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
                            $exit->content = $file;
                        }
                        return function() use($exit){
                            while(\ob_get_level() > \_\OB_OUT){ @\ob_end_clean(); }
                            if(\is_numeric($code = $exit->code ?? null)){
                                \http_response_code($code ?: 200);
                            } 
                            foreach($exit->headers ?? [] as $k => $v){
                                if(\is_string($v)){
                                    if(\is_numeric($k)){
                                        \header($v);    
                                    } else {
                                        \header("{$k}: {$v}");
                                    }
                                }
                            }
                            if(\is_null($content = $exit->content ?? null)){ 
                                return; 
                            } else if($content instanceof \SplFileInfo){
                                \readfile($content);
                            }
                        };
                    }
                }
            } else {
                try {
                    $f = $this->ctlr_file;
                    return function() use($f){ include $f; };
                } finally {
                    $include__fn = function($f){ include $f; };
                    $tsp_list = \explode(PATH_SEPARATOR, \get_include_path());
                    foreach(\array_reverse($tsp_list) as $d){
                        if(\is_file($f = "{$d}/.module.php")){
                            $include__fn($f);
                        }
                    }
                    foreach($tsp_list as $d){
                        if(\is_file($f = "{$d}/.functions-{$this->intfc}.php")){
                            $include__fn($f);
                        }
                        if(\is_file($f = "{$d}/.functions.php")){
                            $include__fn($f);
                        }
                    }
                }
            }
        } else {
            return ($this->abort__fn)(404, '404: Not Found');
        }
    } catch(\Throwable $ex) {
        switch($this->intfc){
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
})->bindTo((object)[])()(); }
