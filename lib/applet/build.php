<?php

global $_;

$acc__ft AND (function($f,&$_,&$_DEF){ include $f; })($acc__f,$_,$_DEF);

$env = $_;

$modules = [];

$modules[\dirname($app_file)] = true;

foreach($_['MODULES'] ?? [] as $k => $v){
    if(\is_numeric($k)){
        if(($m = $v[0]) && ($p = $v[1] ?? '')){
            if($p[0] == '/' || ($p[1] ?? null) == ':'){
                $modules[\str_replace('\\','/', $p)."/{$m}"] ??= true;
            } else {
                $modules[$d = \str_replace('\\','/', $_SERVER['_']['PLEX_DIR'].'/pkg~'.($n = \str_replace('/','~',$p))).'/lib/'.$m] ??= true;
                if(!\is_dir($d)){
                    (include 'install.php')($n, $p, $d);
                }
            }
        } else if($m){
            $p = $m;
            if($p[0] == '/' || ($p[1] ?? null) == ':'){
                $modules[\str_replace('\\','/', $p)] ??= true;
            } else {
                $modules[\dirname($app_file,2).'/'.$p] ??= true;    
            }
        } else {
            $GLOBALS['_TRACE'][] = "Warning: Module resolve error: '{$k}'";
        }
    } else if(\is_bool($v)){
        $p = $k;
        if($p[0] == '/' || ($p[1] ?? null) == ':'){
            $modules[\str_replace('\\','/', $p)] ??= $v;
        } else if(\str_starts_with($p,'../')) {
            $modules[\str_replace('\\','/', \dirname($_SERVER['_']['APP_DIR']).\substr($p,2))] ??= $v;
        } else if(\str_starts_with($p,'.../')) {
            $p = \substr($p,3);
            for (
                $i=0, $dx=$_SERVER['_']['APP_DIR']; 
                $dx && $i < 20 ; 
                $i++, $dx = (\strchr($dx, DIRECTORY_SEPARATOR) != DIRECTORY_SEPARATOR) ? \dirname($dx) : null
            ){ 
                if(\is_dir($dy = $dx.$p)){
                    $modules[\str_replace('\\','/', $dy)] = true;
                    continue 2;
                }
            }
            $GLOBALS['_TRACE'][] = "Warning: Module resolve error: '{$k}'";
        } else {
            $GLOBALS['_TRACE'][] = "Warning: Module resolve error: '{$k}'";
        }
    } else {
        $GLOBALS['_TRACE'][] = "Warning: Module resolve error: '{$k}'";
    }
}

foreach(\explode(PATH_SEPARATOR,\get_include_path()) as $v){
    $modules[\str_replace('\\','/', $v)] ??= true;
}

foreach($modules as $d => &$en){
    if($en){
        if(\is_dir($d)){
            $GLOBALS['_TRACE'][] = "Module included: '".\str_replace('\\','/', $d)."'";
        } else {
            $GLOBALS['_TRACE'][] = "Warning: Module not found: '".\str_replace('\\','/', $d)."'";
            $en = false;
        }
    } else {
        $GLOBALS['_TRACE'][] = "Notice: Module disabled: '".\str_replace('\\','/', $d)."'";
    }
}

$env['AUTO_INCLUDES'] ??= [];

foreach($modules as $d => $en){
    if($en && \is_file($f = "{$d}/.functions.php")){
        $env['AUTO_INCLUDES'][$f] = true;
    }
    if($en && \is_file($f = "{$d}/.functions-{$intfc}.php")){
        $env['AUTO_INCLUDES'][$f] = true;
    }
}

foreach(\array_reverse($modules) as $d => $en){
    if($en && \is_file($f = "{$d}/.module.php")){
        $env['AUTO_INCLUDES'][$f] = true;
    }
    if($en && \is_file($f = "{$d}/.module-{$intfc}.php")){
        $env['AUTO_INCLUDES'][$f] = true;
    }
}

$env['TSP']['PATH'] = \implode(PATH_SEPARATOR, \array_keys($env['TSP']['LIST'] = \array_filter($modules)));
$env_export = \str_replace("\n","\n  ", \var_export($env,true));
$def_export = '';
foreach($_DEF ?? [] as $k => $v){
    $def_export .= "\define('_\\{$k}', '{$v}');\n";
}
$stamp = \date('Y-md-Hi-s').PHP_EOL;
$trace = \implode(PHP_EOL."# ", $GLOBALS['_TRACE'] ?? []);
$contents = <<<PHP
<?php 
namespace {
\$_ENV = \array_replace_recursive(\$_ENV, {$env_export});
{$def_export}
}
# {$trace}
# {$stamp}
PHP;
\is_dir($d = \dirname($lcl__f)) OR \mkdir($d,0777,true);
\file_put_contents(
    $lcl__f, 
    $contents,
    LOCK_EX // prevents race when testing and you have ton of simultaneous requests
);
