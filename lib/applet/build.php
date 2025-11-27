<?php

global $_;

$acc__ft AND (function($f,&$_,&$_DEF){ include $f; })($acc__f,$_,$_DEF);
$aic__ft AND (function($f,&$_,&$_DEF){ include $f; })($aic__f,$_,$_DEF);

$env = $_;

$modules = [];

$modules[\dirname($app_file)] = true;

foreach($_['MODULES'] ?? [] as $k => $v){
    if(\is_numeric($k)){
        if(($m = $v[0]) && ($p = $v[1] ?? '')){
            $modules[($d = \str_replace('\\','/', $_SERVER['_']['PLEX_DIR'].'/pkg~'.($n = \str_replace('/','~',$p)))).'/lib/'.$m] ??= true;
            if(!\is_dir($d)){
                (include 'install.php')($n, $p, $d);
            }
        } else if($m){
            $modules[\dirname($app_file,2).'/'.$m] ??= true;
        } else {
            //ignore for now
        }
    } else if(\is_bool($v)){
        $modules[\str_replace('\\','/',$k)] = $v;
    } else {
        //ignore for now
    }
}

foreach(\explode(PATH_SEPARATOR,\get_include_path()) as $v){
    $modules[\str_replace('\\','/', $v)] ??= true;
}

foreach($modules as $d => $en){
    if($en){
        if(\is_dir($d)){
            $GLOBALS['_TRACE'][] = "Module included: '".\str_replace('\\','/', $d)."'";
        } else {
            $GLOBALS['_TRACE'][] = "Warning: Module not found: '".\str_replace('\\','/', $d)."'";
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
