<?php 

return new class extends \stdClass {
    
    function __construct(){
        $this->PLEX_DIR = $plex_dir = $_SERVER['_']['PLEX_DIR'];
        (function($plex_dir, &$_) {
            if(\is_file($cfg__f = "{$plex_dir}/.local-config.php")){
                include $cfg__f;
            }
        })->bindTo(null,null)($this->PLEX_DIR, $this->_);
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
        $this->CURL_HEADERS['X-GitHub-Api-Version'] = "X-GitHub-Api-Version: 2022-11-28";
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
    
    public function __invoke($pkg_name, $pkg_path, $pkg_dir){
        [$r_owner, $r_repo, $pkg_i] = [\strtok($pkg_path,'/'), \strtok('/'), \strtok('')];
        if($r_owner == 'synth'){
            return;
        }
        $this->GH_TOKEN = trim($this->_[\_\api::class]['github.com']['token'] ?? '');
        $this->GH_OWNER = $r_owner;
        $this->GH_REPO = $r_repo;
        $this->PKG_NAME = $pkg_name;
        $this->PKG_DIR = $pkg_dir;
        $this->GH_TOKEN ??= null;
        
        if(
            ([$ok, $status] = $this->curl_head($this->GH_URL = "https://api.github.com/repos/{$this->GH_OWNER}/{$this->GH_REPO}", $this->GH_TOKEN))
            && (!$ok || $status !== 200)
        ){
            throw new \Exception("Github Response {$status} for Package: {$pkg_path}");
        }
        
        if($pkg_i){
            if(\str_starts_with($pkg_i, 't=')){
                $r_type = 'tag';
                $r_version = \substr($pkg_i,2);
            } else if(\str_starts_with($pkg_i, 'b=')){
                $r_type = 'branch';
                $r_version = \substr($pkg_i,2);
            } else {
                $r_type = 'branch';
                $r_version = 'main';
            }
        } else {
            $r_type = 'branch';
            $r_version = 'main';
        }
        $lib_dir = "{$pkg_dir}/lib";
        $local_dir = $_SERVER['_']['PLEX_DIR'].'/.local';
        $zip_dir = "{$local_dir}/".
            ($zip_name = "pkg-download-".(\str_replace('/','][',"[github/{$r_owner}/{$r_repo}/{$r_type}/{$r_version}]")))
        ;
        $zip_code_file = "{$zip_dir}/code.zip";
        $extract_dir = "{$zip_dir}/extract";
        $meta_json = "{$lib_dir}/.lib.json";
        $meta_data = [
            'installed_on' => \date('Y-m-d H:i:s'),
            'type' => 'lib',
            'from' => $r_type,
            'source' => "github/{$r_owner}/{$r_repo}",
            'version' => $r_version,
            'backuup' => 'none',
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
            $src_lib_subpath = 'lib'; //'--epx/pkg/lib'
            $transfer_to = $lib_dir;
            if(\is_dir($transfer_from = "{$extract_dir}/{$sub_folder}/{$src_lib_subpath}")){
                $this->fs_ensure_parent($transfer_to);
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
            'repo'     => $this->GH_URL,
            'ref'      => $r_version,
            'ref_type' => $r_type,
        ];
        
        $this->pkg_state($state);
    }
};

